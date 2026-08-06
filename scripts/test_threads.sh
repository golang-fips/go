#!/bin/bash

set -e

CPU_COUNT=$(nproc | tr -d '[:space:]')
ITERATIONS=${ITERATIONS:-1}

build_test () {
  local bin=$1
  shift;
  local tags="$@"
  ../bin/go test -o $bin -c $tags crypto/internal/backend
}

exec_test () {
  export GOLANG_FIPS=1
  export OPENSSL_FORCE_FIPS_MODE=1
  local bin=$1
  local val=$2
  # bpftrace does not support cross-thread atomic
  # counters, so instead, we stream events to stdout
  # and aggregate them at the end with awk.
  MAX_CONCURRENT=$(bpftrace --no-warnings -e "
uprobe:/lib64/libcrypto.so.3:RAND_bytes /pid == cpid/ {
  printf(\"ENTER %d\n\", tid);
}
uretprobe:/lib64/libcrypto.so.3:RAND_bytes /pid == cpid/ {
  printf(\"EXIT %d\n\", tid);
}" -c "./$bin -test.count 1 -test.run TestParallelRand 2>/dev/null" | \
	awk '
/^ENTER/ {
    # If this thread is not already tracked as active
    if (!in_flight[$2]) {
        in_flight[$2] = 1;
        active++;
        if (active > max) max = active;
    }
}
/^EXIT/ {
    # If we saw this thread enter, safely remove it
    if (in_flight[$2]) {
        delete in_flight[$2];
        active--;
    }
}
END {
    print (max == "" ? 0 : max);
}')
  echo "Peak concurrent RAND_bytes: $MAX_CONCURRENT"
  if [ -z "$MAX_CONCURRENT" ]; then
	  echo "FAIL: no bpftrace output"; exit 1;
  elif [[ ! "$MAX_CONCURRENT" =~ ^[0-9]+$ ]]; then
	echo "FAIL: bad bpftrace output: $MAX_CONCURRENT"; exit 1
  elif [ $MAX_CONCURRENT -gt $val ]; then
	echo "FAIL: exceeded $val"; exit 1
  fi
}


run_suite_unlimited () {
  local bin=semaphore.test
  local max=1000
  echo "Running without semaphore (no limit)"
  build_test $bin -tags openssl_no_sem
  for i in $(seq 1 $ITERATIONS); do
    exec_test $bin $max
  done
  rm $bin
}

run_suite_default () {
  local bin=semaphore.test
  local max=$(( CPU_COUNT * 4))
  echo "Running with semaphore (default limit)"
  build_test $bin
  for i in $(seq 1 $ITERATIONS); do
    exec_test $bin $max
  done
  rm $bin
}

run_suite_limit512() {
  local bin=semaphore.test
  local max=512
  echo "Running with semaphore (limit $max)"
  build_test $bin
  for i in $(seq 1 $ITERATIONS); do
    GOLANG_FIPS_DRBG_LIMIT=$max exec_test $bin $max
  done
  rm $bin
}

time run_suite_unlimited
time run_suite_default
time run_suite_limit512

echo "PASS (all tests)"
