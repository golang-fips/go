#!/bin/bash
set -e

# Try PLATFORM_ID
OS_ID=$(cat /etc/os-release | awk 'match($0,/PLATFORM_ID="platform:(.*)"/,a){print a[1]}')
if [[ "$OS_ID" == "" ]]; then
# Try REDHAT_BUGZILLA_PRODUCT
  OS_ID=$(cat /etc/os-release | awk 'match($0,/REDHAT_BUGZILLA_PRODUCT=\"(.*)\"/,a){print a[1]}')
fi


ROOT=$(realpath $(dirname $(readlink -f $0))/..)
CONFIG=$ROOT/go/src/crypto/internal/backend/boringtest/config.go

set_param () {
  local param=$1
  local val=$2
  echo "Setting $param to $val."
  sed -i "s/\"$param\":.*,/\"$param\": $val,/" $CONFIG
}

if [[ ! -f "$CONFIG" ]]; then
  echo "could not find $CONFIG"
fi

if [[ "$OS_ID" == "el9" ]]; then
  echo "Detected el9..."
  echo "Keeping current settings."
elif [[ "$OS_ID" == "el8" ]]; then
  echo "Detected el8..."
  set_param "PKCSv1.5" "true"
  set_param "SHA1" "true"
  set_param "RSA4096LeafCert" "true"
  set_param "RSA1024LeafCert" "true"
  set_param "TLS13" "true"
  set_param "CurveP224" "true"
elif [[ "$OS_ID" == "Red Hat Enterprise Linux 7" ]]; then
  echo "Detected el7..."
  set_param "PKCSv1.5" "true"
  set_param "SHA1" "true"
  set_param "RSA4096LeafCert" "false"
  set_param "RSA1024LeafCert" "true"
  set_param "TLS13" "false"
  set_param "CurveP224" "false"
else
  echo "Detected unknown os: $OS_ID ..."
  echo "Keeping current settings."
fi

