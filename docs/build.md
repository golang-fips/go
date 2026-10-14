# Building a go binary that includes golang-fips patches

## Env variables

`GOEXPERIMENT=strictfipsruntime` helps ensure a fips compliant binary is built. Note that this is functionally equivalent of

```
GO_BUILDTAGS+="goexperiment.strictfipsruntime"
```

## Native build - Method 1

The easiest way to do is to simply clone this repo, apply patches and from the internal go/src directory run ./make.bash. See a more comprehensive script at `scripts/build1.sh`

```
git clone https://github.com/golang-fips/go.git golang-fips
cd golang-fips
./scripts/full-initialize-repo.sh go$GOLANG_VER
cd go/src
./make.bash --no-clean
```

## Native build - Method 2

Another way is to directly apply fips patches on downloaded go and golang-fips binaries. See full script at `scripts/build2.sh`

```
wget https://github.com/golang/go/archive/refs/tags/go1.22.2.tar.gz
wget https://github.com/golang-fips/go/archive/refs/tags/go1.22.2-1-openssl-fips.tar.gz
tar -xf go1.22.2.tar.gz
tar -xf go1.22.2-1-openssl-fips.tar.gz
cd go-go1.22.2
for patch in ../go-go1.22.2-1-openssl-fips/patches/*.patch; do
    patch -p1 < "${patch}"
done
cd src
./make.bash --no-clean
```

## Container Build

So far the two methods above described steps to build golang natively. To build golang inside a container, copy the sample Dockerfile located at scripts/Dockerfile.sample to a new directory, modify it to add distro specific variables and run docker/podman on it.

```
mkdir build-context
cp scripts/Dockerfile.sample scripts/Dockerfile
# modify it to make it distro specific
podman/docker build .
```
