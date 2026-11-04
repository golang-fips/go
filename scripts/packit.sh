#!/usr/bin/env bash
# This script execute a set of steps needed by the .packit.yaml file

# Detect the Go version targeted in the PR
version=$(awk '/github.com\/golang\/go/ {gsub(/[: "go]/, "", $2); print $2}' config/versions.json)
# Split the version using '.' as the delimiter
IFS='.' read -ra parts <<< "$version"
# Extract the first two parts and store in go_api
go_api="${parts[0]}.${parts[1]}"
# Extract the third part and store in go_patch
go_patch="${parts[2]}"
# Create a high package release number. This is a dirty hack.
pkg_release="99"

package="go$version-$pkg_release-openssl-fips"

if [ "$1" = "create-archive" ]; then
  git archive --verbose --output $package.tar.gz --prefix go-$package/ HEAD
  ls -1t ./go*-openssl-fips.tar.gz | head -n 1
else
  # Drop fedora.go file
  rm -fv .packit_rpm/fedora.go
  sed -i '/SOURCE2/d' .packit_rpm/golang.spec
  sed -i '/fedora.go/d' .packit_rpm/golang.spec
  # Drop all the patches, we don't know if they can be apply to the new code
  rm -fv .packit_rpm/*.patch
  sed -ri '/^Patch[0-9]*:.+$/d' .packit_rpm/golang.spec

  # Update the Go version in golang.spec with the value of $go_api and $go_patch
  sed -i "s/%global go_api .*/%global go_api $go_api/" .packit_rpm/golang.spec
  sed -i "s/%global go_patch .*/%global go_patch $go_patch/" .packit_rpm/golang.spec
  sed -i "s/%global pkg_release .*/%global pkg_release $pkg_release/" .packit_rpm/golang.spec
fi
