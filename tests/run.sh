#!/bin/bash

set -xe

localdir="$(readlink -f "$(dirname "$0")")"

for f in "$localdir"/data/*.buildinfo
do
  package="$(cat "$f" | grep -oP 'Source: \K.*')"
  version="$(cat "$f" | grep -oP 'Version: \K.*')"
  output="/tmp/sources/$package/$version"
  mkdir -p "$output"
  "$localdir"/../debrebuild.py --output "$output" --builder=mmdebstrap "$f" \
    --extra-repository-file "$localdir/repos/qubes-r4.list" \
    --extra-repository-key "$localdir/keys/qubes-debian-r4.asc" \
    --query-url https://ancient-tundra-75419.herokuapp.com/ \
    --debug
  cd "$output"
  ln -sf $package*.buildinfo buildinfo
  ln -sf rebuild*.link metadata
done
