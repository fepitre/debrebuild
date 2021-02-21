#!/bin/bash

set -e
if [ "$DEBUG" == 1 ]; then
    set -x
    COMMON_OPTS="--debug"
fi

if [ "0$(tput colors 2> /dev/null)" -ge 16 ]; then
    RED='\033[0;31m'
    BLUE='\033[0;34m'
    GREEN='\033[0;32m'
    NC='\033[0m'
fi

localdir="$(readlink -f "$(dirname "$0")")"

COMMON_OPTS="$COMMON_OPTS --builder=mmdebstrap --gpg-sign-keyid 632F8C69E01B25C9E0C3ADF2F360C0D259FB650C"
QUBES_OPTS="$QUBES_OPTS --query-url https://ancient-tundra-75419.herokuapp.com"
QUBES_OPTS="$QUBES_OPTS --extra-repository-file $localdir/repos/qubes-r4.list --extra-repository-key $localdir/keys/qubes-debian-r4.asc"
QUBES_OPTS="$QUBES_OPTS --gpg-verify --gpg-verify-key $localdir/keys/qubes-debian-r4.asc"

echo_info() {
    echo -e "${BLUE}[I]${NC} $*" >&2
}

echo_ok() {
    echo -e "${GREEN}[I]${NC} $*" >&2
}

echo_err() {
    echo -e "${RED}[E]${NC} $*" >&2
}

do_build() {
    buildinfo="$1"
    parsed_name="$(basename "$buildinfo")"
    package="$(echo  "$parsed_name" | cut -d'_' -f1)"
    version="$(echo "$parsed_name" | cut -d'_' -f2)"
    output="/tmp/sources/$package/$version"
    DEBREBUILD_OPTS="$COMMON_OPTS"
    if [[ "$package" =~ ^qubes- ]] || [[ "$buildinfo" =~ ^.*qubes-os.org ]]; then
        DEBREBUILD_OPTS="$DEBREBUILD_OPTS $QUBES_OPTS"
    fi
    if [[ "$buildinfo" =~ .unreproducible$ ]]; then
        DEBREBUILD_OPTS="$DEBREBUILD_OPTS --no-checksums-verification"
    fi
    mkdir -p "$output"
    "$localdir"/../debrebuild.py $DEBREBUILD_OPTS --output "$output" "$buildinfo" || return 1
    cd "$output"
    ln -sf $package*.buildinfo buildinfo
    ln -sf rebuild*.link metadata
}

buildinfos=("$localdir"/data/*.buildinfo*)
buildinfos+=(
    "https://deb.qubes-os.org/r4.1/vm/pool/main/libc/libcomps/libcomps_0.1.15-2+deb11u1_amd64.buildinfo"
    "https://deb.qubes-os.org/r4.1/vm/pool/main/q/qubes-gui-agent/qubes-gui-agent_4.1.15-1+deb11u1_amd64.buildinfo"
)
failed_buildinfos=()

export GNUPGHOME="$localdir/gnupg"

for f in ${buildinfos[*]}; do
    bn_buildinfo="$(basename "$f")"
    echo_info "DEBREBUILD: $bn_buildinfo"
    if do_build "$f"; then
        echo_ok "SUCCESS: $f"
    else
        failed_buildinfos+=("$bn_buildinfo")
        echo_err "FAIL: $f"
    fi
done

if [ -n "${failed_buildinfos[*]}" ]; then
    echo_err "The following buildinfo failed to rebuild: ${failed_buildinfos[*]}"
    exit 1
fi
