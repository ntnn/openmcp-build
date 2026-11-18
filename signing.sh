#!/usr/bin/env bash

# Signs published container images with cosign and OCM component
# versions and verifies what it signed.
#
# Environment:
#   SIGNING_KEY     private key, either the path of a file holding it or the key itself.
#   SIGN            'false' turns signing off even when a key is present
#   SIGNING_NAME    OCM signature name
#   COSIGN          cosign binary, required by sign-images
#   OCM             ocm binary, required by sign-cv and verify-cv
#
# Subcommands:
#   enabled                                              exit 0 when signing should run, 1 otherwise
#   sign-images <image-base> <version> <component>…      cosign sign, each component one by one
#   sign-cv <ctf-dir> <component> <version>              ocm sign a component version in a local CTF
#   verify-cv <repository> <component> <version>         ocm verify a published component version

die() { echo "$@" >&2; exit 1; }
log() { echo ">>> $*"; }
installed() { command -v "$1" &> /dev/null; }

workdir=""

# Passphrase of the imported cosign key. cosign v3 always encrypts the key it imports and
# only takes the passphrase from this variable
key_password=""

finish() {
    if [[ -n "$workdir" ]]; then
        rm -rf "$workdir"
    fi
}
trap finish EXIT INT

# materialize <var> <target> — write the value of <var>, a file or the content itself, to <target> as mode 0600.
materialize() {
    local name="$1" value="${!1}" target="$2"

    if [[ -f "$value" ]]; then
        [[ -r "$value" ]] || die "$name names a file that cannot be read: $value"
        cp "$value" "$target" || die "cannot copy $name into ${target%/*}"
    else
        # CRLF line endings survive being pasted into a CI secret and break openssl.
        printf '%s\n' "$value" | tr -d '\r' > "$target" || die "cannot write $name"
    fi
    chmod 600 "$target" || die "cannot lock down $target"
}

_enabled() {
    [[ "${SIGN:-true}" != "false" ]] || return 1
    [[ -n "${SIGNING_KEY:-}" ]] || return 1
    return 0
}

prepare_workdir() {
    umask 077
    workdir="$(mktemp -d)" || die "cannot create a temporary working directory"
    chmod 700 "$workdir" || die "cannot lock down $workdir"

    materialize SIGNING_KEY "$workdir/signing.key"

    # RSA only: 'ocm sign' has no ECDSA handler, so any other key type would sign the
    # images and then fail on the component version.
    openssl rsa -in "$workdir/signing.key" -check -noout > /dev/null ||
        die "SIGNING_KEY is neither an existing file nor a usable unencrypted RSA private key"

    openssl pkey -in "$workdir/signing.key" -pubout -out "$workdir/pub.pem" || die "cannot derive the public key"
    [[ -s "$workdir/pub.pem" ]] || die "cannot derive the public key"
}

prepare_cosign_key() {
    key_password="$(openssl rand -hex 16)" || die "cannot generate the cosign key password"

    COSIGN_PASSWORD="$key_password" "$COSIGN" import-key-pair --key "$workdir/signing.key" --output-key-prefix "$workdir/cosign" -y ||
        die "cosign could not import the signing key"
}

# verify_signature <image> <digest> — cosign verify with the derived public key, which needs
# no passphrase.
verify_signature() {
    "$COSIGN" verify --key "$workdir/pub.pem" "$1@$2"
}

# sign_image <image-base> <version> <component>
sign_image() {
    local img="$1/$3:$2" dig=""

    if ! dig="$(docker buildx imagetools inspect "$img" --format '{{.Manifest.Digest}}' 2>/dev/null)"; then
        die "Could not read $img from the registry. Was it pushed?"
    fi
    [[ -n "$dig" ]] || die "Could not determine the digest of $img"

    if verify_signature "$img" "$dig" > /dev/null 2>&1; then
        log "$img@$dig is already signed with this key"
    else
        log "Signing $img@$dig"
        COSIGN_PASSWORD="$key_password" "$COSIGN" sign --key "$workdir/cosign.key" --yes "$img@$dig" ||
            die "could not sign $img@$dig"
    fi

    verify_signature "$img" "$dig" ||
        die "the signature of $img@$dig does not verify with the signing key"
    log "Verified the signature of $img@$dig"
}

# verify_cv <repository> <component> <version>
verify_cv() {
    "$OCM" verify componentversions --signature "${SIGNING_NAME}" --public-key "$workdir/pub.pem" "$1//$2:$3"
}

_sign_images() {
    local image_base="${1:-}" version="${2:-}" component=""

    [[ -n "$image_base" ]] || die "usage: signing.sh sign-images <image-base> <version> <component>..."
    [[ -n "$version" ]] || die "usage: signing.sh sign-images <image-base> <version> <component>..."
    shift 2
    [[ $# -gt 0 ]] || die "no components given to sign"
    installed docker || die "docker is required to read the manifest digests of the images"
    _enabled || die "signing is not enabled: set SIGNING_KEY to the key itself or the path of a file holding it, and leave SIGN unset or set it to anything but 'false'"

    prepare_workdir
    prepare_cosign_key

    for component in "$@"; do
        sign_image "$image_base" "$version" "$component"
    done
}

_sign_cv() {
    local ctf="${1:-}" component="${2:-}" version="${3:-}"

    [[ -n "$ctf" && -n "$component" && -n "$version" ]] || die "usage: signing.sh sign-cv <ctf-dir> <component> <version>"
    _enabled || die "signing is not enabled: set SIGNING_KEY to the key itself or the path of a file holding it, and leave SIGN unset or set it to anything but 'false'"

    prepare_workdir

    log "Signing $component:$version in $ctf"
    "$OCM" sign componentversions --signature "${SIGNING_NAME}" --private-key "$workdir/signing.key" "directory::$ctf//$component:$version" ||
        die "could not sign $component:$version"
    verify_cv "directory::$ctf" "$component" "$version" ||
        die "the signature of $component:$version does not verify in $ctf"
    log "Signed and verified $component:$version"
}

_verify_cv() {
    local repository="${1:-}" component="${2:-}" version="${3:-}"

    [[ -n "$repository" && -n "$component" && -n "$version" ]] || die "usage: signing.sh verify-cv <repository> <component> <version>"
    _enabled || die "signing is not enabled: set SIGNING_KEY to the key itself or the path of a file holding it, and leave SIGN unset or set it to anything but 'false'"

    prepare_workdir

    verify_cv "$repository" "$component" "$version" ||
        die "$component:$version is not verifiably signed with ${SIGNING_NAME}"
    log "Verified the signature ${SIGNING_NAME} of $component:$version"
}

subcmd="${1:-}"
[[ -n "$subcmd" ]] || die "usage: signing.sh <enabled|sign-images|sign-cv|verify-cv> [args]"
shift

case "$subcmd" in
    (enabled) _enabled;;
    (sign-images) _sign_images "$@";;
    (sign-cv) _sign_cv "$@";;
    (verify-cv) _verify_cv "$@";;
    (*) die "Unknown subcommand: $subcmd";;
esac
