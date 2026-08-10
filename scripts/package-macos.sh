#!/bin/bash

set -euo pipefail
IFS=$'\n\t'
umask 077

APP_BUNDLE_ID="dev.nodavo.macos"
AGENT_BUNDLE_ID="dev.nodavo.agent"
MINIMUM_MACOS_VERSION="13.0"
SWIFT_RESOURCE_BUNDLE="NodavoMac_NodavoMac.bundle"

usage() {
    cat <<'USAGE'
Usage:
  scripts/package-macos.sh --version X.Y.Z --build-number N [--output DIR]
  scripts/package-macos.sh --development --version X.Y.Z --build-number N [--output DIR]

Release mode (default) requires all of:
  APPLE_TEAM_ID                    10-character Apple Developer Team ID
  MACOS_SIGNING_IDENTITY           Developer ID Application identity or SHA-1
  MACOS_APP_PROVISIONING_PROFILE   profile for dev.nodavo.macos
  MACOS_AGENT_PROVISIONING_PROFILE profile for dev.nodavo.agent
  MACOS_NOTARY_PROFILE             notarytool Keychain profile name

Release mode signs with the hardened runtime, notarizes both the app and DMG,
staples their tickets, and fails unless Gatekeeper accepts both artifacts.

--development creates an ad-hoc signed, non-notarized artifact. It has no
restricted Keychain entitlements, does not register the embedded LaunchAgent,
and is explicitly labeled NOT FOR DISTRIBUTION.
USAGE
}

fail() {
    echo "package-macos: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

render_template() {
    local source=$1
    local destination=$2
    sed \
        -e "s|@VERSION@|${VERSION}|g" \
        -e "s|@BUILD_NUMBER@|${BUILD_NUMBER}|g" \
        -e "s|@DISPLAY_NAME@|${DISPLAY_NAME}|g" \
        -e "s|@DEVELOPMENT_BOOL@|${DEVELOPMENT_BOOL}|g" \
        -e "s|@TEAM_ID@|${TEAM_ID}|g" \
        -e "s|@KEYCHAIN_ACCESS_GROUP@|${KEYCHAIN_ACCESS_GROUP}|g" \
        "$source" >"$destination"
}

validate_profile() {
    local profile=$1
    local expected_identifier=$2
    local decoded=$3

    security cms -D -i "$profile" >"$decoded" 2>/dev/null \
        || fail "could not decode provisioning profile: $profile"
    plutil -lint "$decoded" >/dev/null

    local profile_team
    local profile_identifier
    profile_team=$(/usr/libexec/PlistBuddy -c "Print :TeamIdentifier:0" "$decoded" 2>/dev/null) \
        || fail "provisioning profile has no TeamIdentifier: $profile"
    profile_identifier=$(/usr/libexec/PlistBuddy \
        -c "Print :Entitlements:com.apple.application-identifier" "$decoded" 2>/dev/null) \
        || fail "provisioning profile has no application identifier: $profile"
    [[ "$profile_team" == "$TEAM_ID" ]] \
        || fail "provisioning profile TeamIdentifier does not match APPLE_TEAM_ID"
    [[ "$profile_identifier" == "${TEAM_ID}.${expected_identifier}" ]] \
        || fail "provisioning profile does not authorize ${expected_identifier}"

    /usr/libexec/PlistBuddy -c "Print :Entitlements:keychain-access-groups" "$decoded" 2>/dev/null \
        | grep -F -x -q "    ${KEYCHAIN_ACCESS_GROUP}" \
        || fail "provisioning profile does not authorize ${KEYCHAIN_ACCESS_GROUP}"

    python3 - "$decoded" <<'PY'
import datetime
import plistlib
import sys

with open(sys.argv[1], "rb") as source:
    profile = plistlib.load(source)
expiration = profile.get("ExpirationDate")
if not isinstance(expiration, datetime.datetime):
    raise SystemExit("provisioning profile has no expiration date")
now = datetime.datetime.now(datetime.timezone.utc)
if expiration.tzinfo is None:
    expiration = expiration.replace(tzinfo=datetime.timezone.utc)
if expiration <= now:
    raise SystemExit("provisioning profile is expired")
PY
}

verify_universal() {
    local binary=$1
    local architectures
    architectures=$(lipo -archs "$binary")
    [[ " $architectures " == *" arm64 "* && " $architectures " == *" x86_64 "* ]] \
        || fail "binary is not universal arm64+x86_64: $binary ($architectures)"
}

verify_system_dependencies() {
    local binary=$1
    local dependency
    while IFS= read -r dependency; do
        case "$dependency" in
            /System/* | /usr/lib/* | @rpath/* | @loader_path/* | @executable_path/*) ;;
            *) fail "non-system absolute dependency in $binary: $dependency" ;;
        esac
    done < <(otool -L "$binary" \
        | sed -n -e 's/^[[:space:]][[:space:]]*\([^[:space:]][^[:space:]]*\).*/\1/p')
}

sign_path() {
    local path=$1
    local entitlements=${2:-}
    local identifier=${3:-}
    local arguments=(--force --options runtime)
    if [[ "$MODE" == "release" ]]; then
        arguments+=(--sign "$MACOS_SIGNING_IDENTITY" --timestamp)
    else
        arguments+=(--sign - --timestamp=none)
    fi
    [[ -z "$entitlements" ]] || arguments+=(--entitlements "$entitlements")
    [[ -z "$identifier" ]] || arguments+=(--identifier "$identifier")
    codesign "${arguments[@]}" "$path"
}

notarize_archive() {
    local archive=$1
    local label=$2
    local result="${BUILD_ROOT}/notary-${label}.plist"
    xcrun notarytool submit "$archive" \
        --keychain-profile "$MACOS_NOTARY_PROFILE" \
        --wait --timeout 30m --output-format plist >"$result"
    local status
    status=$(plutil -extract status raw "$result" 2>/dev/null) \
        || fail "notarytool returned no status for $label"
    [[ "$status" == "Accepted" ]] || fail "notarization was not accepted for $label: $status"
}

MODE="release"
VERSION=""
BUILD_NUMBER=""
OUTPUT_DIRECTORY=""

while (($#)); do
    case "$1" in
        --development)
            MODE="development"
            shift
            ;;
        --version)
            (($# >= 2)) || fail "--version requires a value"
            VERSION=$2
            shift 2
            ;;
        --build-number)
            (($# >= 2)) || fail "--build-number requires a value"
            BUILD_NUMBER=$2
            shift 2
            ;;
        --output)
            (($# >= 2)) || fail "--output requires a value"
            OUTPUT_DIRECTORY=$2
            shift 2
            ;;
        --help | -h)
            usage
            exit 0
            ;;
        *) fail "unknown argument: $1" ;;
    esac
done

[[ $(uname -s) == "Darwin" ]] || fail "macOS packaging must run on macOS"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || fail "--version must contain exactly three numeric components"
[[ "$BUILD_NUMBER" =~ ^[1-9][0-9]*$ ]] || fail "--build-number must be a positive integer"

for command in cargo codesign ditto file hdiutil lipo otool plutil rustup security sed swift xcrun; do
    require_command "$command"
done
require_command python3
require_command spctl

SCRIPT_DIRECTORY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPOSITORY_ROOT=$(cd "${SCRIPT_DIRECTORY}/.." && pwd -P)
MACOS_SOURCE="${REPOSITORY_ROOT}/apps/macos"
PACKAGING_SOURCE="${MACOS_SOURCE}/Packaging"
BUILD_ROOT="${REPOSITORY_ROOT}/target/package-macos/${VERSION}-${BUILD_NUMBER}-${MODE}"
OUTPUT_DIRECTORY=${OUTPUT_DIRECTORY:-"${REPOSITORY_ROOT}/dist/macos"}
mkdir -p "$OUTPUT_DIRECTORY"
OUTPUT_DIRECTORY=$(cd "$OUTPUT_DIRECTORY" && pwd -P)

[[ "$BUILD_ROOT" == "${REPOSITORY_ROOT}/target/package-macos/"* ]] \
    || fail "refusing unsafe build root"
rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT"

if [[ "$MODE" == "release" ]]; then
    : "${APPLE_TEAM_ID:?APPLE_TEAM_ID is required for release packaging}"
    : "${MACOS_SIGNING_IDENTITY:?MACOS_SIGNING_IDENTITY is required for release packaging}"
    : "${MACOS_APP_PROVISIONING_PROFILE:?MACOS_APP_PROVISIONING_PROFILE is required}"
    : "${MACOS_AGENT_PROVISIONING_PROFILE:?MACOS_AGENT_PROVISIONING_PROFILE is required}"
    : "${MACOS_NOTARY_PROFILE:?MACOS_NOTARY_PROFILE is required for release packaging}"
    [[ "$APPLE_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || fail "APPLE_TEAM_ID is invalid"
    [[ -f "$MACOS_APP_PROVISIONING_PROFILE" ]] || fail "app provisioning profile is missing"
    [[ -f "$MACOS_AGENT_PROVISIONING_PROFILE" ]] || fail "agent provisioning profile is missing"
    security find-identity -v -p codesigning \
        | grep -F -q "$MACOS_SIGNING_IDENTITY" \
        || fail "MACOS_SIGNING_IDENTITY is not available in the current Keychain"
    TEAM_ID=$APPLE_TEAM_ID
    KEYCHAIN_ACCESS_GROUP="${TEAM_ID}.${AGENT_BUNDLE_ID}"
    DISPLAY_NAME="Nodavo"
    DEVELOPMENT_BOOL="false"
    validate_profile "$MACOS_APP_PROVISIONING_PROFILE" "$APP_BUNDLE_ID" \
        "${BUILD_ROOT}/app-profile.plist"
    validate_profile "$MACOS_AGENT_PROVISIONING_PROFILE" "$AGENT_BUNDLE_ID" \
        "${BUILD_ROOT}/agent-profile.plist"
else
    TEAM_ID="DEVELOPMENT"
    KEYCHAIN_ACCESS_GROUP="DEVELOPMENT-NOT-ENTITLED.${AGENT_BUNDLE_ID}"
    DISPLAY_NAME="Nodavo Development (Not for Distribution)"
    DEVELOPMENT_BOOL="true"
fi

export COPYFILE_DISABLE=1
export MACOSX_DEPLOYMENT_TARGET=$MINIMUM_MACOS_VERSION
export ZERO_AR_DATE=1
# Workspace release stripping also affects host proc-macro dylibs with current
# Rust toolchains. Preserve intermediates and strip only the two final universal
# executables below.
export CARGO_PROFILE_RELEASE_STRIP=none

SWIFT_ARM_SCRATCH="${BUILD_ROOT}/swift-arm64"
SWIFT_X86_SCRATCH="${BUILD_ROOT}/swift-x86_64"
swift build --package-path "$MACOS_SOURCE" --scratch-path "$SWIFT_ARM_SCRATCH" \
    --configuration release --triple "arm64-apple-macosx${MINIMUM_MACOS_VERSION}" \
    --product Nodavo --disable-index-store
swift build --package-path "$MACOS_SOURCE" --scratch-path "$SWIFT_X86_SCRATCH" \
    --configuration release --triple "x86_64-apple-macosx${MINIMUM_MACOS_VERSION}" \
    --product Nodavo --disable-index-store
SWIFT_ARM_BIN=$(swift build --package-path "$MACOS_SOURCE" --scratch-path "$SWIFT_ARM_SCRATCH" \
    --configuration release --triple "arm64-apple-macosx${MINIMUM_MACOS_VERSION}" --show-bin-path)
SWIFT_X86_BIN=$(swift build --package-path "$MACOS_SOURCE" --scratch-path "$SWIFT_X86_SCRATCH" \
    --configuration release --triple "x86_64-apple-macosx${MINIMUM_MACOS_VERSION}" --show-bin-path)

RUST_TARGET_DIRECTORY="${BUILD_ROOT}/rust"
CARGO_TARGET_DIR="$RUST_TARGET_DIRECTORY" cargo build --locked --release -p nodavo-agent \
    --target aarch64-apple-darwin
CARGO_TARGET_DIR="$RUST_TARGET_DIRECTORY" cargo build --locked --release -p nodavo-agent \
    --target x86_64-apple-darwin

UNIVERSAL_DIRECTORY="${BUILD_ROOT}/universal"
mkdir -p "$UNIVERSAL_DIRECTORY"
lipo -create "${SWIFT_ARM_BIN}/Nodavo" "${SWIFT_X86_BIN}/Nodavo" \
    -output "${UNIVERSAL_DIRECTORY}/Nodavo"
lipo -create \
    "${RUST_TARGET_DIRECTORY}/aarch64-apple-darwin/release/nodavo-agent" \
    "${RUST_TARGET_DIRECTORY}/x86_64-apple-darwin/release/nodavo-agent" \
    -output "${UNIVERSAL_DIRECTORY}/nodavo-agent"
strip -S -x "${UNIVERSAL_DIRECTORY}/Nodavo" "${UNIVERSAL_DIRECTORY}/nodavo-agent"
verify_universal "${UNIVERSAL_DIRECTORY}/Nodavo"
verify_universal "${UNIVERSAL_DIRECTORY}/nodavo-agent"
verify_system_dependencies "${UNIVERSAL_DIRECTORY}/Nodavo"
verify_system_dependencies "${UNIVERSAL_DIRECTORY}/nodavo-agent"

APP_PATH="${BUILD_ROOT}/Nodavo.app"
HELPER_APP="${APP_PATH}/Contents/Library/Helpers/NodavoAgent.app"
mkdir -p \
    "${APP_PATH}/Contents/MacOS" \
    "${APP_PATH}/Contents/Resources" \
    "${APP_PATH}/Contents/Library/LaunchAgents" \
    "${HELPER_APP}/Contents/MacOS" \
    "${HELPER_APP}/Contents/Resources"
install -m 0755 "${UNIVERSAL_DIRECTORY}/Nodavo" "${APP_PATH}/Contents/MacOS/Nodavo"
install -m 0755 "${UNIVERSAL_DIRECTORY}/nodavo-agent" \
    "${HELPER_APP}/Contents/MacOS/nodavo-agent"

RESOURCE_SOURCE="${SWIFT_ARM_BIN}/${SWIFT_RESOURCE_BUNDLE}"
[[ -d "$RESOURCE_SOURCE" ]] || fail "Swift resource bundle was not produced"
ditto "$RESOURCE_SOURCE" "${APP_PATH}/Contents/Resources/${SWIFT_RESOURCE_BUNDLE}"
rm -rf "${APP_PATH}/Contents/Resources/${SWIFT_RESOURCE_BUNDLE}/Contents/_CodeSignature"
ditto "${PACKAGING_SOURCE}/Resources/en.lproj" "${APP_PATH}/Contents/Resources/en.lproj"
ditto "${PACKAGING_SOURCE}/Resources/ru.lproj" "${APP_PATH}/Contents/Resources/ru.lproj"
ditto "${PACKAGING_SOURCE}/Resources/en.lproj" "${HELPER_APP}/Contents/Resources/en.lproj"
ditto "${PACKAGING_SOURCE}/Resources/ru.lproj" "${HELPER_APP}/Contents/Resources/ru.lproj"

render_template "${PACKAGING_SOURCE}/Info.plist.in" "${APP_PATH}/Contents/Info.plist"
render_template "${PACKAGING_SOURCE}/AgentInfo.plist.in" "${HELPER_APP}/Contents/Info.plist"
render_template "${PACKAGING_SOURCE}/dev.nodavo.agent.plist.in" \
    "${APP_PATH}/Contents/Library/LaunchAgents/dev.nodavo.agent.plist"

if [[ "$MODE" == "release" ]]; then
    render_template "${PACKAGING_SOURCE}/App.entitlements.in" "${BUILD_ROOT}/App.entitlements"
    render_template "${PACKAGING_SOURCE}/Agent.entitlements.in" "${BUILD_ROOT}/Agent.entitlements"
    install -m 0644 "$MACOS_APP_PROVISIONING_PROFILE" \
        "${APP_PATH}/Contents/embedded.provisionprofile"
    install -m 0644 "$MACOS_AGENT_PROVISIONING_PROFILE" \
        "${HELPER_APP}/Contents/embedded.provisionprofile"
    APP_ENTITLEMENTS="${BUILD_ROOT}/App.entitlements"
    AGENT_ENTITLEMENTS="${BUILD_ROOT}/Agent.entitlements"
else
    APP_ENTITLEMENTS="${PACKAGING_SOURCE}/Development.entitlements"
    AGENT_ENTITLEMENTS="${PACKAGING_SOURCE}/Development.entitlements"
    cat >"${APP_PATH}/Contents/Resources/DEVELOPMENT-NOT-FOR-DISTRIBUTION.txt" <<'NOTICE'
This is an ad-hoc signed development build. It is not notarized, has no
provisioned Keychain access, and must not be distributed as a release.
NOTICE
fi

if grep -E '@[A-Z_]+@' \
    "${APP_PATH}/Contents/Info.plist" \
    "${HELPER_APP}/Contents/Info.plist" \
    "${APP_PATH}/Contents/Library/LaunchAgents/dev.nodavo.agent.plist" \
    "$APP_ENTITLEMENTS" "$AGENT_ENTITLEMENTS" >/dev/null 2>&1; then
    fail "an unresolved packaging template token remains"
fi
find "$APP_PATH" -name '*.plist' -print0 | while IFS= read -r -d '' plist; do
    plutil -lint "$plist" >/dev/null
done
plutil -lint "${APP_PATH}/Contents/Resources/en.lproj/InfoPlist.strings" >/dev/null
plutil -lint "${APP_PATH}/Contents/Resources/ru.lproj/InfoPlist.strings" >/dev/null

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$REPOSITORY_ROOT" log -1 --format=%ct)}
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || fail "SOURCE_DATE_EPOCH must be an integer"
NORMALIZED_TIME=$(date -r "$SOURCE_DATE_EPOCH" '+%Y%m%d%H%M.%S')
find "$APP_PATH" -exec touch -h -t "$NORMALIZED_TIME" {} +

sign_path "${APP_PATH}/Contents/Resources/${SWIFT_RESOURCE_BUNDLE}"
sign_path "$HELPER_APP" "$AGENT_ENTITLEMENTS" "$AGENT_BUNDLE_ID"
sign_path "$APP_PATH" "$APP_ENTITLEMENTS" "$APP_BUNDLE_ID"
codesign --verify --deep --strict --verbose=2 "$APP_PATH"

[[ $(plutil -extract CFBundleIdentifier raw "${APP_PATH}/Contents/Info.plist") == "$APP_BUNDLE_ID" ]]
[[ $(plutil -extract CFBundleIdentifier raw "${HELPER_APP}/Contents/Info.plist") == "$AGENT_BUNDLE_ID" ]]
[[ $(plutil -extract NodavoKeychainAccessGroup raw "${APP_PATH}/Contents/Info.plist") \
    == "$KEYCHAIN_ACCESS_GROUP" ]]
[[ -f "${APP_PATH}/Contents/Resources/${SWIFT_RESOURCE_BUNDLE}/Contents/Resources/en.lproj/Localizable.strings" ]]
[[ -f "${APP_PATH}/Contents/Resources/${SWIFT_RESOURCE_BUNDLE}/Contents/Resources/ru.lproj/Localizable.strings" ]]

if [[ "$MODE" == "release" ]]; then
    APP_ARCHIVE="${BUILD_ROOT}/Nodavo-app.zip"
    ditto -c -k --keepParent "$APP_PATH" "$APP_ARCHIVE"
    notarize_archive "$APP_ARCHIVE" "app"
    xcrun stapler staple "$APP_PATH"
    xcrun stapler validate "$APP_PATH"
    spctl --assess --type execute --verbose=4 "$APP_PATH"
fi

DMG_ROOT="${BUILD_ROOT}/dmg-root"
mkdir -p "$DMG_ROOT"
ditto "$APP_PATH" "${DMG_ROOT}/Nodavo.app"
ln -s /Applications "${DMG_ROOT}/Applications"
if [[ "$MODE" == "development" ]]; then
    cp "${APP_PATH}/Contents/Resources/DEVELOPMENT-NOT-FOR-DISTRIBUTION.txt" \
        "${DMG_ROOT}/DEVELOPMENT-NOT-FOR-DISTRIBUTION.txt"
fi

if [[ "$MODE" == "release" ]]; then
    DMG_NAME="Nodavo-${VERSION}-${BUILD_NUMBER}.dmg"
else
    DMG_NAME="Nodavo-${VERSION}-${BUILD_NUMBER}-development-NOT-NOTARIZED.dmg"
fi
DMG_PATH="${BUILD_ROOT}/${DMG_NAME}"
hdiutil create -quiet -ov -format UDZO -volname "Nodavo ${VERSION}" \
    -srcfolder "$DMG_ROOT" "$DMG_PATH"
sign_path "$DMG_PATH"
codesign --verify --strict --verbose=2 "$DMG_PATH"

if [[ "$MODE" == "release" ]]; then
    notarize_archive "$DMG_PATH" "dmg"
    xcrun stapler staple "$DMG_PATH"
    xcrun stapler validate "$DMG_PATH"
    spctl --assess --type open --context context:primary-signature --verbose=4 "$DMG_PATH"
else
    if spctl --assess --type execute --verbose=4 "$APP_PATH"; then
        echo "Development artifact happened to pass the local Gatekeeper policy; it is still not notarized."
    else
        echo "Development artifact is not Gatekeeper-approved (expected for ad-hoc signing)."
    fi
fi

if [[ "$MODE" == "release" ]]; then
    OUTPUT_APP="${OUTPUT_DIRECTORY}/Nodavo-${VERSION}.app"
else
    OUTPUT_APP="${OUTPUT_DIRECTORY}/Nodavo-${VERSION}-development-NOT-NOTARIZED.app"
fi
rm -rf "$OUTPUT_APP" "${OUTPUT_DIRECTORY}/${DMG_NAME}"
ditto "$APP_PATH" "$OUTPUT_APP"
ditto "$DMG_PATH" "${OUTPUT_DIRECTORY}/${DMG_NAME}"

echo "App: ${OUTPUT_APP}"
echo "DMG: ${OUTPUT_DIRECTORY}/${DMG_NAME}"
if [[ "$MODE" == "development" ]]; then
    echo "Status: DEVELOPMENT ONLY — ad-hoc signed, not notarized, not for distribution."
else
    echo "Status: Developer ID signed, notarization accepted, tickets stapled and validated."
fi
