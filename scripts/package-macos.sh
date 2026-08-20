#!/bin/bash

set -euo pipefail
IFS=$'\n\t'
umask 077

APP_BUNDLE_ID="dev.nodavo.macos"
AGENT_BUNDLE_ID="dev.nodavo.agent"
MACH_SERVICE_NAME="dev.nodavo.agent.ipc"
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
staples their tickets, and fails unless Gatekeeper accepts both artifacts. The
UI profile does not need the agent's Keychain access group; the helper profile
must authorize it.

--development creates an ad-hoc signed, non-notarized artifact with the
compile-time same-user UDS IPC verification bypass. It has no restricted Keychain
entitlements, does not register the embedded LaunchAgent, and is explicitly
labeled NOT FOR DISTRIBUTION.
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
        -e "s|@MACH_SERVICE_BOOL@|${MACH_SERVICE_BOOL}|g" \
        -e "s|@TEAM_ID@|${TEAM_ID}|g" \
        -e "s|@KEYCHAIN_ACCESS_GROUP@|${KEYCHAIN_ACCESS_GROUP}|g" \
        "$source" >"$destination"
}

validate_profile() {
    local profile=$1
    local expected_identifier=$2
    local decoded=$3
    local require_keychain_group=$4

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

    if [[ "$require_keychain_group" == "true" ]]; then
        /usr/libexec/PlistBuddy -c "Print :Entitlements:keychain-access-groups" "$decoded" 2>/dev/null \
            | grep -F -x -q "    ${KEYCHAIN_ACCESS_GROUP}" \
            || fail "provisioning profile does not authorize ${KEYCHAIN_ACCESS_GROUP}"
    fi

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

RUST_PRODUCT_VERSION=$(cargo metadata --locked --no-deps --format-version 1 \
    --manifest-path "${REPOSITORY_ROOT}/Cargo.toml" \
    | python3 -c 'import json,sys; matches=[p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "nodavo-agent"]; print(matches[0]) if len(matches) == 1 else sys.exit("nodavo-agent package metadata is missing or ambiguous")') \
    || fail "could not read the exact nodavo-agent package version"
[[ "$VERSION" == "$RUST_PRODUCT_VERSION" ]] \
    || fail "--version ${VERSION} does not match nodavo-agent ${RUST_PRODUCT_VERSION}"
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
    MACH_SERVICE_BOOL="true"
    validate_profile "$MACOS_APP_PROVISIONING_PROFILE" "$APP_BUNDLE_ID" \
        "${BUILD_ROOT}/app-profile.plist" false
    validate_profile "$MACOS_AGENT_PROVISIONING_PROFILE" "$AGENT_BUNDLE_ID" \
        "${BUILD_ROOT}/agent-profile.plist" true
else
    TEAM_ID="DEVELOPMENT"
    KEYCHAIN_ACCESS_GROUP="DEVELOPMENT-NOT-ENTITLED.${AGENT_BUNDLE_ID}"
    DISPLAY_NAME="Nodavo Development (Not for Distribution)"
    DEVELOPMENT_BOOL="true"
    MACH_SERVICE_BOOL="false"
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
SWIFT_BUILD_FLAGS=()
RUST_AUTH_FEATURES=(--no-default-features)
if [[ "$MODE" == "release" ]]; then
    export NODAVO_APPLE_TEAM_ID="$TEAM_ID"
else
    unset NODAVO_APPLE_TEAM_ID
    SWIFT_BUILD_FLAGS=(-Xswiftc -DNODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC)
    RUST_AUTH_FEATURES+=(--features development-unverified-local-ipc)
fi
for RUST_TARGET in aarch64-apple-darwin x86_64-apple-darwin; do
    AGENT_FEATURE_TREE=$(cargo tree --locked \
        --manifest-path "${REPOSITORY_ROOT}/Cargo.toml" \
        -e features -p nodavo-agent \
        "${RUST_AUTH_FEATURES[@]}" --target "$RUST_TARGET") \
        || fail "could not inspect the exact nodavo-agent feature tree for ${RUST_TARGET}"
    if grep -F 'nodavo-update feature "supervisor-host"' \
        <<<"$AGENT_FEATURE_TREE" >/dev/null; then
        fail "nodavo-agent must not enable the supervisor-only update reducer feature"
    fi
done
swift build --package-path "$MACOS_SOURCE" --scratch-path "$SWIFT_ARM_SCRATCH" \
    --configuration release --triple "arm64-apple-macosx${MINIMUM_MACOS_VERSION}" \
    --product Nodavo --disable-index-store "${SWIFT_BUILD_FLAGS[@]}"
swift build --package-path "$MACOS_SOURCE" --scratch-path "$SWIFT_X86_SCRATCH" \
    --configuration release --triple "x86_64-apple-macosx${MINIMUM_MACOS_VERSION}" \
    --product Nodavo --disable-index-store "${SWIFT_BUILD_FLAGS[@]}"
SWIFT_ARM_BIN=$(swift build --package-path "$MACOS_SOURCE" --scratch-path "$SWIFT_ARM_SCRATCH" \
    --configuration release --triple "arm64-apple-macosx${MINIMUM_MACOS_VERSION}" --show-bin-path)
SWIFT_X86_BIN=$(swift build --package-path "$MACOS_SOURCE" --scratch-path "$SWIFT_X86_SCRATCH" \
    --configuration release --triple "x86_64-apple-macosx${MINIMUM_MACOS_VERSION}" --show-bin-path)

RUST_TARGET_DIRECTORY="${BUILD_ROOT}/rust"
CARGO_TARGET_DIR="$RUST_TARGET_DIRECTORY" cargo build --locked --release -p nodavo-agent \
    "${RUST_AUTH_FEATURES[@]}" \
    --target aarch64-apple-darwin
CARGO_TARGET_DIR="$RUST_TARGET_DIRECTORY" cargo build --locked --release -p nodavo-agent \
    "${RUST_AUTH_FEATURES[@]}" \
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

AGENT_SELF_CHECK=$(python3 - "${UNIVERSAL_DIRECTORY}/nodavo-agent" <<'PY'
import subprocess
import sys

try:
    result = subprocess.run(
        [sys.argv[1], "--self-check"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
except (subprocess.SubprocessError, OSError):
    raise SystemExit(1)
print(result.stdout.strip())
PY
) || fail "agent local IPC policy self-check failed"
if [[ "$MODE" == "release" ]]; then
    [[ "$AGENT_SELF_CHECK" == "nodavo-agent: xpc-signed-mutual-local-ipc" ]] \
        || fail "release agent does not select signed mutual XPC local IPC"
else
    [[ "$AGENT_SELF_CHECK" == "nodavo-agent: development-unverified-uds-local-ipc" ]] \
        || fail "development agent does not contain the explicit UDS IPC bypass"
fi

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
provisioned Keychain access, includes an unsafe same-user UDS IPC bypass,
and must not be distributed as a release.
NOTICE
fi

python3 - "$APP_ENTITLEMENTS" "$AGENT_ENTITLEMENTS" "$MODE" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as source:
    ui = plistlib.load(source)
with open(sys.argv[2], "rb") as source:
    agent = plistlib.load(source)
if sys.argv[3] == "release":
    expected_ui = {
        "com.apple.application-identifier",
        "com.apple.developer.team-identifier",
    }
    expected_agent = expected_ui | {"keychain-access-groups"}
else:
    expected_ui = set()
    expected_agent = set()
if set(ui) != expected_ui:
    raise SystemExit("UI entitlement template contains a broad or missing entitlement")
if set(agent) != expected_agent:
    raise SystemExit("agent entitlement template contains a broad or missing entitlement")
PY

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
if plutil -extract NSDownloadsFolderUsageDescription raw \
    "${APP_PATH}/Contents/Info.plist" >/dev/null 2>&1; then
    fail "Downloads usage description belongs only to the receiving agent"
fi
[[ $(plutil -extract NSDownloadsFolderUsageDescription raw \
    "${HELPER_APP}/Contents/Info.plist") \
    == "Nodavo saves files received from explicitly paired devices in Downloads/Nodavo." ]] \
    || fail "agent bundle has no exact Downloads usage description"
for localization in en ru; do
    LOCALIZED_DOWNLOADS_USAGE=$(plutil -extract NSDownloadsFolderUsageDescription raw \
        "${HELPER_APP}/Contents/Resources/${localization}.lproj/InfoPlist.strings" 2>/dev/null) \
        || fail "agent bundle has no ${localization} Downloads usage description"
    [[ -n "$LOCALIZED_DOWNLOADS_USAGE" ]] \
        || fail "agent bundle has an empty ${localization} Downloads usage description"
done
python3 - \
    "${APP_PATH}/Contents/Info.plist" \
    "${APP_PATH}/Contents/Library/LaunchAgents/dev.nodavo.agent.plist" \
    "$MODE" "$TEAM_ID" "$MACH_SERVICE_NAME" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as source:
    app = plistlib.load(source)
with open(sys.argv[2], "rb") as source:
    launch_agent = plistlib.load(source)
mode, team_id, service = sys.argv[3:]
if app.get("NodavoAgentMachService") != service:
    raise SystemExit("app does not bind the fixed agent Mach service")
if app.get("NodavoAppleTeamIdentifier") != team_id:
    raise SystemExit("app does not bind the build Team ID")
if launch_agent.get("MachServices") != {service: mode == "release"}:
    raise SystemExit("LaunchAgent MachServices mode does not match packaging mode")
PY

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$REPOSITORY_ROOT" log -1 --format=%ct)}
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || fail "SOURCE_DATE_EPOCH must be an integer"
NORMALIZED_TIME=$(date -r "$SOURCE_DATE_EPOCH" '+%Y%m%d%H%M.%S')
find "$APP_PATH" -exec touch -h -t "$NORMALIZED_TIME" {} +

sign_path "${APP_PATH}/Contents/Resources/${SWIFT_RESOURCE_BUNDLE}"
sign_path "$HELPER_APP" "$AGENT_ENTITLEMENTS" "$AGENT_BUNDLE_ID"
sign_path "$APP_PATH" "$APP_ENTITLEMENTS" "$APP_BUNDLE_ID"
codesign --verify --strict --all-architectures --verbose=2 "$HELPER_APP"
codesign --verify --deep --strict --all-architectures --verbose=2 "$APP_PATH"

[[ $(plutil -extract CFBundleIdentifier raw "${APP_PATH}/Contents/Info.plist") == "$APP_BUNDLE_ID" ]]
[[ $(plutil -extract CFBundleIdentifier raw "${HELPER_APP}/Contents/Info.plist") == "$AGENT_BUNDLE_ID" ]]
[[ $(plutil -extract NodavoKeychainAccessGroup raw "${HELPER_APP}/Contents/Info.plist") \
    == "$KEYCHAIN_ACCESS_GROUP" ]]
[[ -f "${APP_PATH}/Contents/Resources/${SWIFT_RESOURCE_BUNDLE}/Contents/Resources/en.lproj/Localizable.strings" ]]
[[ -f "${APP_PATH}/Contents/Resources/${SWIFT_RESOURCE_BUNDLE}/Contents/Resources/ru.lproj/Localizable.strings" ]]

UI_ACTUAL_ENTITLEMENTS="${BUILD_ROOT}/ui-actual-entitlements.plist"
AGENT_ACTUAL_ENTITLEMENTS="${BUILD_ROOT}/agent-actual-entitlements.plist"
codesign -d --entitlements :- "$APP_PATH" >"$UI_ACTUAL_ENTITLEMENTS" 2>/dev/null
codesign -d --entitlements :- "$HELPER_APP" >"$AGENT_ACTUAL_ENTITLEMENTS" 2>/dev/null
plutil -lint "$UI_ACTUAL_ENTITLEMENTS" >/dev/null
plutil -lint "$AGENT_ACTUAL_ENTITLEMENTS" >/dev/null
python3 - "$UI_ACTUAL_ENTITLEMENTS" "$AGENT_ACTUAL_ENTITLEMENTS" \
    "$MODE" "$KEYCHAIN_ACCESS_GROUP" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as source:
    ui = plistlib.load(source)
with open(sys.argv[2], "rb") as source:
    agent = plistlib.load(source)
mode, keychain_group = sys.argv[3:]
if mode == "release":
    expected_ui = {
        "com.apple.application-identifier",
        "com.apple.developer.team-identifier",
    }
    expected_agent = expected_ui | {"keychain-access-groups"}
    if agent.get("keychain-access-groups") != [keychain_group]:
        raise SystemExit("signed agent does not contain exactly its Keychain access group")
else:
    expected_ui = set()
    expected_agent = set()
if set(ui) != expected_ui:
    raise SystemExit("signed UI contains a broad or missing entitlement")
if set(agent) != expected_agent:
    raise SystemExit("signed agent contains a broad or missing entitlement")
PY

if [[ "$MODE" == "release" ]]; then
    UI_REQUIREMENT="anchor apple generic and identifier \"${APP_BUNDLE_ID}\" and certificate leaf[subject.OU] = \"${TEAM_ID}\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and entitlement[\"com.apple.application-identifier\"] = \"${TEAM_ID}.${APP_BUNDLE_ID}\" and entitlement[\"com.apple.developer.team-identifier\"] = \"${TEAM_ID}\" and entitlement[\"com.apple.security.get-task-allow\"] absent"
    AGENT_REQUIREMENT="anchor apple generic and identifier \"${AGENT_BUNDLE_ID}\" and certificate leaf[subject.OU] = \"${TEAM_ID}\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and entitlement[\"com.apple.application-identifier\"] = \"${TEAM_ID}.${AGENT_BUNDLE_ID}\" and entitlement[\"com.apple.developer.team-identifier\"] = \"${TEAM_ID}\" and entitlement[\"com.apple.security.get-task-allow\"] absent"
    codesign --verify --strict --all-architectures -R="$UI_REQUIREMENT" "$APP_PATH"
    codesign --verify --strict --all-architectures -R="$AGENT_REQUIREMENT" "$HELPER_APP"

    UI_SIGNING_DETAILS=$(codesign -d --verbose=4 "$APP_PATH" 2>&1)
    AGENT_SIGNING_DETAILS=$(codesign -d --verbose=4 "$HELPER_APP" 2>&1)
    grep -F -x -q "Identifier=${APP_BUNDLE_ID}" <<<"$UI_SIGNING_DETAILS" \
        || fail "signed UI identifier is not ${APP_BUNDLE_ID}"
    grep -F -x -q "TeamIdentifier=${TEAM_ID}" <<<"$UI_SIGNING_DETAILS" \
        || fail "signed UI TeamIdentifier does not match APPLE_TEAM_ID"
    grep -E -q '^CodeDirectory .*flags=.*\(runtime\)' <<<"$UI_SIGNING_DETAILS" \
        || fail "signed UI does not enable the hardened runtime"
    grep -F -x -q "Identifier=${AGENT_BUNDLE_ID}" <<<"$AGENT_SIGNING_DETAILS" \
        || fail "signed agent identifier is not ${AGENT_BUNDLE_ID}"
    grep -F -x -q "TeamIdentifier=${TEAM_ID}" <<<"$AGENT_SIGNING_DETAILS" \
        || fail "signed agent TeamIdentifier does not match APPLE_TEAM_ID"
    grep -E -q '^CodeDirectory .*flags=.*\(runtime\)' <<<"$AGENT_SIGNING_DETAILS" \
        || fail "signed agent does not enable the hardened runtime"

    [[ $(/usr/libexec/PlistBuddy -c "Print :com.apple.application-identifier" \
        "$UI_ACTUAL_ENTITLEMENTS") == "${TEAM_ID}.${APP_BUNDLE_ID}" ]] \
        || fail "signed UI application identifier is not secured to the expected Team ID"
    [[ $(/usr/libexec/PlistBuddy -c "Print :com.apple.developer.team-identifier" \
        "$UI_ACTUAL_ENTITLEMENTS") == "$TEAM_ID" ]] \
        || fail "signed UI entitlement Team ID does not match APPLE_TEAM_ID"
    if /usr/libexec/PlistBuddy -c "Print :com.apple.security.get-task-allow" \
        "$UI_ACTUAL_ENTITLEMENTS" >/dev/null 2>&1; then
        fail "signed UI contains the forbidden get-task-allow entitlement"
    fi
    if /usr/libexec/PlistBuddy -c "Print :keychain-access-groups" \
        "$UI_ACTUAL_ENTITLEMENTS" >/dev/null 2>&1; then
        fail "signed UI must not contain the agent Keychain access group"
    fi
    [[ $(/usr/libexec/PlistBuddy -c "Print :com.apple.application-identifier" \
        "$AGENT_ACTUAL_ENTITLEMENTS") == "${TEAM_ID}.${AGENT_BUNDLE_ID}" ]] \
        || fail "signed agent application identifier is not secured to the expected Team ID"
    [[ $(/usr/libexec/PlistBuddy -c "Print :com.apple.developer.team-identifier" \
        "$AGENT_ACTUAL_ENTITLEMENTS") == "$TEAM_ID" ]] \
        || fail "signed agent entitlement Team ID does not match APPLE_TEAM_ID"
    if /usr/libexec/PlistBuddy -c "Print :com.apple.security.get-task-allow" \
        "$AGENT_ACTUAL_ENTITLEMENTS" >/dev/null 2>&1; then
        fail "signed agent contains the forbidden get-task-allow entitlement"
    fi
    APP_ARCHIVE="${BUILD_ROOT}/Nodavo-app.zip"
    ditto -c -k --keepParent "$APP_PATH" "$APP_ARCHIVE"
    notarize_archive "$APP_ARCHIVE" "app"
    xcrun stapler staple "$APP_PATH"
    xcrun stapler validate "$APP_PATH"
    spctl --assess --type execute --verbose=4 "$APP_PATH"
fi

# The validation-only updater boundary accepts only a sealed bundle tree. Seal
# after all signing/notarization mutations, then repeat the platform checks so
# the emitted app, DMG, and update archive all carry the same immutable modes.
chmod -R a-w "$APP_PATH"
python3 - "$APP_PATH" <<'PY'
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
for candidate in (root, *root.rglob("*")):
    if stat.S_IMODE(os.lstat(candidate).st_mode) & 0o222:
        raise SystemExit(f"sealed application contains a writable node: {candidate}")
PY
codesign --verify --deep --strict --all-architectures --verbose=2 "$APP_PATH"
if [[ "$MODE" == "release" ]]; then
    xcrun stapler validate "$APP_PATH"
    spctl --assess --type execute --verbose=4 "$APP_PATH"
fi

if [[ "$MODE" == "release" ]]; then
    UPDATE_ARCHIVE_NAME="Nodavo-${VERSION}-${BUILD_NUMBER}-macos-universal.zip"
    UPDATE_METADATA_NAME="Nodavo-${VERSION}-${BUILD_NUMBER}-macos-universal.update.json"
else
    UPDATE_ARCHIVE_NAME="Nodavo-${VERSION}-${BUILD_NUMBER}-macos-universal-development-NOT-NOTARIZED.zip"
    UPDATE_METADATA_NAME="Nodavo-${VERSION}-${BUILD_NUMBER}-macos-universal-development-NOT-NOTARIZED.update.json"
fi
UPDATE_ARCHIVE_PATH="${BUILD_ROOT}/${UPDATE_ARCHIVE_NAME}"
UPDATE_METADATA_PATH="${BUILD_ROOT}/${UPDATE_METADATA_NAME}"
UPDATE_VERIFY_ROOT="${BUILD_ROOT}/update-archive-verify"
rm -rf "$UPDATE_ARCHIVE_PATH" "$UPDATE_METADATA_PATH" "$UPDATE_VERIFY_ROOT"
ditto -c -k --keepParent "$APP_PATH" "$UPDATE_ARCHIVE_PATH"
mkdir -p "$UPDATE_VERIFY_ROOT"
ditto -x -k "$UPDATE_ARCHIVE_PATH" "$UPDATE_VERIFY_ROOT"
[[ -d "${UPDATE_VERIFY_ROOT}/Nodavo.app" ]] \
    || fail "update archive does not contain the exact Nodavo.app root"
[[ $(find "$UPDATE_VERIFY_ROOT" -mindepth 1 -maxdepth 1 -print \
    | wc -l | tr -d '[:space:]') == 1 ]] \
    || fail "update archive contains an unexpected top-level entry"
python3 - "${UPDATE_VERIFY_ROOT}/Nodavo.app" <<'PY'
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
for candidate in (root, *root.rglob("*")):
    if stat.S_IMODE(os.lstat(candidate).st_mode) & 0o222:
        raise SystemExit(f"update archive contains a writable bundle node: {candidate}")
PY
codesign --verify --deep --strict --all-architectures --verbose=2 \
    "${UPDATE_VERIFY_ROOT}/Nodavo.app"
verify_universal "${UPDATE_VERIFY_ROOT}/Nodavo.app/Contents/MacOS/Nodavo"
verify_universal \
    "${UPDATE_VERIFY_ROOT}/Nodavo.app/Contents/Library/Helpers/NodavoAgent.app/Contents/MacOS/nodavo-agent"
if [[ "$MODE" == "release" ]]; then
    xcrun stapler validate "${UPDATE_VERIFY_ROOT}/Nodavo.app"
    spctl --assess --type execute --verbose=4 "${UPDATE_VERIFY_ROOT}/Nodavo.app"
fi

python3 - "$UPDATE_ARCHIVE_PATH" "$UPDATE_METADATA_PATH" "$UPDATE_ARCHIVE_NAME" \
    "$VERSION" "$BUILD_NUMBER" "$MODE" "$APP_BUNDLE_ID" "$AGENT_BUNDLE_ID" <<'PY'
import hashlib
import json
import sys

archive_path, output_path, archive_name, version, build, mode, app_id, agent_id = sys.argv[1:]
digest = hashlib.sha256()
size = 0
with open(archive_path, "rb") as source:
    while chunk := source.read(1024 * 1024):
        size += len(chunk)
        digest.update(chunk)
if size <= 0:
    raise SystemExit("update archive is empty")
metadata = {
    "schema": 1,
    "product": "nodavo",
    "platform": "macos",
    "architectures": ["aarch64", "x86_64"],
    "version": version,
    "build": int(build),
    "mode": mode,
    "artifact": archive_name,
    "artifact_size": size,
    "artifact_sha256": digest.hexdigest(),
    "bundle_identifier": app_id,
    "agent_bundle_identifier": agent_id,
}
with open(output_path, "x", encoding="utf-8", newline="\n") as destination:
    json.dump(metadata, destination, sort_keys=True, separators=(",", ":"))
    destination.write("\n")
PY

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
rm -rf \
    "$OUTPUT_APP" \
    "${OUTPUT_DIRECTORY}/${DMG_NAME}" \
    "${OUTPUT_DIRECTORY}/${UPDATE_ARCHIVE_NAME}" \
    "${OUTPUT_DIRECTORY}/${UPDATE_METADATA_NAME}"
ditto "$APP_PATH" "$OUTPUT_APP"
ditto "$DMG_PATH" "${OUTPUT_DIRECTORY}/${DMG_NAME}"
ditto "$UPDATE_ARCHIVE_PATH" "${OUTPUT_DIRECTORY}/${UPDATE_ARCHIVE_NAME}"
ditto "$UPDATE_METADATA_PATH" "${OUTPUT_DIRECTORY}/${UPDATE_METADATA_NAME}"

echo "App: ${OUTPUT_APP}"
echo "DMG: ${OUTPUT_DIRECTORY}/${DMG_NAME}"
echo "Update archive: ${OUTPUT_DIRECTORY}/${UPDATE_ARCHIVE_NAME}"
echo "Update metadata: ${OUTPUT_DIRECTORY}/${UPDATE_METADATA_NAME}"
if [[ "$MODE" == "development" ]]; then
    echo "Status: DEVELOPMENT ONLY — ad-hoc signed, not notarized, not for distribution."
else
    echo "Status: Developer ID signed, notarization accepted, tickets stapled and validated."
fi
