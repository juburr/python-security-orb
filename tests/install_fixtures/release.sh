# shellcheck shell=bash disable=SC2034 # a fragment: the install contract it is spliced into reads these
# Release binaries downloaded from GitHub (uv).
# On top of the shared contract, the download_base_url mirror: it replaces
# https://github.com in the release URL, and what it serves is verified like
# any download.
FIXTURE_ORIGIN="https://github.com"

fixture_checks() {
    local mirror="https://mirror.example/artifactory/github" mirror_url listed_file tampered_file binary
    begin "${TOOL_NAME}: download_base_url"
    # The mirror serves exactly the files served for the origin (an archive
    # made again would differ in its timestamps).
    listed_file=$(served_file "${LISTED}" "${DEFAULT_ARCH}")
    tampered_file=$(served_file "${TAMPERED}" "${DEFAULT_ARCH}")
    UV_DOWNLOAD_BASE_URL=${mirror}
    cp "${listed_file}" "$(served_file "${LISTED}" "${DEFAULT_ARCH}")"
    cp "${tampered_file}" "$(served_file "${TAMPERED}" "${DEFAULT_ARCH}")"
    mirror_url=$(url "${LISTED}" "${DEFAULT_ARCH}")
    unset UV_DOWNLOAD_BASE_URL
    OUTPUT="mirror URL: ${mirror_url}"
    check "the mirror URL is the release URL with the mirror in place of ${FIXTURE_ORIGIN}" \
        test "${mirror_url#"${mirror}"}" = "$(url "${LISTED}" "${DEFAULT_ARCH}" | sed "s|^${FIXTURE_ORIGIN}||")"
    new_case
    run_install "PARAM_DOWNLOAD_BASE_URL=${mirror}/"
    check "installs from the mirror" installed
    check "downloads from the mirror alone" downloaded "${mirror_url}"
    check "once" download_count 1
    check "says which mirror it uses, and what it replaces" said "download mirror:  ${mirror} (in place of ${FIXTURE_ORIGIN})"
    new_case
    # shellcheck disable=SC2016 # expanded by install.sh
    run_install 'PARAM_DOWNLOAD_BASE_URL=${ORB_TEST_MIRROR}' "ORB_TEST_MIRROR=${mirror}"
    check "expands environment variables in it" installed
    for mode in strict known_versions; do
        new_case
        run_install "PARAM_DOWNLOAD_BASE_URL=${mirror}" "PARAM_VERSION=${TAMPERED}" "PARAM_VERIFY_CHECKSUMS=${mode}"
        check "${mode}: refuses a tampered asset from the mirror" failed
        check "${mode}: reporting the mismatch" said "Checksum verification failed."
        check "${mode}: and installs nothing" not_installed
    done
    for value in "http://mirror.example" "mirror.example" "https://mirror example"; do
        new_case
        run_install "PARAM_DOWNLOAD_BASE_URL=${value}"
        check "refuses '${value}'" failed
        check "saying it must be an https URL" said "download_base_url must be an https:// URL"
        check "before downloading anything" no_downloads
    done
    new_case
    run_install "PARAM_DOWNLOAD_BASE_URL=http://user:s3cret@mirror.example/github"
    check "refuses credentials in the URL" failed
    check "saying they would show in the log" said "download_base_url must not hold credentials"
    check "without printing them" not_said "s3cret"
    check "before downloading anything" no_downloads
    for value in "https://mirror.example/github?access_token=s3cret" "https://mirror.example/github#s3cret"; do
        new_case
        run_install "PARAM_DOWNLOAD_BASE_URL=${value}"
        check "refuses a query or fragment ('${value//s3cret/...}')" failed
        check "saying it could hold a token" said "download_base_url must not have a query or fragment"
        check "without printing it" not_said "s3cret"
        check "before downloading anything" no_downloads
    done
    if declare -F fixture_tool_checks > /dev/null; then
        fixture_tool_checks
    fi
}
