#!/usr/bin/env bash
#
# Validates the reports in /tmp/python-security-reports (or the directories
# given) with tests/validate_reports.py: SARIF against the OASIS SARIF 2.1.0
# schema, pinned by SHA-256, JUnit's counts, and run records against
# schemas/run-record.v1.json. The CI jobs run it after the orb's commands,
# with uv and the Python the orb installed.
#
# Run from a checkout:
#   bash tests/validate_reports.sh [DIR...]

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCHEMA=$(mktemp)
trap 'rm -f "${SCHEMA}"' EXIT
curl --fail --silent --show-error --location --proto '=https' --output "${SCHEMA}" \
    https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
echo "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e  ${SCHEMA}" | sha256sum -c -
if [[ $# -eq 0 ]]; then
    set -- /tmp/python-security-reports
fi
uv run --no-config --no-project --python "${PYTHON_SECURITY_ORB_PYTHON:-python3}" --with jsonschema==4.26.0 \
    python "${ROOT}/tests/validate_reports.py" --sarif-schema "${SCHEMA}" "$@"
