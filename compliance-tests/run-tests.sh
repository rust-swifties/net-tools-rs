#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$SCRIPT_DIR/tests"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

TOTAL_FAILED=0
TOTAL_PASSED=0

echo "========================================"
echo "Running net-tools compliance tests"
echo "========================================"
echo

for test_script in "$TESTS_DIR"/*_test.sh; do
    if [ -f "$test_script" ]; then
        if ! bash "$test_script"; then
            TOTAL_FAILED=$((TOTAL_FAILED + 1))
        fi
        echo
    fi
done

if [ $TOTAL_FAILED -gt 0 ]; then
    exit 1
fi

exit 0
