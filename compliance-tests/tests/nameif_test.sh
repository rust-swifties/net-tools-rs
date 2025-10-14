#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGINAL_NAMEIF="${ORIGINAL_NAMEIF:-/sbin/nameif}"
RUST_NAMEIF="${RUST_NAMEIF:-/workspace/target/release/nameif}"

FAILED=0
PASSED=0
FAILED_TESTS=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

fail() {
    echo -e "${RED}FAILED${NC}"
    FAILED=$((FAILED + 1))
    FAILED_TESTS+=("$1")
}

pass() {
    echo -e "${GREEN}ok${NC}"
    PASSED=$((PASSED + 1))
}

cleanup() {
    ip link delete dummy0 2>/dev/null || true
    ip link delete testif0 2>/dev/null || true
    ip link delete testif1 2>/dev/null || true
    rm -f /tmp/test_mactab
}

setup_interface() {
    local name=$1
    local mac=$2
    ip link add "$name" type dummy
    ip link set "$name" address "$mac"
}

test_basic_rename() {
    echo -n "test nameif::test_basic_rename ... "
    cleanup

    setup_interface dummy0 "00:11:22:33:44:55"

    set +e
    $ORIGINAL_NAMEIF testif0 00:11:22:33:44:55 2>/tmp/original_stderr
    ORIG_EXIT=$?
    set -e
    ORIG_EXISTS=$(ip link show testif0 2>/dev/null && echo "yes" || echo "no")

    if [ "$ORIG_EXISTS" = "yes" ]; then
        ip link set testif0 name dummy0 2>/dev/null || true
    fi

    set +e
    $RUST_NAMEIF testif0 00:11:22:33:44:55 2>/tmp/rust_stderr
    RUST_EXIT=$?
    set -e
    RUST_EXISTS=$(ip link show testif0 2>/dev/null && echo "yes" || echo "no")

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && [ "$ORIG_EXISTS" = "$RUST_EXISTS" ]; then
        pass
    else
        fail "nameif::test_basic_rename"
    fi

    cleanup
}

test_config_file() {
    echo -n "test nameif::test_config_file ... "
    cleanup

    setup_interface dummy0 "aa:bb:cc:dd:ee:ff"

    cat > /tmp/test_mactab <<EOF
testif1 aa:bb:cc:dd:ee:ff
EOF

    set +e
    $ORIGINAL_NAMEIF -c /tmp/test_mactab 2>/tmp/original_stderr
    ORIG_EXIT=$?
    set -e
    ORIG_EXISTS=$(ip link show testif1 2>/dev/null && echo "yes" || echo "no")

    if [ "$ORIG_EXISTS" = "yes" ]; then
        ip link set testif1 name dummy0 2>/dev/null || true
    fi

    set +e
    $RUST_NAMEIF -c /tmp/test_mactab 2>/tmp/rust_stderr
    RUST_EXIT=$?
    set -e
    RUST_EXISTS=$(ip link show testif1 2>/dev/null && echo "yes" || echo "no")

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && [ "$ORIG_EXISTS" = "$RUST_EXISTS" ]; then
        pass
    else
        fail "nameif::test_config_file"
    fi

    cleanup
}

test_missing_interface() {
    echo -n "test nameif::test_missing_interface ... "
    cleanup

    set +e
    $ORIGINAL_NAMEIF testnonexist 00:00:00:00:00:00 2>/tmp/original_stderr
    ORIG_EXIT=$?

    $RUST_NAMEIF testnonexist 00:00:00:00:00:00 2>/tmp/rust_stderr
    RUST_EXIT=$?
    set -e

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ]; then
        pass
    else
        fail "nameif::test_missing_interface"
    fi

    cleanup
}

test_invalid_mac() {
    echo -n "test nameif::test_invalid_mac ... "
    cleanup

    set +e
    $ORIGINAL_NAMEIF testif0 "invalid:mac" 2>/tmp/original_stderr
    ORIG_EXIT=$?

    $RUST_NAMEIF testif0 "invalid:mac" 2>/tmp/rust_stderr
    RUST_EXIT=$?
    set -e

    # Both should fail
    if [ "$ORIG_EXIT" -ne 0 ] && [ "$RUST_EXIT" -ne 0 ]; then
        pass
    else
        fail "nameif::test_invalid_mac"
    fi

    cleanup
}

echo "running nameif tests"
test_basic_rename
test_config_file
test_missing_interface
test_invalid_mac

echo
if [ $FAILED -gt 0 ]; then
    echo "failures:"
    for test in "${FAILED_TESTS[@]}"; do
        echo "    $test"
    done
    echo
fi

if [ $FAILED -eq 0 ]; then
    echo -e "test result: ${GREEN}ok${NC}. $PASSED passed; $FAILED failed"
    exit 0
else
    echo -e "test result: ${RED}FAILED${NC}. $PASSED passed; $FAILED failed"
    exit 1
fi
