#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGINAL_ARP="${ORIGINAL_ARP:-/usr/sbin/arp}"
RUST_ARP="${RUST_ARP:-/workspace/target/release/arp}"

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

compare_output() {
    local orig_file=$1
    local rust_file=$2
    local test_name=$3

    if diff -u "$orig_file" "$rust_file" >/tmp/diff_output 2>&1; then
        return 0
    else
        echo -e "\n${RED}Output mismatch in $test_name:${NC}"
        cat /tmp/diff_output
        return 1
    fi
}

cleanup() {
    ip link delete dummy0 2>/dev/null || true
    ip link delete veth0 2>/dev/null || true
    ip link delete veth1 2>/dev/null || true
    ip link delete veth2 2>/dev/null || true
    ip link delete veth3 2>/dev/null || true
    ip netns delete arp_test 2>/dev/null || true

    sed -i '/test-short-name/d' /etc/hosts 2>/dev/null || true
    sed -i '/test-very-long-hostname-that-exceeds-twentythree-characters/d' /etc/hosts 2>/dev/null || true

    # Restore DNS configuration
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
}

setup_test_arp_entries() {
    # Configure DNS to prevent external network queries during reverse lookup
    # This prevents the race condition where DNS triggers gateway ARP
    echo "nameserver 127.0.0.1" > /etc/resolv.conf

    ip link add veth0 type veth peer name veth1
    ip addr add 192.168.100.1/24 dev veth0
    ip addr add 192.168.100.2/24 dev veth1
    ip link set veth0 up
    ip link set veth1 up

    ip link add veth2 type veth peer name veth3
    ip addr add 192.168.101.1/24 dev veth2
    ip addr add 192.168.101.2/24 dev veth3
    ip link set veth2 up
    ip link set veth3 up

    # Generate dynamic ARP entries by pinging
    # This creates complete (ATF_COM) entries
    ping -c 1 -W 1 192.168.100.2 >/dev/null 2>&1 || true
    ping -c 1 -W 1 192.168.101.2 >/dev/null 2>&1 || true

    # Add a static permanent entry to test ATF_PERM flag
    arp -s 192.168.100.10 aa:bb:cc:dd:ee:01 -i veth0 >/dev/null 2>&1 || true
    arp -s 192.168.101.10 aa:bb:cc:dd:ee:02 -i veth2 >/dev/null 2>&1 || true

    # Add temporary /etc/hosts entries for reverse lookup testing
    echo "192.168.100.50 test-short-name" >> /etc/hosts
    echo "192.168.100.51 test-very-long-hostname-that-exceeds-twentythree-characters.example.com" >> /etc/hosts
    arp -s 192.168.100.50 bb:cc:dd:ee:ff:01 -i veth0 >/dev/null 2>&1 || true
    arp -s 192.168.100.51 bb:cc:dd:ee:ff:02 -i veth0 >/dev/null 2>&1 || true

    # Wait for ARP entries to stabilize
    sleep 0.5
}

test_default_display() {
    echo -n "test arp::test_default_display ... "
    cleanup
    setup_test_arp_entries

    set +e
    $ORIGINAL_ARP >/tmp/original_default 2>&1
    ORIG_EXIT=$?

    $RUST_ARP >/tmp/rust_default 2>&1
    RUST_EXIT=$?
    set -e

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && compare_output /tmp/original_default /tmp/rust_default "test_default_display"; then
        pass
    else
        fail "arp::test_default_display"
    fi

    cleanup
}

test_numeric_flag() {
    echo -n "test arp::test_numeric_flag ... "
    cleanup
    setup_test_arp_entries

    set +e
    $ORIGINAL_ARP -n >/tmp/original_numeric 2>&1
    ORIG_EXIT=$?

    $RUST_ARP -n >/tmp/rust_numeric 2>&1
    RUST_EXIT=$?
    set -e

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && compare_output /tmp/original_numeric /tmp/rust_numeric "$(basename ${BASH_SOURCE[0]} .sh)"; then
        pass
    else
        fail "arp::test_numeric_flag"
    fi

    cleanup
}

test_bsd_style_flag() {
    echo -n "test arp::test_bsd_style_flag ... "
    cleanup
    setup_test_arp_entries

    set +e
    $ORIGINAL_ARP -a >/tmp/original_bsd 2>&1
    ORIG_EXIT=$?

    $RUST_ARP -a >/tmp/rust_bsd 2>&1
    RUST_EXIT=$?
    set -e

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && compare_output /tmp/original_bsd /tmp/rust_bsd "$(basename ${BASH_SOURCE[0]} .sh)"; then
        pass
    else
        fail "arp::test_bsd_style_flag"
    fi

    cleanup
}

test_invalid_hostname() {
    echo -n "test arp::test_invalid_hostname ... "
    cleanup

    set +e
    $ORIGINAL_ARP invalid.hostname.that.does.not.exist.12345 >/tmp/original_invalid 2>&1
    ORIG_EXIT=$?

    $RUST_ARP invalid.hostname.that.does.not.exist.12345 >/tmp/rust_invalid 2>&1
    RUST_EXIT=$?
    set -e

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && [ "$ORIG_EXIT" -ne 0 ] && compare_output /tmp/original_invalid /tmp/rust_invalid "test_invalid_hostname"; then
        pass
    else
        fail "arp::test_invalid_hostname"
    fi
}

test_device_filter() {
    echo -n "test arp::test_device_filter ... "
    cleanup
    setup_test_arp_entries

    set +e
    $ORIGINAL_ARP -i lo >/tmp/original_device 2>&1
    ORIG_EXIT=$?

    $RUST_ARP -i lo >/tmp/rust_device 2>&1
    RUST_EXIT=$?
    set -e

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && compare_output /tmp/original_device /tmp/rust_device "$(basename ${BASH_SOURCE[0]} .sh)"; then
        pass
    else
        fail "arp::test_device_filter"
    fi
    cleanup
}

test_hwtype_filter() {
    echo -n "test arp::test_hwtype_filter ... "
    cleanup
    setup_test_arp_entries

    set +e
    $ORIGINAL_ARP -H ether >/tmp/original_hwtype 2>&1
    ORIG_EXIT=$?

    $RUST_ARP -H ether >/tmp/rust_hwtype 2>&1
    RUST_EXIT=$?
    set -e

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && compare_output /tmp/original_hwtype /tmp/rust_hwtype "$(basename ${BASH_SOURCE[0]} .sh)"; then
        pass
    else
        fail "arp::test_hwtype_filter"
    fi

    cleanup
}

test_invalid_hwtype() {
    echo -n "test arp::test_invalid_hwtype ... "
    cleanup
    setup_test_arp_entries

    set +e
    $ORIGINAL_ARP -H invalid_hwtype >/tmp/original_invalid_hw 2>&1
    ORIG_EXIT=$?

    $RUST_ARP -H invalid_hwtype >/tmp/rust_invalid_hw 2>&1
    RUST_EXIT=$?
    set -e

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && [ "$ORIG_EXIT" -ne 0 ] && compare_output /tmp/original_invalid_hw /tmp/rust_invalid_hw "test_invalid_hwtype"; then
        pass
    else
        fail "arp::test_invalid_hwtype"
    fi

    cleanup
}

test_verbose_flag() {
    echo -n "test arp::test_verbose_flag ... "
    cleanup
    setup_test_arp_entries

    set +e
    $ORIGINAL_ARP -v >/tmp/original_verbose 2>&1
    ORIG_EXIT=$?

    $RUST_ARP -v >/tmp/rust_verbose 2>&1
    RUST_EXIT=$?
    set -e

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && compare_output /tmp/original_verbose /tmp/rust_verbose "$(basename ${BASH_SOURCE[0]} .sh)"; then
        pass
    else
        fail "arp::test_verbose_flag"
    fi

    cleanup
}

test_linux_style_flag() {
    echo -n "test arp::test_linux_style_flag ... "
    cleanup
    setup_test_arp_entries

    set +e
    $ORIGINAL_ARP -e >/tmp/original_linux 2>&1
    ORIG_EXIT=$?

    $RUST_ARP -e >/tmp/rust_linux 2>&1
    RUST_EXIT=$?
    set -e

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && compare_output /tmp/original_linux /tmp/rust_linux "$(basename ${BASH_SOURCE[0]} .sh)"; then
        pass
    else
        fail "arp::test_linux_style_flag"
    fi

    cleanup
}

test_combined_flags() {
    echo -n "test arp::test_combined_flags ... "
    cleanup
    setup_test_arp_entries

    set +e
    $ORIGINAL_ARP -n -v >/tmp/original_combined 2>&1
    ORIG_EXIT=$?

    $RUST_ARP -n -v >/tmp/rust_combined 2>&1
    RUST_EXIT=$?
    set -e

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && compare_output /tmp/original_combined /tmp/rust_combined "$(basename ${BASH_SOURCE[0]} .sh)"; then
        pass
    else
        fail "arp::test_combined_flags"
    fi

    cleanup
}

test_bsd_with_device() {
    echo -n "test arp::test_bsd_with_device ... "
    cleanup
    setup_test_arp_entries

    set +e
    $ORIGINAL_ARP -a -i lo >/tmp/original_bsd_dev 2>&1
    ORIG_EXIT=$?

    $RUST_ARP -a -i lo >/tmp/rust_bsd_dev 2>&1
    RUST_EXIT=$?
    set -e

    if [ "$ORIG_EXIT" -eq "$RUST_EXIT" ] && compare_output /tmp/original_bsd_dev /tmp/rust_bsd_dev "$(basename ${BASH_SOURCE[0]} .sh)"; then
        pass
    else
        fail "arp::test_bsd_with_device"
    fi

    cleanup
}

echo "running arp tests"
test_default_display
test_numeric_flag
test_bsd_style_flag
test_verbose_flag
test_linux_style_flag
test_combined_flags
test_invalid_hostname
test_device_filter
test_hwtype_filter
test_invalid_hwtype
test_bsd_with_device

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
