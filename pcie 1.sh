#!/bin/bash

# Simple PCIe Adapter Validation Script

# Fixed version without complex formatting

SCRIPT_VERSION=“1.0-simple”
LOG_DIR=”$HOME/pcie_validation”
VALIDATION_LOG=”$LOG_DIR/validation_$(date +%Y%m%d_%H%M%S).log”
ERROR_LOG=”$LOG_DIR/errors_$(date +%Y%m%d_%H%M%S).log”
REPORT_FILE=”$LOG_DIR/validation_report_$(date +%Y%m%d_%H%M%S).txt”

# Test configuration

STRESS_DURATION=60
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Initialize logging

init_logging() {
mkdir -p “$LOG_DIR”
touch “$VALIDATION_LOG” “$ERROR_LOG” “$REPORT_FILE”

```
echo "[INFO] PCIe Adapter Validation Script v$SCRIPT_VERSION"
echo "[INFO] Started: $(date)"
echo "[INFO] System: $(hostname) - $(uname -r)"
```

}

# Logging functions

log_info() {
local msg=”[INFO] $(date ‘+%H:%M:%S’) $1”
echo “$msg”
echo “$msg” >> “$VALIDATION_LOG”
}

log_success() {
local msg=”[PASS] $(date ‘+%H:%M:%S’) $1”
echo “$msg”
echo “$msg” >> “$VALIDATION_LOG”
}

log_warning() {
local msg=”[WARN] $(date ‘+%H:%M:%S’) $1”
echo “$msg”
echo “$msg” >> “$VALIDATION_LOG”
}

log_error() {
local msg=”[FAIL] $(date ‘+%H:%M:%S’) $1”
echo “$msg”
echo “$msg” >> “$VALIDATION_LOG”
echo “$msg” >> “$ERROR_LOG”
}

log_test_start() {
echo “”
echo “=== $1 ===”
log_info “Starting test: $1”
((TOTAL_TESTS++))
}

log_test_result() {
local test_name=”$1”
local result=”$2”
local details=”$3”

```
if [ "$result" = "PASS" ]; then
    log_success "$test_name: PASSED $details"
    ((PASSED_TESTS++))
else
    log_error "$test_name: FAILED $details"
    ((FAILED_TESTS++))
fi
```

}

# Get PCIe device information

get_pcie_devices() {
log_info “Scanning for PCIe devices…”

```
lspci -vvv > /tmp/lspci_full.txt 2>/dev/null
lspci -nn > /tmp/lspci_basic.txt 2>/dev/null

if [ ! -s /tmp/lspci_basic.txt ]; then
    log_error "Cannot access PCIe device information"
    return 1
fi

log_info "Found $(wc -l < /tmp/lspci_basic.txt) PCIe devices"
return 0
```

}

# Test 1: Basic Device Detection

test_device_detection() {
log_test_start “Device Detection and Enumeration”

```
local errors=0

if ! lspci > /dev/null 2>&1; then
    log_test_result "Device Detection" "FAIL" "lspci command failed"
    return 1
fi

# Check for devices with invalid vendor/device IDs
while read -r device; do
    local pci_id=$(echo "$device" | awk '{print $1}')
    local vendor_device=$(echo "$device" | grep -o '\[....:....\]' | head -1)
    
    if [ -z "$vendor_device" ] || [ "$vendor_device" = "[ffff:ffff]" ]; then
        log_error "Invalid vendor/device ID for $pci_id"
        ((errors++))
    fi
done < /tmp/lspci_basic.txt

if [ $errors -eq 0 ]; then
    log_test_result "Device Detection" "PASS" "All devices properly detected"
    return 0
else
    log_test_result "Device Detection" "FAIL" "$errors devices with invalid IDs"
    return 1
fi
```

}

# Test 2: Configuration Space Access

test_config_space() {
log_test_start “Configuration Space Access Test”

```
local errors=0
local devices_tested=0

while read -r device; do
    local pci_id=$(echo "$device" | awk '{print $1}')
    ((devices_tested++))
    
    if ! lspci -s "$pci_id" -xxx > /dev/null 2>&1; then
        log_error "Failed to read config space for $pci_id"
        ((errors++))
        continue
    fi
    
    # Check for config space corruption
    local config_first_line=$(lspci -s "$pci_id" -xxx | grep "^00:" | head -1)
    if echo "$config_first_line" | grep -q "ff ff ff ff"; then
        log_error "Config space corruption detected for $pci_id"
        ((errors++))
    fi
    
done < /tmp/lspci_basic.txt

if [ $errors -eq 0 ]; then
    log_test_result "Configuration Space" "PASS" "All $devices_tested devices accessible"
    return 0
else
    log_test_result "Configuration Space" "FAIL" "$errors/$devices_tested devices failed"
    return 1
fi
```

}

# Test 3: Link Status Analysis

test_link_status() {
log_test_start “PCIe Link Status Analysis”

```
local errors=0
local links_found=0

# Look for link status in lspci output
if grep -q "LnkSta:" /tmp/lspci_full.txt; then
    while IFS= read -r line; do
        if echo "$line" | grep -q "LnkSta:"; then
            ((links_found++))
            log_info "Link Status: $line"
            
            if echo "$line" | grep -q "Speed Unknown"; then
                log_error "Unknown link speed detected"
                ((errors++))
            fi
        fi
    done < /tmp/lspci_full.txt
else
    log_warning "No PCIe link status information available"
fi

if [ $errors -eq 0 ]; then
    log_test_result "Link Status" "PASS" "$links_found links analyzed"
    return 0
else
    log_test_result "Link Status" "FAIL" "$errors link issues"
    return 1
fi
```

}

# Test 4: Error Detection

test_error_detection() {
log_test_start “PCIe Error Detection”

```
local errors=0

# Check for AER information
if grep -q "Advanced Error Reporting" /tmp/lspci_full.txt; then
    log_info "AER capability found on some devices"
else
    log_warning "No AER capability detected"
fi

# Check dmesg for PCIe errors if available
if command -v dmesg >/dev/null 2>&1; then
    local pcie_errors=$(dmesg 2>/dev/null | grep -i "pcie.*error\|aer.*error\|pci.*error" | wc -l)
    if [ $pcie_errors -gt 0 ]; then
        log_warning "Found $pcie_errors PCIe error messages in system log"
        dmesg 2>/dev/null | grep -i "pcie.*error\|aer.*error\|pci.*error" | tail -5 >> "$ERROR_LOG"
    else
        log_info "No PCIe errors found in system log"
    fi
fi

log_test_result "Error Detection" "PASS" "Error detection completed"
return 0
```

}

# Test 5: Stress Test

test_stress() {
log_test_start “PCIe Stress Test”

```
local errors=0
local iterations=0

log_info "Running ${STRESS_DURATION}s stress test..."

local end_time=$(($(date +%s) + STRESS_DURATION))

while [ $(date +%s) -lt $end_time ]; do
    if ! lspci -vvv > /dev/null 2>&1; then
        log_error "lspci failed during stress test"
        ((errors++))
    fi
    
    ((iterations++))
    
    if [ $((iterations % 100)) -eq 0 ]; then
        local elapsed=$(($(date +%s) - (end_time - STRESS_DURATION)))
        log_info "Stress test progress: ${elapsed}s/${STRESS_DURATION}s"
    fi
    
    sleep 0.1
done

log_info "Completed $iterations stress test iterations"

if [ $errors -eq 0 ]; then
    log_test_result "Stress Test" "PASS" "$iterations iterations without errors"
    return 0
else
    log_test_result "Stress Test" "FAIL" "$errors errors detected"
    return 1
fi
```

}

# Generate report

generate_report() {
log_info “Generating validation report…”

```
{
    echo "PCIe Adapter Validation Report"
    echo "=============================="
    echo "Generated: $(date)"
    echo "System: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "Script Version: $SCRIPT_VERSION"
    echo ""
    
    echo "VALIDATION SUMMARY"
    echo "=================="
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $((TOTAL_TESTS - PASSED_TESTS))"
    echo ""
    
    if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
        echo "OVERALL RESULT: PASS - Basic validation successful"
        echo "STATUS: Adapter appears functional"
    else
        echo "OVERALL RESULT: FAIL - Issues detected"
        echo "STATUS: Adapter may be faulty"
    fi
    
    echo ""
    echo "SYSTEM INFORMATION"
    echo "=================="
    echo "PCIe Devices Found: $(wc -l < /tmp/lspci_basic.txt)"
    echo ""
    lspci
    
    if [ -s "$ERROR_LOG" ]; then
        echo ""
        echo "ERRORS DETECTED"
        echo "==============="
        cat "$ERROR_LOG"
    fi
    
} | tee "$REPORT_FILE"

echo ""
log_info "Report saved to: $REPORT_FILE"
```

}

# Main function

main() {
echo “PCIe Adapter Validation Script”
echo “==============================”

```
init_logging

# Get device information
get_pcie_devices || {
    log_error "Failed to enumerate PCIe devices"
    exit 1
}

# Run tests
test_device_detection
test_config_space
test_link_status
test_error_detection
test_stress

# Generate report
generate_report

# Final result
if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo ""
    echo "VALIDATION PASSED - Adapter appears functional"
    exit 0
else
    echo ""
    echo "VALIDATION FAILED - Issues detected"
    exit 1
fi
```

}

# Run main function

main “$@”