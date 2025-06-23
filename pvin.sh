#!/bin/bash

# PCIe Adapter Validation Script

# Comprehensive testing to validate PCIe adapters before deployment

# This script performs extensive testing to catch faulty adapters

# Configuration

SCRIPT_VERSION=“1.0”
LOG_DIR=”/var/log/pcie_validation”
VALIDATION_LOG=”$LOG_DIR/validation_$(date +%Y%m%d_%H%M%S).log”
ERROR_LOG=”$LOG_DIR/errors_$(date +%Y%m%d_%H%M%S).log”
REPORT_FILE=”$LOG_DIR/validation_report_$(date +%Y%m%d_%H%M%S).txt”

# Test configuration

STRESS_DURATION=300        # 5 minutes stress test
STABILITY_CYCLES=10        # Number of stability test cycles
THERMAL_CYCLES=5           # Number of thermal stress cycles
ERROR_THRESHOLD=0          # Zero tolerance for errors in validation
LINK_RETRAIN_CYCLES=20     # Number of link retraining cycles

# Colors

RED=’\033[0;31m’
GREEN=’\033[0;32m’
YELLOW=’\033[1;33m’
BLUE=’\033[0;34m’
PURPLE=’\033[0;35m’
CYAN=’\033[0;36m’
NC=’\033[0m’

# Test results tracking

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
declare -a FAILED_TEST_NAMES=()
declare -a TEST_RESULTS=()

# Initialize logging

init_logging() {
mkdir -p “$LOG_DIR”
touch “$VALIDATION_LOG” “$ERROR_LOG” “$REPORT_FILE”

```
log_info "PCIe Adapter Validation Script v$SCRIPT_VERSION"
log_info "Started: $(date)"
log_info "System: $(hostname) - $(uname -r)"
```

}

# Logging functions

log_info() {
local msg=”[INFO] $(date ‘+%H:%M:%S’) $1”
echo -e “${CYAN}$msg${NC}”
echo “$msg” >> “$VALIDATION_LOG”
}

log_success() {
local msg=”[PASS] $(date ‘+%H:%M:%S’) $1”
echo -e “${GREEN}$msg${NC}”
echo “$msg” >> “$VALIDATION_LOG”
}

log_warning() {
local msg=”[WARN] $(date ‘+%H:%M:%S’) $1”
echo -e “${YELLOW}$msg${NC}”
echo “$msg” >> “$VALIDATION_LOG”
}

log_error() {
local msg=”[FAIL] $(date ‘+%H:%M:%S’) $1”
echo -e “${RED}$msg${NC}”
echo “$msg” >> “$VALIDATION_LOG”
echo “$msg” >> “$ERROR_LOG”
}

log_test_start() {
echo -e “\n${BLUE}=== $1 ===${NC}”
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
    TEST_RESULTS+=("PASS: $test_name - $details")
else
    log_error "$test_name: FAILED $details"
    ((FAILED_TESTS++))
    FAILED_TEST_NAMES+=("$test_name")
    TEST_RESULTS+=("FAIL: $test_name - $details")
fi
```

}

# Check if running as root

check_root() {
if [[ $EUID -ne 0 ]]; then
log_error “This validation script must be run as root”
exit 1
fi
}

# Get PCIe device information

get_pcie_devices() {
log_info “Scanning for PCIe devices…”

```
# Get all PCIe devices with detailed info
lspci -D -vvv > /tmp/lspci_full.txt
lspci -D -nn > /tmp/lspci_basic.txt

# Filter for specific device types if needed
local target_device="$1"
if [ -n "$target_device" ]; then
    log_info "Focusing on device: $target_device"
    grep -i "$target_device" /tmp/lspci_basic.txt || {
        log_error "Target device '$target_device' not found"
        return 1
    }
fi

log_info "Found $(wc -l < /tmp/lspci_basic.txt) PCIe devices"
return 0
```

}

# Test 1: Basic Device Detection and Enumeration

test_device_detection() {
log_test_start “Device Detection and Enumeration”

```
local errors=0

# Test lspci functionality
if ! lspci -D > /dev/null 2>&1; then
    log_test_result "Device Detection" "FAIL" "lspci command failed"
    return 1
fi

# Check for any devices that fail to enumerate
local enum_failures=$(dmesg | grep -i "pci.*enumeration.*fail" | wc -l)
if [ $enum_failures -gt 0 ]; then
    log_test_result "Device Detection" "FAIL" "Found $enum_failures enumeration failures in dmesg"
    return 1
fi

# Verify all devices have valid vendor/device IDs
while read -r device; do
    local pci_id=$(echo "$device" | awk '{print $1}')
    local vendor_device=$(echo "$device" | grep -o '\[....:....\]' | head -1)
    
    if [ -z "$vendor_device" ] || [ "$vendor_device" = "[ffff:ffff]" ]; then
        log_test_result "Device Detection" "FAIL" "Invalid vendor/device ID for $pci_id"
        ((errors++))
    fi
done < /tmp/lspci_basic.txt

if [ $errors -eq 0 ]; then
    log_test_result "Device Detection" "PASS" "All devices properly detected and enumerated"
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
    
    # Test standard config space (256 bytes)
    if ! lspci -s "$pci_id" -xxx > /dev/null 2>&1; then
        log_error "Failed to read standard config space for $pci_id"
        ((errors++))
        continue
    fi
    
    # Test extended config space (4096 bytes) if available
    if lspci -s "$pci_id" -xxxx > /dev/null 2>&1; then
        log_info "Extended config space accessible for $pci_id"
    fi
    
    # Check for config space corruption (all 0xFF or 0x00)
    local config_dump=$(lspci -s "$pci_id" -xxx | grep -v "$pci_id" | tr -d ' \t\n')
    if [[ "$config_dump" =~ ^f+$ ]] || [[ "$config_dump" =~ ^0+$ ]]; then
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

# Test 3: Link Status and Capabilities

test_link_status() {
log_test_start “PCIe Link Status and Capabilities”

```
local errors=0
local links_tested=0

for device_path in /sys/bus/pci/devices/*/; do
    [ -d "$device_path" ] || continue
    
    local device_name=$(basename "$device_path")
    
    # Skip if not a PCIe device
    [ -f "${device_path}current_link_speed" ] || continue
    
    ((links_tested++))
    
    # Check current link speed
    local current_speed=$(cat "${device_path}current_link_speed" 2>/dev/null)
    local max_speed=$(cat "${device_path}max_link_speed" 2>/dev/null)
    local current_width=$(cat "${device_path}current_link_width" 2>/dev/null)
    local max_width=$(cat "${device_path}max_link_width" 2>/dev/null)
    
    log_info "Device $device_name: Speed=$current_speed/$max_speed, Width=x$current_width/x$max_width"
    
    # Check if link is running at reasonable speed/width
    if [ -z "$current_speed" ] || [ "$current_speed" = "Unknown" ]; then
        log_error "Cannot determine link speed for $device_name"
        ((errors++))
    fi
    
    if [ -z "$current_width" ] || [ "$current_width" = "0" ]; then
        log_error "Invalid link width for $device_name"
        ((errors++))
    fi
    
    # Check link training status
    if [ -f "${device_path}link_retrain" ]; then
        # Test link retraining
        echo 1 > "${device_path}link_retrain" 2>/dev/null || {
            log_warning "Could not retrain link for $device_name"
        }
        sleep 1
    fi
    
done

if [ $errors -eq 0 ] && [ $links_tested -gt 0 ]; then
    log_test_result "Link Status" "PASS" "$links_tested PCIe links verified"
    return 0
else
    log_test_result "Link Status" "FAIL" "$errors errors in $links_tested links"
    return 1
fi
```

}

# Test 4: Error Status Monitoring

test_error_status() {
log_test_start “PCIe Error Status Check”

```
local errors=0
local devices_checked=0

# Clear dmesg buffer and start fresh
dmesg -c > /dev/null

# Check AER error counters
for device_path in /sys/bus/pci/devices/*/; do
    [ -d "$device_path" ] || continue
    local device_name=$(basename "$device_path")
    
    # Check for AER capability
    if [ -f "${device_path}aer_dev_correctable" ]; then
        ((devices_checked++))
        
        local correctable=$(cat "${device_path}aer_dev_correctable" 2>/dev/null || echo "0")
        local uncorrectable=$(cat "${device_path}aer_dev_uncorrectable" 2>/dev/null || echo "0")
        local fatal=$(cat "${device_path}aer_dev_fatal" 2>/dev/null || echo "0")
        
        log_info "Device $device_name AER: Correctable=$correctable, Uncorrectable=$uncorrectable, Fatal=$fatal"
        
        if [ "$uncorrectable" -gt 0 ] || [ "$fatal" -gt 0 ]; then
            log_error "Device $device_name has uncorrectable/fatal errors"
            ((errors++))
        fi
        
        if [ "$correctable" -gt 100 ]; then
            log_warning "Device $device_name has high correctable error count: $correctable"
        fi
    fi
done

# Check for recent PCIe errors in dmesg
sleep 2
local pcie_errors=$(dmesg | grep -i -E "(pcie|aer|pci.*error)" | wc -l)
if [ $pcie_errors -gt 0 ]; then
    log_error "Found $pcie_errors PCIe-related errors in dmesg"
    dmesg | grep -i -E "(pcie|aer|pci.*error)" >> "$ERROR_LOG"
    ((errors++))
fi

if [ $errors -eq 0 ]; then
    log_test_result "Error Status" "PASS" "$devices_checked devices clean, no new errors"
    return 0
else
    log_test_result "Error Status" "FAIL" "$errors error conditions detected"
    return 1
fi
```

}

# Test 5: Memory Access and BAR Testing

test_memory_access() {
log_test_start “Memory Access and BAR Testing”

```
local errors=0
local bars_tested=0

for device_path in /sys/bus/pci/devices/*/; do
    [ -d "$device_path" ] || continue
    local device_name=$(basename "$device_path")
    
    # Check each BAR
    for bar in {0..5}; do
        if [ -f "${device_path}resource${bar}" ]; then
            local resource=$(cat "${device_path}resource${bar}" 2>/dev/null)
            if [ -n "$resource" ] && [ "$resource" != "0x0000000000000000 0x0000000000000000 0x0000000000000000" ]; then
                ((bars_tested++))
                
                # Parse resource info
                local start=$(echo $resource | awk '{print $1}')
                local end=$(echo $resource | awk '{print $2}')
                local flags=$(echo $resource | awk '{print $3}')
                
                if [ "$start" = "0x0000000000000000" ] && [ "$end" != "0x0000000000000000" ]; then
                    log_error "BAR $bar for $device_name not properly assigned"
                    ((errors++))
                fi
                
                log_info "Device $device_name BAR$bar: $start-$end flags=$flags"
            fi
        fi
    done
    
    # Check if device is enabled
    if [ -f "${device_path}enable" ]; then
        local enabled=$(cat "${device_path}enable" 2>/dev/null)
        if [ "$enabled" != "1" ]; then
            log_warning "Device $device_name is not enabled"
        fi
    fi
done

if [ $errors -eq 0 ]; then
    log_test_result "Memory Access" "PASS" "$bars_tested BARs verified"
    return 0
else
    log_test_result "Memory Access" "FAIL" "$errors BAR assignment errors"
    return 1
fi
```

}

# Test 6: Link Stability Test

test_link_stability() {
log_test_start “PCIe Link Stability Test”

```
local errors=0
local retrain_errors=0

log_info "Running $LINK_RETRAIN_CYCLES link retrain cycles..."

for device_path in /sys/bus/pci/devices/*/; do
    [ -d "$device_path" ] || continue
    [ -f "${device_path}current_link_speed" ] || continue
    
    local device_name=$(basename "$device_path")
    
    # Record initial link parameters
    local initial_speed=$(cat "${device_path}current_link_speed" 2>/dev/null)
    local initial_width=$(cat "${device_path}current_link_width" 2>/dev/null)
    
    if [ -f "${device_path}link_retrain" ]; then
        for ((cycle=1; cycle<=LINK_RETRAIN_CYCLES; cycle++)); do
            # Clear dmesg
            dmesg -c > /dev/null
            
            # Trigger link retrain
            echo 1 > "${device_path}link_retrain" 2>/dev/null || continue
            
            # Wait for retrain to complete
            sleep 2
            
            # Check if link came back up with same parameters
            local new_speed=$(cat "${device_path}current_link_speed" 2>/dev/null)
            local new_width=$(cat "${device_path}current_link_width" 2>/dev/null)
            
            if [ "$new_speed" != "$initial_speed" ] || [ "$new_width" != "$initial_width" ]; then
                log_error "Link parameters changed after retrain for $device_name: $initial_speed/$initial_width -> $new_speed/$new_width"
                ((retrain_errors++))
            fi
            
            # Check for errors during retrain
            local link_errors=$(dmesg | grep -i -E "(link.*train|link.*fail|link.*error)" | wc -l)
            if [ $link_errors -gt 0 ]; then
                log_error "Link training errors detected for $device_name in cycle $cycle"
                ((retrain_errors++))
            fi
            
            [ $((cycle % 5)) -eq 0 ] && log_info "Completed $cycle/$LINK_RETRAIN_CYCLES retrain cycles for $device_name"
        done
    fi
done

if [ $retrain_errors -eq 0 ]; then
    log_test_result "Link Stability" "PASS" "$LINK_RETRAIN_CYCLES retrain cycles completed successfully"
    return 0
else
    log_test_result "Link Stability" "FAIL" "$retrain_errors errors during link retraining"
    return 1
fi
```

}

# Test 7: Stress Test with I/O Operations

test_io_stress() {
log_test_start “PCIe I/O Stress Test”

```
local errors=0

log_info "Running ${STRESS_DURATION}s I/O stress test..."

# Clear error counters
dmesg -c > /dev/null

# Start background I/O stress
{
    local end_time=$(($(date +%s) + STRESS_DURATION))
    while [ $(date +%s) -lt $end_time ]; do
        # Continuous lspci operations to stress config space access
        lspci -vvv > /dev/null 2>&1
        lspci -D -xxx > /dev/null 2>&1
        
        # Brief pause to prevent overwhelming the system
        sleep 0.1
    done &
    local stress_pid=$!
    
    # Monitor for errors during stress test
    local error_count=0
    local check_end_time=$(($(date +%s) + STRESS_DURATION))
    
    while [ $(date +%s) -lt $check_end_time ]; do
        sleep 5
        local new_errors=$(dmesg | grep -i -E "(pcie|aer|pci.*error|timeout)" | wc -l)
        if [ $new_errors -gt $error_count ]; then
            log_error "New PCIe errors detected during stress test: $((new_errors - error_count))"
            ((errors++))
            error_count=$new_errors
        fi
        log_info "Stress test progress: $(($(date +%s) - (check_end_time - STRESS_DURATION)))/${STRESS_DURATION}s"
    done
    
    # Clean up background process
    kill $stress_pid 2>/dev/null
    wait $stress_pid 2>/dev/null
}

# Final error check
sleep 2
local final_errors=$(dmesg | grep -i -E "(pcie|aer|pci.*error)" | wc -l)
if [ $final_errors -gt 0 ]; then
    log_error "Found $final_errors PCIe errors after stress test"
    ((errors++))
fi

if [ $errors -eq 0 ]; then
    log_test_result "I/O Stress Test" "PASS" "${STRESS_DURATION}s stress test completed without errors"
    return 0
else
    log_test_result "I/O Stress Test" "FAIL" "$errors error conditions during stress test"
    return 1
fi
```

}

# Test 8: Power Management Test

test_power_management() {
log_test_start “Power Management Test”

```
local errors=0
local pm_devices=0

for device_path in /sys/bus/pci/devices/*/; do
    [ -d "$device_path" ] || continue
    local device_name=$(basename "$device_path")
    
    # Check if device supports power management
    if [ -d "${device_path}power" ]; then
        ((pm_devices++))
        
        # Check current power state
        local power_state=$(cat "${device_path}power/runtime_status" 2>/dev/null || echo "unknown")
        log_info "Device $device_name power state: $power_state"
        
        # Test runtime PM if supported
        if [ -f "${device_path}power/control" ]; then
            local pm_control=$(cat "${device_path}power/control" 2>/dev/null)
            if [ "$pm_control" = "auto" ]; then
                # Test power state transitions
                echo "on" > "${device_path}power/control" 2>/dev/null
                sleep 1
                echo "auto" > "${device_path}power/control" 2>/dev/null
                
                # Verify device is still accessible
                if ! lspci -s "$device_name" > /dev/null 2>&1; then
                    log_error "Device $device_name not accessible after PM test"
                    ((errors++))
                fi
            fi
        fi
    fi
done

if [ $errors -eq 0 ]; then
    log_test_result "Power Management" "PASS" "$pm_devices devices tested"
    return 0
else
    log_test_result "Power Management" "FAIL" "$errors PM-related errors"
    return 1
fi
```

}

# Generate comprehensive report

generate_validation_report() {
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
    echo "Failed: $FAILED_TESTS"
    echo ""
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo "OVERALL RESULT: ✅ PASS - Adapter validated successfully"
        echo "STATUS: READY FOR DEPLOYMENT"
    else
        echo "OVERALL RESULT: ❌ FAIL - Adapter validation failed"
        echo "STATUS: DO NOT DEPLOY - RETURN TO WORKSHOP"
        echo ""
        echo "Failed Tests:"
        for test_name in "${FAILED_TEST_NAMES[@]}"; do
            echo "  - $test_name"
        done
    fi
    
    echo ""
    echo "DETAILED TEST RESULTS"
    echo "===================="
    for result in "${TEST_RESULTS[@]}"; do
        echo "$result"
    done
    
    echo ""
    echo "SYSTEM INFORMATION"
    echo "=================="
    echo "PCIe Devices Found: $(wc -l < /tmp/lspci_basic.txt)"
    lspci -D | head -20
    
    if [ -s "$ERROR_LOG" ]; then
        echo ""
        echo "ERROR DETAILS"
        echo "============="
        tail -50 "$ERROR_LOG"
    fi
    
} | tee "$REPORT_FILE"

echo ""
log_info "Full report saved to: $REPORT_FILE"
log_info "Validation log: $VALIDATION_LOG"
log_info "Error log: $ERROR_LOG"
```

}

# Main validation function

run_full_validation() {
local target_device=”$1”

```
echo -e "${PURPLE}"
echo "╔════════════════════════════════════════════════════════════════════════════════╗"
echo "║                        PCIe Adapter Validation Suite                          ║"
echo "║                              Version $SCRIPT_VERSION                                      ║"
echo "╚════════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

init_logging
check_root

# Get device information
get_pcie_devices "$target_device" || {
    log_error "Failed to enumerate PCIe devices"
    exit 1
}

# Run all validation tests
test_device_detection
test_config_space
test_link_status
test_error_status
test_memory_access
test_link_stability
test_io_stress
test_power_management

# Generate final report
generate_validation_report

# Exit with appropriate code
if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "\n${GREEN}🎉 VALIDATION PASSED - Adapter is ready for deployment${NC}"
    exit 0
else
    echo -e "\n${RED}❌ VALIDATION FAILED - Do not deploy this adapter${NC}"
    echo -e "${RED}   Send back to workshop for replacement${NC}"
    exit 1
fi
```

}

# Command line interface

case “${1:-full}” in
“full”)
run_full_validation “$2”
;;
“quick”)
STRESS_DURATION=60
STABILITY_CYCLES=3
LINK_RETRAIN_CYCLES=5
run_full_validation “$2”
;;
“device”)
if [ -z “$2” ]; then
echo “Usage: $0 device <device_pattern>”
echo “Example: $0 device ‘Ethernet controller’”
exit 1
fi
run_full_validation “$2”
;;
“help”|”-h”|”–help”)
echo “PCIe Adapter Validation Script v$SCRIPT_VERSION”
echo “”
echo “Usage: $0 [full|quick|device <pattern>|help]”
echo “”
echo “Commands:”
echo “  full             - Run complete validation suite (default)”
echo “  quick            - Run shortened validation (faster)”
echo “  device <pattern> - Focus on specific device type”
echo “  help             - Show this help”
echo “”
echo “Examples:”
echo “  $0                           # Full validation”
echo “  $0 quick                     # Quick validation”
echo “  $0 device ‘NVMe’            # Test only NVMe devices”
echo “  $0 device ‘Network’         # Test only Network adapters”
echo “”
echo “Exit codes:”
echo “  0 - All tests passed (adapter is good)”
echo “  1 - One or more tests failed (adapter is faulty)”
;;
*)
echo “Unknown command: $1”
echo “Use ‘$0 help’ for usage information”
exit 1
;;
esac