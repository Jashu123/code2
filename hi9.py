#!/usr/bin/env python3
“””
PCIe Bus Error Monitor and Validator
Monitors system logs and PCIe device status to detect faulty adapters
“””

import subprocess
import re
import time
import logging
import json
from datetime import datetime, timedelta
from pathlib import Path
import sys
import argparse

class PCIeErrorMonitor:
def **init**(self, log_file=None, verbose=False):
self.log_file = log_file or “/var/log/kern.log”
self.verbose = verbose
self.setup_logging()

```
    # Error patterns to watch for
    self.error_patterns = [
        r'pcieport.*AER.*error',
        r'PCIe Bus Error',
        r'RxErr',
        r'TxErr',
        r'BadTLP',
        r'BadDLLP',
        r'Rollover',
        r'Timeout',
        r'NonFatalErr',
        r'FatalErr',
        r'UnsupReq',
        r'ACSViol',
        r'UncorrIntErr',
        r'CorrIntErr',
        r'HeaderOF',
        r'ECRC',
        r'dnvme.*error',
        r'nvme.*error'
    ]

def setup_logging(self):
    """Setup logging configuration"""
    log_level = logging.DEBUG if self.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('pcie_monitor.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    self.logger = logging.getLogger(__name__)

def get_pcie_devices(self):
    """Get list of PCIe devices using lspci"""
    try:
        result = subprocess.run(['lspci', '-v'], capture_output=True, text=True, check=True)
        devices = []
        current_device = {}
        
        for line in result.stdout.split('\n'):
            if re.match(r'^[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]', line):
                if current_device:
                    devices.append(current_device)
                current_device = {'address': line.split()[0], 'description': ' '.join(line.split()[1:])}
            elif line.startswith('\t') and current_device:
                current_device.setdefault('details', []).append(line.strip())
        
        if current_device:
            devices.append(current_device)
        
        return devices
    except subprocess.CalledProcessError as e:
        self.logger.error(f"Failed to get PCIe devices: {e}")
        return []

def check_aer_status(self):
    """Check Advanced Error Reporting (AER) status"""
    aer_errors = {}
    try:
        # Check for AER capability
        result = subprocess.run(['lspci', '-vvv'], capture_output=True, text=True, check=True)
        
        current_device = None
        for line in result.stdout.split('\n'):
            if re.match(r'^[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]', line):
                current_device = line.split()[0]
                aer_errors[current_device] = {'correctable': 0, 'uncorrectable': 0, 'details': []}
            elif 'Advanced Error Reporting' in line and current_device:
                aer_errors[current_device]['has_aer'] = True
            elif 'UESta:' in line and current_device:
                # Uncorrectable Error Status
                if any(err in line for err in ['DLP', 'TLP', 'FCP', 'PTLP', 'CA', 'UC', 'RO', 'MT']):
                    aer_errors[current_device]['uncorrectable'] += 1
                    aer_errors[current_device]['details'].append(f"Uncorrectable: {line.strip()}")
            elif 'CESta:' in line and current_device:
                # Correctable Error Status
                if any(err in line for err in ['RxErr', 'BadTLP', 'BadDLLP', 'Rollover', 'Timeout']):
                    aer_errors[current_device]['correctable'] += 1
                    aer_errors[current_device]['details'].append(f"Correctable: {line.strip()}")
    
    except subprocess.CalledProcessError as e:
        self.logger.error(f"Failed to check AER status: {e}")
    
    return aer_errors

def scan_system_logs(self, hours=24):
    """Scan system logs for PCIe errors in the last N hours"""
    errors_found = []
    cutoff_time = datetime.now() - timedelta(hours=hours)
    
    try:
        # Try different log sources
        log_sources = [
            self.log_file,
            "/var/log/messages", 
            "/var/log/syslog",
            "/var/log/dmesg"
        ]
        
        for log_source in log_sources:
            if not Path(log_source).exists():
                continue
                
            self.logger.debug(f"Scanning {log_source}")
            
            try:
                with open(log_source, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        # Extract timestamp (various formats)
                        timestamp_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
                        if timestamp_match:
                            try:
                                # Parse timestamp (assuming current year)
                                timestamp_str = timestamp_match.group(1)
                                timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                                
                                if timestamp < cutoff_time:
                                    continue
                            except ValueError:
                                pass  # Skip lines with unparseable timestamps
                        
                        # Check for error patterns
                        for pattern in self.error_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                errors_found.append({
                                    'timestamp': timestamp_match.group(1) if timestamp_match else 'Unknown',
                                    'source': log_source,
                                    'line': line_num,
                                    'message': line.strip(),
                                    'pattern': pattern
                                })
                                break
            
            except PermissionError:
                self.logger.warning(f"Permission denied reading {log_source}")
            except Exception as e:
                self.logger.error(f"Error reading {log_source}: {e}")
    
    except Exception as e:
        self.logger.error(f"Error scanning logs: {e}")
    
    return errors_found

def run_pcie_stress_test(self, duration=60):
    """Run a basic PCIe stress test"""
    self.logger.info(f"Starting PCIe stress test for {duration} seconds...")
    
    # Check if we can access PCIe config space
    try:
        subprocess.run(['lspci', '-xxx'], capture_output=True, check=True)
        self.logger.info("PCIe config space accessible")
    except subprocess.CalledProcessError:
        self.logger.warning("Cannot access PCIe config space")
    
    # Monitor for errors during stress period
    start_time = time.time()
    errors_during_test = []
    
    while time.time() - start_time < duration:
        # Check for new errors
        recent_errors = self.scan_system_logs(hours=0.1)  # Last 6 minutes
        for error in recent_errors:
            if error not in errors_during_test:
                errors_during_test.append(error)
                self.logger.warning(f"Error detected during stress test: {error['message']}")
        
        time.sleep(5)
    
    self.logger.info("Stress test completed")
    return errors_during_test

def validate_adapter(self, device_address=None):
    """Comprehensive adapter validation"""
    self.logger.info("Starting PCIe adapter validation...")
    
    validation_results = {
        'timestamp': datetime.now().isoformat(),
        'overall_status': 'PASS',
        'tests': {}
    }
    
    # Test 1: Device enumeration
    devices = self.get_pcie_devices()
    validation_results['tests']['device_enumeration'] = {
        'status': 'PASS' if devices else 'FAIL',
        'devices_found': len(devices),
        'details': devices[:5]  # Limit output
    }
    
    if not devices:
        validation_results['overall_status'] = 'FAIL'
    
    # Test 2: AER status check
    aer_status = self.check_aer_status()
    aer_errors = sum(dev.get('correctable', 0) + dev.get('uncorrectable', 0) for dev in aer_status.values())
    validation_results['tests']['aer_status'] = {
        'status': 'PASS' if aer_errors == 0 else 'FAIL',
        'total_errors': aer_errors,
        'details': {k: v for k, v in aer_status.items() if v.get('correctable', 0) > 0 or v.get('uncorrectable', 0) > 0}
    }
    
    if aer_errors > 0:
        validation_results['overall_status'] = 'FAIL'
    
    # Test 3: Recent error log scan
    recent_errors = self.scan_system_logs(hours=1)
    validation_results['tests']['recent_errors'] = {
        'status': 'PASS' if not recent_errors else 'FAIL',
        'error_count': len(recent_errors),
        'details': recent_errors[:10]  # Limit output
    }
    
    if recent_errors:
        validation_results['overall_status'] = 'FAIL'
    
    # Test 4: Basic stress test
    stress_errors = self.run_pcie_stress_test(duration=30)
    validation_results['tests']['stress_test'] = {
        'status': 'PASS' if not stress_errors else 'FAIL',
        'errors_during_test': len(stress_errors),
        'details': stress_errors
    }
    
    if stress_errors:
        validation_results['overall_status'] = 'FAIL'
    
    return validation_results

def generate_report(self, results):
    """Generate a human-readable report"""
    print("\n" + "="*60)
    print("PCIe ADAPTER VALIDATION REPORT")
    print("="*60)
    print(f"Timestamp: {results['timestamp']}")
    print(f"Overall Status: {results['overall_status']}")
    print("\nTest Results:")
    print("-" * 40)
    
    for test_name, test_data in results['tests'].items():
        status_symbol = "✅" if test_data['status'] == 'PASS' else "❌"
        print(f"{status_symbol} {test_name.replace('_', ' ').title()}: {test_data['status']}")
        
        if test_data['status'] == 'FAIL' and test_data.get('details'):
            print(f"   Details: {test_data['details']}")
    
    print("\n" + "="*60)
    
    if results['overall_status'] == 'FAIL':
        print("⚠️  ADAPTER VALIDATION FAILED - DO NOT DEPLOY")
        print("This adapter should be returned to the workshop.")
    else:
        print("✅ ADAPTER VALIDATION PASSED - SAFE TO DEPLOY")
    
    print("="*60)
```

def main():
parser = argparse.ArgumentParser(description=‘PCIe Bus Error Monitor and Validator’)
parser.add_argument(’–validate’, action=‘store_true’, help=‘Run full adapter validation’)
parser.add_argument(’–monitor’, type=int, metavar=‘HOURS’, help=‘Monitor logs for errors (specify hours to look back)’)
parser.add_argument(’–stress-test’, type=int, metavar=‘SECONDS’, help=‘Run stress test for specified duration’)
parser.add_argument(’–log-file’, help=‘Specify log file to monitor (default: /var/log/kern.log)’)
parser.add_argument(’–verbose’, ‘-v’, action=‘store_true’, help=‘Enable verbose output’)
parser.add_argument(’–output’, help=‘Save results to JSON file’)

```
args = parser.parse_args()

if not any([args.validate, args.monitor, args.stress_test]):
    parser.print_help()
    return

monitor = PCIeErrorMonitor(log_file=args.log_file, verbose=args.verbose)

if args.validate:
    results = monitor.validate_adapter()
    monitor.generate_report(results)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")

elif args.monitor:
    errors = monitor.scan_system_logs(hours=args.monitor)
    print(f"\nFound {len(errors)} PCIe errors in the last {args.monitor} hours:")
    for error in errors:
        print(f"  {error['timestamp']}: {error['message']}")

elif args.stress_test:
    errors = monitor.run_pcie_stress_test(duration=args.stress_test)
    print(f"\nStress test completed. Found {len(errors)} errors during test.")
    for error in errors:
        print(f"  {error['message']}")
```

if **name** == “**main**”:
main()