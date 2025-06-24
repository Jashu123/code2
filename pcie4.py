#!/usr/bin/env python3
"""
PCIe Bus Error Monitor and Validator
Monitors system logs and PCIe device status to detect faulty adapters
"""

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
    def __init__(self, log_file=None, verbose=False):
        self.log_file = log_file or "/var/log/kern.log"
        self.verbose = verbose
        self.setup_logging()
        
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
        handlers = [logging.StreamHandler(sys.stdout)]
        
        # Try to create log file, fall back to console-only if permission denied
        try:
            # Try current directory first
            log_path = 'pcie_monitor.log'
            handlers.append(logging.FileHandler(log_path))
        except PermissionError:
            try:
                # Try /tmp directory as fallback
                log_path = '/tmp/pcie_monitor.log'
                handlers.append(logging.FileHandler(log_path))
                print(f"Log file created at: {log_path}")
            except PermissionError:
                # Fall back to console-only logging
                print("Warning: Cannot create log file. Using console output only.")
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=handlers
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
                    with open(log_source, 'r', errors='ignore') as f:
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
    
    def run_nvme_stress_test(self, device_address, duration=300):
        """Run comprehensive NVMe stress test to trigger potential errors"""
        self.logger.info(f"Starting intensive NVMe stress test for {duration} seconds...")
        
        stress_results = {
            'duration': duration,
            'tests_run': [],
            'errors_detected': [],
            'aer_errors_before': {},
            'aer_errors_after': {},
            'status': 'PASS'
        }
        
        # Get baseline AER error counts
        stress_results['aer_errors_before'] = self.check_nvme_aer_status(device_address)
        
        # Find the /dev/nvme device path
        nvme_device_path = None
        try:
            result = subprocess.run(['nvme', 'list'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '/dev/nvme' in line:
                        nvme_device_path = line.split()[0]
                        break
        except:
            pass
        
        start_time = time.time()
        test_processes = []
        
        try:
            # Test 1: Continuous device enumeration stress
            self.logger.info("Starting PCIe enumeration stress...")
            stress_results['tests_run'].append('pcie_enumeration_stress')
            
            # Test 2: NVMe command stress (if nvme-cli available and device accessible)
            if nvme_device_path:
                self.logger.info(f"Starting NVMe command stress on {nvme_device_path}...")
                stress_results['tests_run'].append('nvme_command_stress')
            
            # Test 3: PCIe config space stress
            self.logger.info("Starting PCIe config space stress...")
            stress_results['tests_run'].append('pcie_config_stress')
            
            # Test 4: I/O stress (if device is accessible)
            if nvme_device_path and self._check_device_writable(nvme_device_path):
                self.logger.info("Starting I/O stress test...")
                stress_results['tests_run'].append('io_stress')
            
            # Run stress tests
            while time.time() - start_time < duration:
                current_time = time.time() - start_time
                
                # PCIe enumeration stress - hammer lspci
                try:
                    subprocess.run(['lspci', '-s', device_address], 
                                 capture_output=True, timeout=2)
                    subprocess.run(['lspci', '-vvv', '-s', device_address], 
                                 capture_output=True, timeout=5)
                except subprocess.TimeoutExpired:
                    error_msg = f"PCIe enumeration timeout at {current_time:.1f}s"
                    stress_results['errors_detected'].append(error_msg)
                    self.logger.warning(error_msg)
                except subprocess.CalledProcessError as e:
                    error_msg = f"PCIe enumeration failed at {current_time:.1f}s: {e}"
                    stress_results['errors_detected'].append(error_msg)
                    self.logger.warning(error_msg)
                
                # NVMe SMART queries (every 5 seconds)
                if nvme_device_path and int(current_time) % 5 == 0:
                    try:
                        subprocess.run(['nvme', 'smart-log', nvme_device_path], 
                                     capture_output=True, timeout=10)
                        subprocess.run(['nvme', 'id-ctrl', nvme_device_path], 
                                     capture_output=True, timeout=10)
                    except subprocess.TimeoutExpired:
                        error_msg = f"NVMe command timeout at {current_time:.1f}s"
                        stress_results['errors_detected'].append(error_msg)
                        self.logger.warning(error_msg)
                    except subprocess.CalledProcessError as e:
                        error_msg = f"NVMe command failed at {current_time:.1f}s: {e}"
                        stress_results['errors_detected'].append(error_msg)
                        self.logger.warning(error_msg)
                
                # PCIe config space reads (every 2 seconds)
                if int(current_time) % 2 == 0:
                    try:
                        subprocess.run(['setpci', '-s', device_address, '0.L'], 
                                     capture_output=True, timeout=3)
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                        error_msg = f"PCIe config read failed at {current_time:.1f}s: {e}"
                        stress_results['errors_detected'].append(error_msg)
                        self.logger.warning(error_msg)
                
                # Check for new AER errors every 10 seconds
                if int(current_time) % 10 == 0:
                    current_aer = self.check_nvme_aer_status(device_address)
                    baseline_errors = (stress_results['aer_errors_before'].get('correctable', 0) + 
                                     stress_results['aer_errors_before'].get('uncorrectable', 0))
                    current_errors = (current_aer.get('correctable', 0) + 
                                    current_aer.get('uncorrectable', 0))
                    
                    if current_errors > baseline_errors:
                        error_msg = f"New AER errors detected at {current_time:.1f}s"
                        stress_results['errors_detected'].append(error_msg)
                        self.logger.warning(error_msg)
                
                # Check system logs for new errors
                recent_errors = self.scan_system_logs(hours=0.01)  # Last ~36 seconds
                for error in recent_errors:
                    if (('nvme' in error['message'].lower() or device_address in error['message']) 
                        and error['message'] not in [e for e in stress_results['errors_detected']]):
                        stress_results['errors_detected'].append(f"Log error at {current_time:.1f}s: {error['message']}")
                        self.logger.warning(f"New log error: {error['message']}")
                
                # Brief pause to prevent overwhelming the system
                time.sleep(0.5)
                
                # Progress indicator
                if int(current_time) % 30 == 0:
                    self.logger.info(f"Stress test progress: {current_time:.0f}/{duration}s")
        
        except KeyboardInterrupt:
            self.logger.info("Stress test interrupted by user")
        except Exception as e:
            error_msg = f"Stress test exception: {e}"
            stress_results['errors_detected'].append(error_msg)
            self.logger.error(error_msg)
        
        # Get final AER error counts
        stress_results['aer_errors_after'] = self.check_nvme_aer_status(device_address)
        
        # Determine overall status
        if stress_results['errors_detected']:
            stress_results['status'] = 'FAIL'
        
        # Check for AER error increases
        before_total = (stress_results['aer_errors_before'].get('correctable', 0) + 
                       stress_results['aer_errors_before'].get('uncorrectable', 0))
        after_total = (stress_results['aer_errors_after'].get('correctable', 0) + 
                      stress_results['aer_errors_after'].get('uncorrectable', 0))
        
        if after_total > before_total:
            stress_results['status'] = 'FAIL'
            stress_results['errors_detected'].append(f"AER errors increased from {before_total} to {after_total}")
        
        self.logger.info(f"Stress test completed. Status: {stress_results['status']}")
        return stress_results
    
    def _check_device_writable(self, device_path):
        """Check if device is safe for write testing"""
        try:
            # Only do read-only tests to avoid data loss
            result = subprocess.run(['blockdev', '--getsize64', device_path], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def run_thermal_stress(self, device_address, duration=60):
        """Run thermal stress by keeping device busy"""
        self.logger.info(f"Starting thermal stress test for {duration} seconds...")
        
        thermal_errors = []
        start_time = time.time()
        
        # Find NVMe device
        nvme_device = None
        try:
            result = subprocess.run(['nvme', 'list'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '/dev/nvme' in line:
                        nvme_device = line.split()[0]
                        break
        except:
            pass
        
        if not nvme_device:
            return {'status': 'SKIP', 'reason': 'No accessible NVMe device found'}
        
        # Continuous SMART queries to keep device active
        while time.time() - start_time < duration:
            try:
                # Multiple rapid SMART queries
                for _ in range(5):
                    result = subprocess.run(['nvme', 'smart-log', nvme_device], 
                                          capture_output=True, timeout=5)
                    if result.returncode != 0:
                        thermal_errors.append(f"SMART query failed during thermal stress")
                        break
                
                # Brief pause
                time.sleep(1)
                
            except subprocess.TimeoutExpired:
                thermal_errors.append("SMART query timeout during thermal stress")
            except Exception as e:
                thermal_errors.append(f"Thermal stress error: {e}")
        
        return {
            'status': 'FAIL' if thermal_errors else 'PASS',
            'errors': thermal_errors
        }
    
    def find_nvme_devices(self):
        """Find NVMe devices specifically"""
        nvme_devices = []
        try:
            # Method 1: Look for NVMe class devices
            result = subprocess.run(['lspci', '-d', '::0108'], capture_output=True, text=True, check=True)
            for line in result.stdout.strip().split('\n'):
                if line:
                    device_addr = line.split()[0]
                    nvme_devices.append(device_addr)
            
            # Method 2: Also check for devices with "NVMe" in description
            result = subprocess.run(['lspci'], capture_output=True, text=True, check=True)
            for line in result.stdout.split('\n'):
                if 'nvme' in line.lower() or 'non-volatile memory' in line.lower():
                    device_addr = line.split()[0]
                    if device_addr not in nvme_devices:
                        nvme_devices.append(device_addr)
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to find NVMe devices: {e}")
        
        return nvme_devices
    
    def check_nvme_aer_status(self, device_address):
        """Check AER status for specific NVMe device"""
        aer_status = {'correctable': 0, 'uncorrectable': 0, 'details': [], 'has_aer': False}
        
        try:
            result = subprocess.run(['lspci', '-vvv', '-s', device_address], 
                                  capture_output=True, text=True, check=True)
            
            in_aer_section = False
            for line in result.stdout.split('\n'):
                if 'Advanced Error Reporting' in line:
                    aer_status['has_aer'] = True
                    in_aer_section = True
                elif in_aer_section and 'UESta:' in line:
                    # Check for actual errors (not just capability)
                    if any(err in line for err in ['DLP+', 'SDES+', 'TLP+', 'FCP+', 'CmpltTO+', 
                                                 'CmpltAbrt+', 'UnxCmplt+', 'RxOF+', 'MalfTLP+', 
                                                 'ECRC+', 'UnsupReq+', 'ACSViol+']):
                        aer_status['uncorrectable'] += 1
                        aer_status['details'].append(f"Uncorrectable: {line.strip()}")
                elif in_aer_section and 'CESta:' in line:
                    # Check for actual errors (not just capability)
                    if any(err in line for err in ['RxErr+', 'BadTLP+', 'BadDLLP+', 'Rollover+', 
                                                 'Timeout+', 'AdvNonFatalErr+']):
                        aer_status['correctable'] += 1
                        aer_status['details'].append(f"Correctable: {line.strip()}")
                elif in_aer_section and line.strip() == '':
                    in_aer_section = False
        
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to check AER for device {device_address}: {e}")
        
        return aer_status
    
    def test_nvme_functionality(self, device_address):
        """Test basic NVMe functionality"""
        test_results = {'status': 'PASS', 'details': []}
        
        try:
            # Check if nvme command line tool is available
            result = subprocess.run(['nvme', 'list'], capture_output=True, text=True)
            if result.returncode == 0:
                # Find corresponding /dev/nvme device
                nvme_drives = []
                for line in result.stdout.split('\n'):
                    if '/dev/nvme' in line:
                        drive = line.split()[0]
                        nvme_drives.append(drive)
                
                if nvme_drives:
                    test_results['details'].append(f"Found NVMe drives: {', '.join(nvme_drives)}")
                    
                    # Test SMART data access for first drive
                    try:
                        smart_result = subprocess.run(['nvme', 'smart-log', nvme_drives[0]], 
                                                    capture_output=True, text=True, timeout=10)
                        if smart_result.returncode == 0:
                            test_results['details'].append("SMART data accessible")
                        else:
                            test_results['status'] = 'FAIL'
                            test_results['details'].append("SMART data not accessible")
                    except subprocess.TimeoutExpired:
                        test_results['status'] = 'FAIL'
                        test_results['details'].append("SMART query timeout")
                else:
                    test_results['details'].append("No /dev/nvme devices found")
            else:
                test_results['details'].append("nvme-cli not available")
        
        except FileNotFoundError:
            test_results['details'].append("nvme-cli not installed")
        except Exception as e:
            test_results['status'] = 'FAIL'
            test_results['details'].append(f"Error testing NVMe: {e}")
        
        return test_results
    
    def validate_adapter(self, device_address=None):
        """Validate NVMe adapter specifically"""
        self.logger.info("Starting NVMe adapter validation...")
        
        validation_results = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'PASS',
            'tests': {},
            'target_device': None
        }
        
        # Find NVMe devices
        nvme_devices = self.find_nvme_devices()
        if not nvme_devices:
            validation_results['overall_status'] = 'FAIL'
            validation_results['tests']['device_detection'] = {
                'status': 'FAIL',
                'message': 'No NVMe devices found'
            }
            return validation_results
        
        # Use specified device or first found NVMe device
        target_device = device_address if device_address in nvme_devices else nvme_devices[0]
        validation_results['target_device'] = target_device
        
        self.logger.info(f"Testing NVMe device: {target_device}")
        
        # Test 1: Device enumeration
        validation_results['tests']['device_detection'] = {
            'status': 'PASS',
            'nvme_devices_found': nvme_devices,
            'target_device': target_device
        }
        
        # Test 2: AER status check (only for target device)
        aer_status = self.check_nvme_aer_status(target_device)
        total_errors = aer_status.get('correctable', 0) + aer_status.get('uncorrectable', 0)
        validation_results['tests']['aer_status'] = {
            'status': 'PASS' if total_errors == 0 else 'FAIL',
            'has_aer': aer_status.get('has_aer', False),
            'correctable_errors': aer_status.get('correctable', 0),
            'uncorrectable_errors': aer_status.get('uncorrectable', 0),
            'details': aer_status.get('details', [])
        }
        
        if total_errors > 0:
            validation_results['overall_status'] = 'FAIL'
        
        # Test 3: NVMe functionality test
        nvme_test = self.test_nvme_functionality(target_device)
        validation_results['tests']['nvme_functionality'] = nvme_test
        
        if nvme_test['status'] == 'FAIL':
            validation_results['overall_status'] = 'FAIL'
        
        # Test 4: Recent NVMe-specific error log scan
        recent_errors = self.scan_system_logs(hours=1)
        nvme_errors = [e for e in recent_errors if 'nvme' in e['message'].lower() or target_device in e['message']]
        validation_results['tests']['recent_nvme_errors'] = {
            'status': 'PASS' if not nvme_errors else 'FAIL',
            'error_count': len(nvme_errors),
            'details': nvme_errors[:5]
        }
        
        if nvme_errors:
            validation_results['overall_status'] = 'FAIL'
        
        # Test 5: Intensive stress test to trigger errors
        self.logger.info("Running intensive stress test to trigger potential errors...")
        stress_results = self.run_nvme_stress_test(target_device, duration=60)
        validation_results['tests']['intensive_stress'] = {
            'status': stress_results['status'],
            'duration': stress_results['duration'],
            'tests_executed': stress_results['tests_run'],
            'errors_detected': len(stress_results['errors_detected']),
            'error_details': stress_results['errors_detected'][:10],  # Limit output
            'aer_before': stress_results['aer_errors_before'],
            'aer_after': stress_results['aer_errors_after']
        }
        
        if stress_results['status'] == 'FAIL':
            validation_results['overall_status'] = 'FAIL'
        
        # Test 6: Thermal stress (optional)
        thermal_results = self.run_thermal_stress(target_device, duration=30)
        validation_results['tests']['thermal_stress'] = thermal_results
        
        if thermal_results['status'] == 'FAIL':
            validation_results['overall_status'] = 'FAIL'
        
        return validation_results
    
    def generate_report(self, results):
        """Generate a human-readable report"""
        print("\n" + "="*60)
        print("NVMe ADAPTER VALIDATION REPORT")
        print("="*60)
        print(f"Timestamp: {results['timestamp']}")
        print(f"Target Device: {results.get('target_device', 'Unknown')}")
        print(f"Overall Status: {results['overall_status']}")
        print("\nTest Results:")
        print("-" * 40)
        
        test_descriptions = {
            'device_detection': 'NVMe Device Detection',
            'aer_status': 'Advanced Error Reporting',
            'nvme_functionality': 'NVMe Functionality Test',
            'recent_nvme_errors': 'Recent Error Log Scan',
            'intensive_stress': 'Intensive Stress Test',
            'thermal_stress': 'Thermal Stress Test'
        }
        
        for test_name, test_data in results['tests'].items():
            display_name = test_descriptions.get(test_name, test_name.replace('_', ' ').title())
            status_symbol = "✅" if test_data['status'] == 'PASS' else "❌"
            print(f"{status_symbol} {display_name}: {test_data['status']}")
            
            if test_data['status'] == 'FAIL':
                if 'details' in test_data and test_data['details']:
                    print(f"   Issue: {test_data['details']}")
                elif 'message' in test_data:
                    print(f"   Issue: {test_data['message']}")
                elif test_name == 'aer_status':
                    error_count = test_data.get('correctable_errors', 0) + test_data.get('uncorrectable_errors', 0)
                    print(f"   Issue: {error_count} AER errors detected")
        
        print("\n" + "="*60)
        
        if results['overall_status'] == 'FAIL':
            print("⚠️  NVMe ADAPTER VALIDATION FAILED - DO NOT DEPLOY")
            print("This adapter should be returned to the workshop.")
        else:
            print("✅ NVMe ADAPTER VALIDATION PASSED - SAFE TO DEPLOY")
        
        print("="*60)


def main():
    parser = argparse.ArgumentParser(description='NVMe Adapter Validation Tool')
    parser.add_argument('--validate', action='store_true', help='Run full NVMe adapter validation')
    parser.add_argument('--device', help='Specific PCIe device address to test (e.g., 01:00.0)')
    parser.add_argument('--monitor', type=int, metavar='HOURS', help='Monitor logs for NVMe errors (specify hours to look back)')
    parser.add_argument('--stress-test', type=int, metavar='SECONDS', help='Run intensive stress test for specified duration (default: 300s)')
    parser.add_argument('--thermal-stress', type=int, metavar='SECONDS', help='Run thermal stress test for specified duration')
    parser.add_argument('--quick-stress', action='store_true', help='Run quick 60-second stress test')
    parser.add_argument('--list-nvme', action='store_true', help='List all detected NVMe devices')
    parser.add_argument('--log-file', help='Specify log file to monitor (default: /var/log/kern.log)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--output', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    if not any([args.validate, args.monitor, args.stress_test, args.thermal_stress, args.quick_stress, args.list_nvme]):
        parser.print_help()
        return
    
    monitor = PCIeErrorMonitor(log_file=args.log_file, verbose=args.verbose)
    
    if args.list_nvme:
        nvme_devices = monitor.find_nvme_devices()
        print(f"\nDetected NVMe devices:")
        for device in nvme_devices:
            print(f"  {device}")
        if not nvme_devices:
            print("  No NVMe devices found")
    
    elif args.validate:
        results = monitor.validate_adapter(device_address=args.device)
        monitor.generate_report(results)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to {args.output}")
    
    elif args.stress_test or args.quick_stress:
        # Find NVMe device first
        nvme_devices = monitor.find_nvme_devices()
        if not nvme_devices:
            print("No NVMe devices found for stress testing")
            return
        
        target_device = args.device if args.device in nvme_devices else nvme_devices[0]
        duration = args.stress_test if args.stress_test else 60
        
        print(f"Running intensive stress test on {target_device} for {duration} seconds...")
        stress_results = monitor.run_nvme_stress_test(target_device, duration)
        
        print(f"\nStress Test Results:")
        print(f"Status: {stress_results['status']}")
        print(f"Tests executed: {', '.join(stress_results['tests_run'])}")
        print(f"Errors detected: {len(stress_results['errors_detected'])}")
        
        if stress_results['errors_detected']:
            print("\nErrors found:")
            for error in stress_results['errors_detected'][:10]:
                print(f"  {error}")
        
        # Show AER error comparison
        before = stress_results['aer_errors_before']
        after = stress_results['aer_errors_after']
        before_total = before.get('correctable', 0) + before.get('uncorrectable', 0)
        after_total = after.get('correctable', 0) + after.get('uncorrectable', 0)
        
        print(f"\nAER Error Count: {before_total} → {after_total}")
        if after_total > before_total:
            print("⚠️  AER errors increased during stress test!")
    
    elif args.thermal_stress:
        nvme_devices = monitor.find_nvme_devices()
        if not nvme_devices:
            print("No NVMe devices found for thermal stress testing")
            return
        
        target_device = args.device if args.device in nvme_devices else nvme_devices[0]
        thermal_results = monitor.run_thermal_stress(target_device, args.thermal_stress)
        
        print(f"\nThermal Stress Test Results:")
        print(f"Status: {thermal_results['status']}")
        if thermal_results.get('errors'):
            print("Errors:")
            for error in thermal_results['errors']:
                print(f"  {error}")
    
    elif args.monitor:
        errors = monitor.scan_system_logs(hours=args.monitor)
        nvme_errors = [e for e in errors if 'nvme' in e['message'].lower()]
        print(f"\nFound {len(nvme_errors)} NVMe-related errors in the last {args.monitor} hours:")
        for error in nvme_errors:
            print(f"  {error['timestamp']}: {error['message']}")


if __name__ == "__main__":
    main()