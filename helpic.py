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
import threading

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
    
    def run_maximum_stress_test(self, device_address, duration=600):
        """Run maximum intensity stress test to simulate days of production load in minutes"""
        self.logger.info(f"Starting MAXIMUM intensity stress test for {duration} seconds...")
        self.logger.info("This test simulates days of production workload in minutes")
        
        stress_results = {
            'duration': duration,
            'tests_run': [],
            'errors_detected': [],
            'aer_errors_before': {},
            'aer_errors_after': {},
            'status': 'PASS',
            'stress_phases': []
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
            # Phase 1: Extreme PCIe enumeration stress (continuous)
            self.logger.info("Phase 1: Maximum PCIe enumeration stress...")
            stress_results['tests_run'].append('extreme_pcie_enumeration')
            
            # Phase 2: Aggressive NVMe command bombardment (continuous)
            if nvme_device_path:
                self.logger.info("Phase 2: Aggressive NVMe command stress...")
                stress_results['tests_run'].append('aggressive_nvme_commands')
            
            # Phase 3: Mixed I/O patterns (simulating production)
            self.logger.info("Phase 3: Mixed I/O pattern simulation...")
            stress_results['tests_run'].append('mixed_io_patterns')
            
            # Phase 4: Thermal stress (keep device hot)
            self.logger.info("Phase 4: Thermal stress...")
            stress_results['tests_run'].append('thermal_stress')
            
            # Phase 5: Power state stress
            self.logger.info("Phase 5: Power state transitions...")
            stress_results['tests_run'].append('power_state_stress')
            
            phase_duration = duration // 5  # Split into 5 phases
            current_phase = 1
            
            while time.time() - start_time < duration:
                current_time = time.time() - start_time
                
                # Determine current stress phase
                new_phase = min(int(current_time // phase_duration) + 1, 5)
                if new_phase != current_phase:
                    self.logger.info(f"Entering stress phase {new_phase}")
                    stress_results['stress_phases'].append(f"Phase {new_phase} at {current_time:.1f}s")
                    current_phase = new_phase
                
                # CONTINUOUS: Extreme PCIe enumeration (every 0.1 seconds)
                try:
                    subprocess.run(['lspci', '-s', device_address], 
                                 capture_output=True, timeout=1)
                    if int(current_time * 10) % 5 == 0:  # Every 0.5 seconds
                        subprocess.run(['lspci', '-vvv', '-s', device_address], 
                                     capture_output=True, timeout=3)
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                    error_msg = f"PCIe enumeration failed at {current_time:.1f}s: {e}"
                    stress_results['errors_detected'].append(error_msg)
                    self.logger.warning(error_msg)
                
                # CONTINUOUS: Aggressive NVMe commands (every 0.2 seconds)
                if nvme_device_path and int(current_time * 5) % 1 == 0:
                    commands = [
                        ['nvme', 'smart-log', nvme_device_path],
                        ['nvme', 'id-ctrl', nvme_device_path],
                        ['nvme', 'id-ns', '-n', '1', nvme_device_path],
                        ['nvme', 'get-log', '-i', '1', nvme_device_path],
                        ['nvme', 'list-ns', nvme_device_path]
                    ]
                    
                    for cmd in commands:
                        try:
                            subprocess.run(cmd, capture_output=True, timeout=5)
                        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                            error_msg = f"NVMe command {cmd[1]} failed at {current_time:.1f}s: {e}"
                            stress_results['errors_detected'].append(error_msg)
                            self.logger.warning(error_msg)
                        
                        # Brief pause between commands
                        time.sleep(0.05)
                
                # PHASE-SPECIFIC STRESS TESTS
                if current_phase == 1:
                    # Phase 1: PCIe config space hammering
                    if int(current_time * 10) % 2 == 0:  # Every 0.2 seconds
                        try:
                            # Read various config registers rapidly
                            registers = ['0.L', '4.L', '8.L', 'c.L', '10.L', '14.L']
                            for reg in registers:
                                subprocess.run(['setpci', '-s', device_address, reg], 
                                             capture_output=True, timeout=2)
                        except Exception as e:
                            error_msg = f"Config space read failed at {current_time:.1f}s: {e}"
                            stress_results['errors_detected'].append(error_msg)
                
                elif current_phase == 2:
                    # Phase 2: Small random I/O simulation (if safe)
                    if nvme_device_path and int(current_time) % 3 == 0:
                        try:
                            # Use dd for small reads to simulate random I/O
                            subprocess.run(['dd', 'if=' + nvme_device_path, 'of=/dev/null', 
                                          'bs=4k', 'count=1', 'skip=0'], 
                                         capture_output=True, timeout=5)
                        except Exception as e:
                            error_msg = f"Small I/O test failed at {current_time:.1f}s: {e}"
                            stress_results['errors_detected'].append(error_msg)
                
                elif current_phase == 3:
                    # Phase 3: Large sequential I/O simulation
                    if nvme_device_path and int(current_time) % 5 == 0:
                        try:
                            # Larger sequential reads
                            subprocess.run(['dd', 'if=' + nvme_device_path, 'of=/dev/null', 
                                          'bs=1M', 'count=10'], 
                                         capture_output=True, timeout=10)
                        except Exception as e:
                            error_msg = f"Large I/O test failed at {current_time:.1f}s: {e}"
                            stress_results['errors_detected'].append(error_msg)
                
                elif current_phase == 4:
                    # Phase 4: Concurrent operations
                    if int(current_time) % 2 == 0:
                        try:
                            # Multiple concurrent NVMe operations
                            processes = []
                            for i in range(3):
                                p = subprocess.Popen(['nvme', 'smart-log', nvme_device_path], 
                                                   capture_output=True)
                                processes.append(p)
                            
                            # Wait for all to complete
                            for p in processes:
                                try:
                                    p.wait(timeout=5)
                                except subprocess.TimeoutExpired:
                                    p.kill()
                                    error_msg = f"Concurrent operation timeout at {current_time:.1f}s"
                                    stress_results['errors_detected'].append(error_msg)
                        except Exception as e:
                            error_msg = f"Concurrent operation failed at {current_time:.1f}s: {e}"
                            stress_results['errors_detected'].append(error_msg)
                
                elif current_phase == 5:
                    # Phase 5: Maximum frequency operations
                    try:
                        # Rapid-fire short operations
                        for _ in range(5):
                            subprocess.run(['lspci', '-s', device_address], 
                                         capture_output=True, timeout=1)
                            if nvme_device_path:
                                subprocess.run(['nvme', 'list'], 
                                             capture_output=True, timeout=2)
                    except Exception as e:
                        error_msg = f"Maximum frequency test failed at {current_time:.1f}s: {e}"
                        stress_results['errors_detected'].append(error_msg)
                
                # Check for new AER errors every 15 seconds
                if int(current_time) % 15 == 0:
                    current_aer = self.check_nvme_aer_status(device_address)
                    baseline_errors = (stress_results['aer_errors_before'].get('correctable', 0) + 
                                     stress_results['aer_errors_before'].get('uncorrectable', 0))
                    current_errors = (current_aer.get('correctable', 0) + 
                                    current_aer.get('uncorrectable', 0))
                    
                    if current_errors > baseline_errors:
                        error_msg = f"New AER errors detected at {current_time:.1f}s (Phase {current_phase})"
                        stress_results['errors_detected'].append(error_msg)
                        self.logger.warning(error_msg)
                
                # Check system logs for new errors every 20 seconds
                if int(current_time) % 20 == 0:
                    recent_errors = self.scan_system_logs(hours=0.01)  # Last ~36 seconds
                    for error in recent_errors:
                        if (('nvme' in error['message'].lower() or device_address in error['message']) 
                            and error['message'] not in [e for e in stress_results['errors_detected'] if 'Log error' in e]):
                            stress_results['errors_detected'].append(f"Log error at {current_time:.1f}s (Phase {current_phase}): {error['message']}")
                            self.logger.warning(f"New log error: {error['message']}")
                
                # Progress indicator every 60 seconds
                if int(current_time) % 60 == 0 and current_time > 0:
                    remaining = duration - current_time
                    self.logger.info(f"Maximum stress progress: {current_time:.0f}/{duration}s (Phase {current_phase}, {remaining:.0f}s remaining)")
                
                # Very brief pause to prevent complete system overload
                time.sleep(0.1)
        
        except KeyboardInterrupt:
            self.logger.info("Maximum stress test interrupted by user")
        except Exception as e:
            error_msg = f"Maximum stress test exception: {e}"
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
    
    def simulate_reseat_cycle(self, device_address, cycles=3):
        """Simulate adapter reseating by forcing PCIe bus rescans and power cycles"""
        self.logger.info(f"Starting reseat simulation for {cycles} cycles...")
        
        reseat_results = {
            'cycles_completed': 0,
            'cycles_requested': cycles,
            'errors_detected': [],
            'aer_before_each_cycle': [],
            'aer_after_each_cycle': [],
            'device_disappeared': [],
            'device_reappeared': [],
            'status': 'PASS'
        }
        
        for cycle in range(cycles):
            cycle_num = cycle + 1
            self.logger.info(f"Starting reseat cycle {cycle_num}/{cycles}")
            
            try:
                # Get AER status before this cycle
                aer_before = self.check_nvme_aer_status(device_address)
                reseat_results['aer_before_each_cycle'].append(aer_before)
                
                # Step 1: Force PCIe bus rescan (simulates physical removal)
                self.logger.info(f"Cycle {cycle_num}: Forcing PCIe bus rescan...")
                
                # Get the bus number from device address (e.g., "01:00.0" -> bus "01")
                bus_num = device_address.split(':')[0]
                
                try:
                    # Force remove device from PCIe bus
                    with open(f'/sys/bus/pci/devices/0000:{device_address}/remove', 'w') as f:
                        f.write('1')
                    self.logger.info(f"Cycle {cycle_num}: Device removed from bus")
                    time.sleep(2)
                    
                    # Check if device disappeared
                    result = subprocess.run(['lspci', '-s', device_address], capture_output=True)
                    if result.returncode != 0:
                        reseat_results['device_disappeared'].append(cycle_num)
                        self.logger.info(f"Cycle {cycle_num}: Device successfully disappeared")
                    else:
                        error_msg = f"Cycle {cycle_num}: Device failed to disappear after remove"
                        reseat_results['errors_detected'].append(error_msg)
                        self.logger.warning(error_msg)
                    
                    # Force PCIe bus rescan (simulates physical reinsertion)
                    with open(f'/sys/bus/pci/rescan', 'w') as f:
                        f.write('1')
                    self.logger.info(f"Cycle {cycle_num}: PCIe bus rescanned")
                    time.sleep(3)
                    
                    # Check if device reappeared
                    result = subprocess.run(['lspci', '-s', device_address], capture_output=True)
                    if result.returncode == 0:
                        reseat_results['device_reappeared'].append(cycle_num)
                        self.logger.info(f"Cycle {cycle_num}: Device successfully reappeared")
                    else:
                        error_msg = f"Cycle {cycle_num}: Device failed to reappear after rescan"
                        reseat_results['errors_detected'].append(error_msg)
                        self.logger.error(error_msg)
                        reseat_results['status'] = 'FAIL'
                        break
                
                except PermissionError:
                    # If we can't write to sysfs, try alternative methods
                    self.logger.warning(f"Cycle {cycle_num}: Cannot write to sysfs, trying alternative reseat simulation")
                    
                    # Alternative: Rapid PCIe config space access to stress the connection
                    for i in range(50):
                        try:
                            subprocess.run(['lspci', '-s', device_address], capture_output=True, timeout=1)
                            subprocess.run(['setpci', '-s', device_address, '0.L'], capture_output=True, timeout=1)
                        except:
                            pass
                        time.sleep(0.1)
                
                except Exception as e:
                    error_msg = f"Cycle {cycle_num}: Exception during reseat simulation: {e}"
                    reseat_results['errors_detected'].append(error_msg)
                    self.logger.error(error_msg)
                
                # Step 2: Stress test immediately after "reseating"
                self.logger.info(f"Cycle {cycle_num}: Running post-reseat stress test...")
                
                # Quick stress test to see if reseating caused issues
                post_reseat_stress = self.run_nvme_stress_test(device_address, duration=60)
                if post_reseat_stress['status'] == 'FAIL':
                    error_msg = f"Cycle {cycle_num}: Post-reseat stress test failed"
                    reseat_results['errors_detected'].append(error_msg)
                    reseat_results['status'] = 'FAIL'
                    self.logger.error(error_msg)
                
                # Step 3: Check AER status after this cycle
                aer_after = self.check_nvme_aer_status(device_address)
                reseat_results['aer_after_each_cycle'].append(aer_after)
                
                # Compare AER errors
                before_total = aer_before.get('correctable', 0) + aer_before.get('uncorrectable', 0)
                after_total = aer_after.get('correctable', 0) + aer_after.get('uncorrectable', 0)
                
                if after_total > before_total:
                    error_msg = f"Cycle {cycle_num}: AER errors increased from {before_total} to {after_total}"
                    reseat_results['errors_detected'].append(error_msg)
                    reseat_results['status'] = 'FAIL'
                    self.logger.warning(error_msg)
                
                reseat_results['cycles_completed'] = cycle_num
                self.logger.info(f"Cycle {cycle_num}: Completed successfully")
                
                # Brief pause between cycles
                time.sleep(2)
                
            except Exception as e:
                error_msg = f"Cycle {cycle_num}: Fatal error during reseat simulation: {e}"
                reseat_results['errors_detected'].append(error_msg)
                reseat_results['status'] = 'FAIL'
                self.logger.error(error_msg)
                break
        
        self.logger.info(f"Reseat simulation completed: {reseat_results['cycles_completed']}/{cycles} cycles")
        return reseat_results
    
    def run_back_to_back_stress(self, device_address, rounds=3, stress_duration=120):
        """Run multiple back-to-back stress tests with reseat simulation"""
        self.logger.info(f"Starting back-to-back stress test with {rounds} rounds...")
        
        b2b_results = {
            'rounds_completed': 0,
            'rounds_requested': rounds,
            'stress_duration': stress_duration,
            'round_results': [],
            'overall_errors': [],
            'status': 'PASS'
        }
        
        for round_num in range(1, rounds + 1):
            self.logger.info(f"Starting round {round_num}/{rounds}")
            
            round_result = {
                'round': round_num,
                'reseat_result': None,
                'stress_result': None,
                'status': 'PASS'
            }
            
            try:
                # Step 1: Simulate reseating (1 cycle)
                self.logger.info(f"Round {round_num}: Simulating adapter reseat...")
                reseat_result = self.simulate_reseat_cycle(device_address, cycles=1)
                round_result['reseat_result'] = reseat_result
                
                if reseat_result['status'] == 'FAIL':
                    round_result['status'] = 'FAIL'
                    b2b_results['status'] = 'FAIL'
                    error_msg = f"Round {round_num}: Reseat simulation failed"
                    b2b_results['overall_errors'].append(error_msg)
                    self.logger.error(error_msg)
                
                # Step 2: Immediate stress test after reseating
                self.logger.info(f"Round {round_num}: Running stress test after reseat...")
                stress_result = self.run_nvme_stress_test(device_address, duration=stress_duration)
                round_result['stress_result'] = stress_result
                
                if stress_result['status'] == 'FAIL':
                    round_result['status'] = 'FAIL'
                    b2b_results['status'] = 'FAIL'
                    error_msg = f"Round {round_num}: Stress test failed"
                    b2b_results['overall_errors'].append(error_msg)
                    self.logger.error(error_msg)
                
                b2b_results['round_results'].append(round_result)
                b2b_results['rounds_completed'] = round_num
                
                self.logger.info(f"Round {round_num}: Completed with status {round_result['status']}")
                
                # Brief pause between rounds
                if round_num < rounds:
                    self.logger.info(f"Pausing 10 seconds before round {round_num + 1}...")
                    time.sleep(10)
            
            except Exception as e:
                error_msg = f"Round {round_num}: Exception occurred: {e}"
                b2b_results['overall_errors'].append(error_msg)
                b2b_results['status'] = 'FAIL'
                self.logger.error(error_msg)
                break
        
    def run_heavy_enumeration_stress(self, device_address, duration=300):
        """Run heavy PCIe enumeration stress to trigger bus errors"""
        self.logger.info(f"Starting heavy enumeration stress for {duration} seconds...")
        
        enum_results = {
            'duration': duration,
            'enumeration_cycles': 0,
            'config_reads': 0,
            'capability_scans': 0,
            'power_state_cycles': 0,
            'errors_detected': [],
            'timing_violations': [],
            'status': 'PASS'
        }
        
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration:
                cycle_start = time.time()
                enum_results['enumeration_cycles'] += 1
                
                # 1. Rapid PCIe enumeration (every 50ms)
                try:
                    subprocess.run(['lspci', '-s', device_address], 
                                 capture_output=True, timeout=1)
                    subprocess.run(['lspci', '-vvv', '-s', device_address], 
                                 capture_output=True, timeout=2)
                except subprocess.TimeoutExpired:
                    error_msg = f"Enumeration timeout at cycle {enum_results['enumeration_cycles']}"
                    enum_results['errors_detected'].append(error_msg)
                    enum_results['status'] = 'FAIL'
                
                # 2. Aggressive config space hammering
                config_registers = ['0.L', '4.L', '8.L', 'c.L', '10.L', '14.L', '18.L', '1c.L', 
                                  '2c.L', '34.B', '3c.B', '3d.B', '3e.W', '40.L', '44.L']
                
                for reg in config_registers:
                    try:
                        result = subprocess.run(['setpci', '-s', device_address, reg], 
                                               capture_output=True, timeout=0.5)
                        enum_results['config_reads'] += 1
                        if result.returncode != 0:
                            error_msg = f"Config read failed for register {reg} at cycle {enum_results['enumeration_cycles']}"
                            enum_results['errors_detected'].append(error_msg)
                    except subprocess.TimeoutExpired:
                        error_msg = f"Config read timeout for register {reg}"
                        enum_results['errors_detected'].append(error_msg)
                        enum_results['status'] = 'FAIL'
                
                # 3. Capability structure rapid scanning
                try:
                    subprocess.run(['lspci', '-xxx', '-s', device_address], 
                                 capture_output=True, timeout=1)
                    enum_results['capability_scans'] += 1
                except subprocess.TimeoutExpired:
                    error_msg = f"Capability scan timeout at cycle {enum_results['enumeration_cycles']}"
                    enum_results['errors_detected'].append(error_msg)
                
                # 4. Power state cycling stress (every 10 cycles)
                if enum_results['enumeration_cycles'] % 10 == 0:
                    try:
                        # Read power management control register
                        subprocess.run(['setpci', '-s', device_address, '4.L'], 
                                     capture_output=True, timeout=0.5)
                        enum_results['power_state_cycles'] += 1
                    except:
                        pass  # Don't fail test on power state issues
                
                # 5. Timing stress - minimal delays between operations
                cycle_time = time.time() - cycle_start
                if cycle_time > 0.1:  # If cycle took longer than 100ms
                    enum_results['timing_violations'].append(cycle_time)
                
                # Very brief pause to prevent system overload
                time.sleep(0.02)  # 20ms - very aggressive timing
                
                # Progress every 1000 cycles
                if enum_results['enumeration_cycles'] % 1000 == 0:
                    elapsed = time.time() - start_time
                    rate = enum_results['enumeration_cycles'] / elapsed
                    self.logger.info(f"Enumeration stress: {enum_results['enumeration_cycles']} cycles, "
                                   f"{rate:.1f} cycles/sec, {len(enum_results['errors_detected'])} errors")
        
        except Exception as e:
            error_msg = f"Heavy enumeration stress exception: {e}"
            enum_results['errors_detected'].append(error_msg)
            enum_results['status'] = 'FAIL'
        
        enum_results['total_time'] = time.time() - start_time
        enum_results['cycles_per_second'] = enum_results['enumeration_cycles'] / enum_results['total_time']
        
        if enum_results['errors_detected']:
            enum_results['status'] = 'FAIL'
        
        return enum_results
    
    def run_signal_integrity_stress(self, device_address, duration=300):
        """Run signal integrity stress patterns to trigger electrical issues"""
        self.logger.info(f"Starting signal integrity stress for {duration} seconds...")
        
        signal_results = {
            'duration': duration,
            'burst_cycles': 0,
            'concurrent_operations': 0,
            'bandwidth_tests': 0,
            'link_retraining_attempts': 0,
            'errors_detected': [],
            'link_downgrades': [],
            'status': 'PASS'
        }
        
        start_time = time.time()
        nvme_device = self._get_nvme_device()
        
        try:
            while time.time() - start_time < duration:
                cycle_start = time.time()
                signal_results['burst_cycles'] += 1
                
                # 1. High-frequency burst operations
                burst_processes = []
                try:
                    # Launch multiple concurrent PCIe operations
                    for _ in range(8):  # 8 concurrent operations
                        p = subprocess.Popen(['lspci', '-s', device_address], 
                                           capture_output=True)
                        burst_processes.append(p)
                    
                    # Wait for all to complete with timeout
                    for p in burst_processes:
                        try:
                            p.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            p.kill()
                            error_msg = f"Burst operation timeout at cycle {signal_results['burst_cycles']}"
                            signal_results['errors_detected'].append(error_msg)
                    
                    signal_results['concurrent_operations'] += len(burst_processes)
                
                except Exception as e:
                    error_msg = f"Burst operation failed: {e}"
                    signal_results['errors_detected'].append(error_msg)
                
                # 2. PCIe bandwidth stress testing
                if nvme_device and signal_results['burst_cycles'] % 5 == 0:
                    try:
                        # Multiple rapid NVMe operations to stress PCIe bandwidth
                        bandwidth_processes = []
                        for _ in range(4):
                            p = subprocess.Popen(['nvme', 'smart-log', nvme_device], 
                                               capture_output=True)
                            bandwidth_processes.append(p)
                        
                        for p in bandwidth_processes:
                            try:
                                p.wait(timeout=2)
                            except subprocess.TimeoutExpired:
                                p.kill()
                                error_msg = f"Bandwidth stress timeout at cycle {signal_results['burst_cycles']}"
                                signal_results['errors_detected'].append(error_msg)
                        
                        signal_results['bandwidth_tests'] += 1
                    
                    except Exception as e:
                        error_msg = f"Bandwidth stress failed: {e}"
                        signal_results['errors_detected'].append(error_msg)
                
                # 3. Link speed detection and stress
                try:
                    result = subprocess.run(['lspci', '-vvv', '-s', device_address], 
                                          capture_output=True, text=True, timeout=2)
                    
                    if result.returncode == 0:
                        # Check for link speed downgrades
                        if 'LnkSta:' in result.stdout:
                            link_info = [line for line in result.stdout.split('\n') if 'LnkSta:' in line]
                            if link_info:
                                signal_results['link_retraining_attempts'] += 1
                                # Look for speed downgrades (this is simplified - real implementation would parse speeds)
                                if 'Downgraded' in result.stdout:
                                    signal_results['link_downgrades'].append(signal_results['burst_cycles'])
                
                except subprocess.TimeoutExpired:
                    error_msg = f"Link status check timeout at cycle {signal_results['burst_cycles']}"
                    signal_results['errors_detected'].append(error_msg)
                
                # 4. EMI simulation through rapid operations
                if signal_results['burst_cycles'] % 20 == 0:
                    try:
                        # Rapid-fire operations to create electrical noise
                        for _ in range(50):
                            subprocess.run(['setpci', '-s', device_address, '0.L'], 
                                         capture_output=True, timeout=0.1)
                    except:
                        pass  # Expected to have some timeouts
                
                # 5. Configuration space pattern stress
                try:
                    # Read/write patterns that stress signal integrity
                    config_patterns = ['0.L', '4.L', '0.L', '8.L', '0.L', 'c.L']
                    for pattern in config_patterns:
                        subprocess.run(['setpci', '-s', device_address, pattern], 
                                     capture_output=True, timeout=0.2)
                
                except Exception as e:
                    error_msg = f"Config pattern stress failed: {e}"
                    signal_results['errors_detected'].append(error_msg)
                
                # Minimal delay for maximum stress
                time.sleep(0.01)  # 10ms - very aggressive
                
                # Progress every 500 cycles
                if signal_results['burst_cycles'] % 500 == 0:
                    elapsed = time.time() - start_time
                    rate = signal_results['burst_cycles'] / elapsed
                    self.logger.info(f"Signal integrity stress: {signal_results['burst_cycles']} cycles, "
                                   f"{rate:.1f} cycles/sec, {len(signal_results['errors_detected'])} errors")
        
        except Exception as e:
            error_msg = f"Signal integrity stress exception: {e}"
            signal_results['errors_detected'].append(error_msg)
            signal_results['status'] = 'FAIL'
        
        signal_results['total_time'] = time.time() - start_time
        signal_results['cycles_per_second'] = signal_results['burst_cycles'] / signal_results['total_time']
        
        if signal_results['errors_detected'] or signal_results['link_downgrades']:
            signal_results['status'] = 'FAIL'
        
        return signal_results
    
    def run_advanced_bus_stress(self, device_address, duration=300):
        """Run advanced bus stress patterns targeting bus-level issues"""
        self.logger.info(f"Starting advanced bus stress for {duration} seconds...")
        
        bus_results = {
            'duration': duration,
            'bus_cycles': 0,
            'arbitration_tests': 0,
            'multi_device_conflicts': 0,
            'hotplug_cycles': 0,
            'topology_scans': 0,
            'errors_detected': [],
            'bus_hangs': [],
            'status': 'PASS'
        }
        
        start_time = time.time()
        bus_num = device_address.split(':')[0]
        
        try:
            while time.time() - start_time < duration:
                cycle_start = time.time()
                bus_results['bus_cycles'] += 1
                
                # 1. Bus arbitration stress
                try:
                    # Multiple devices trying to access bus simultaneously
                    arbitration_processes = []
                    
                    # Scan all devices on the same bus
                    for slot in range(8):  # Check slots 0-7
                        slot_addr = f"{bus_num}:{slot:02d}.0"
                        p = subprocess.Popen(['lspci', '-s', slot_addr], 
                                           capture_output=True)
                        arbitration_processes.append(p)
                    
                    # Wait for all with timeout
                    for p in arbitration_processes:
                        try:
                            p.wait(timeout=0.5)
                        except subprocess.TimeoutExpired:
                            p.kill()
                            error_msg = f"Bus arbitration timeout at cycle {bus_results['bus_cycles']}"
                            bus_results['errors_detected'].append(error_msg)
                    
                    bus_results['arbitration_tests'] += 1
                
                except Exception as e:
                    error_msg = f"Bus arbitration stress failed: {e}"
                    bus_results['errors_detected'].append(error_msg)
                
                # 2. Multi-device conflict simulation
                if bus_results['bus_cycles'] % 10 == 0:
                    try:
                        # Simultaneous operations on multiple PCIe devices
                        conflict_processes = []
                        
                        # Target our device and any others on the bus
                        devices_to_stress = [device_address]
                        
                        # Add other devices if they exist
                        try:
                            result = subprocess.run(['lspci'], capture_output=True, text=True, timeout=2)
                            for line in result.stdout.split('\n'):
                                if line.startswith(bus_num + ':') and device_address not in line:
                                    other_device = line.split()[0]
                                    devices_to_stress.append(other_device)
                                    if len(devices_to_stress) >= 4:  # Limit to 4 devices
                                        break
                        except:
                            pass
                        
                        # Stress all devices simultaneously
                        for device in devices_to_stress:
                            for _ in range(3):  # 3 operations per device
                                p = subprocess.Popen(['lspci', '-vvv', '-s', device], 
                                                   capture_output=True)
                                conflict_processes.append(p)
                        
                        # Wait for all to complete
                        for p in conflict_processes:
                            try:
                                p.wait(timeout=1)
                            except subprocess.TimeoutExpired:
                                p.kill()
                                error_msg = f"Multi-device conflict timeout at cycle {bus_results['bus_cycles']}"
                                bus_results['errors_detected'].append(error_msg)
                        
                        bus_results['multi_device_conflicts'] += 1
                    
                    except Exception as e:
                        error_msg = f"Multi-device conflict test failed: {e}"
                        bus_results['errors_detected'].append(error_msg)
                
                # 3. Rapid hotplug simulation
                if bus_results['bus_cycles'] % 25 == 0:
                    try:
                        hotplug_start = time.time()
                        
                        # Remove device
                        with open(f'/sys/bus/pci/devices/0000:{device_address}/remove', 'w') as f:
                            f.write('1')
                        
                        # Very brief delay
                        time.sleep(0.05)  # 50ms - very fast hotplug
                        
                        # Rescan
                        with open('/sys/bus/pci/rescan', 'w') as f:
                            f.write('1')
                        
                        # Wait for device to reappear
                        for attempt in range(10):  # 10 attempts
                            try:
                                result = subprocess.run(['lspci', '-s', device_address], 
                                                      capture_output=True, timeout=0.5)
                                if result.returncode == 0:
                                    break
                                time.sleep(0.1)
                            except:
                                pass
                        else:
                            error_msg = f"Device failed to reappear after hotplug cycle {bus_results['hotplug_cycles']}"
                            bus_results['errors_detected'].append(error_msg)
                            bus_results['status'] = 'FAIL'
                        
                        hotplug_time = time.time() - hotplug_start
                        if hotplug_time > 2.0:  # If hotplug took longer than 2 seconds
                            bus_results['bus_hangs'].append(hotplug_time)
                        
                        bus_results['hotplug_cycles'] += 1
                    
                    except PermissionError:
                        # Skip hotplug if no permission
                        pass
                    except Exception as e:
                        error_msg = f"Hotplug simulation failed: {e}"
                        bus_results['errors_detected'].append(error_msg)
                
                # 4. PCIe topology stress scanning
                if bus_results['bus_cycles'] % 50 == 0:
                    try:
                        # Full topology scan with timing stress
                        topology_start = time.time()
                        
                        subprocess.run(['lspci', '-tv'], capture_output=True, timeout=2)
                        subprocess.run(['lspci', '-vvv'], capture_output=True, timeout=5)
                        
                        topology_time = time.time() - topology_start
                        if topology_time > 3.0:  # If topology scan took longer than 3 seconds
                            bus_results['bus_hangs'].append(topology_time)
                        
                        bus_results['topology_scans'] += 1
                    
                    except subprocess.TimeoutExpired:
                        error_msg = f"Topology scan timeout at cycle {bus_results['bus_cycles']}"
                        bus_results['errors_detected'].append(error_msg)
                        bus_results['status'] = 'FAIL'
                    except Exception as e:
                        error_msg = f"Topology scan failed: {e}"
                        bus_results['errors_detected'].append(error_msg)
                
                # 5. Configuration space race condition testing
                try:
                    # Simultaneous config space access from multiple processes
                    race_processes = []
                    for _ in range(4):
                        p = subprocess.Popen(['setpci', '-s', device_address, '0.L'], 
                                           capture_output=True)
                        race_processes.append(p)
                    
                    for p in race_processes:
                        try:
                            p.wait(timeout=0.2)
                        except subprocess.TimeoutExpired:
                            p.kill()
                
                except Exception as e:
                    error_msg = f"Race condition test failed: {e}"
                    bus_results['errors_detected'].append(error_msg)
                
                # Minimal delay for maximum bus stress
                time.sleep(0.005)  # 5ms - extremely aggressive
                
                # Progress every 1000 cycles
                if bus_results['bus_cycles'] % 1000 == 0:
                    elapsed = time.time() - start_time
                    rate = bus_results['bus_cycles'] / elapsed
                    self.logger.info(f"Advanced bus stress: {bus_results['bus_cycles']} cycles, "
                                   f"{rate:.1f} cycles/sec, {len(bus_results['errors_detected'])} errors")
        
        except Exception as e:
            error_msg = f"Advanced bus stress exception: {e}"
            bus_results['errors_detected'].append(error_msg)
            bus_results['status'] = 'FAIL'
        
        bus_results['total_time'] = time.time() - start_time
        bus_results['cycles_per_second'] = bus_results['bus_cycles'] / bus_results['total_time']
        
        if bus_results['errors_detected'] or bus_results['bus_hangs']:
            bus_results['status'] = 'FAIL'
        
        return bus_results
        """Run continuous reseat cycles for specified duration (just enumeration testing)"""
        self.logger.info(f"Starting continuous reseat test for {duration} seconds (10 minutes)...")
        self.logger.info("This test only focuses on connect/disconnect enumeration - no stress testing")
        
        reseat_results = {
            'duration': duration,
            'cycles_attempted': 0,
            'cycles_successful': 0,
            'remove_failures': 0,
            'rescan_failures': 0,
            'enumeration_failures': 0,
            'errors_detected': [],
            'cycle_times': [],
            'status': 'PASS'
        }
        
        start_time = time.time()
        cycle_count = 0
        
        try:
            while time.time() - start_time < duration:
                cycle_start = time.time()
                cycle_count += 1
                current_time = time.time() - start_time
                
                self.logger.info(f"Cycle {cycle_count} at {current_time:.1f}s")
                reseat_results['cycles_attempted'] = cycle_count
                
                try:
                    # Step 1: Remove device from PCIe bus
                    try:
                        with open(f'/sys/bus/pci/devices/0000:{device_address}/remove', 'w') as f:
                            f.write('1')
                        
                        # Brief pause for removal to take effect
                        time.sleep(1)
                        
                        # Verify device disappeared
                        result = subprocess.run(['lspci', '-s', device_address], capture_output=True)
                        if result.returncode == 0:
                            # Device still visible - this is a problem
                            error_msg = f"Cycle {cycle_count}: Device failed to disappear after remove command"
                            reseat_results['errors_detected'].append(error_msg)
                            reseat_results['remove_failures'] += 1
                            reseat_results['status'] = 'FAIL'
                            self.logger.warning(error_msg)
                        else:
                            self.logger.debug(f"Cycle {cycle_count}: Device successfully removed")
                    
                    except PermissionError:
                        error_msg = f"Cycle {cycle_count}: Permission denied writing to remove file"
                        reseat_results['errors_detected'].append(error_msg)
                        reseat_results['remove_failures'] += 1
                        self.logger.error(error_msg)
                        # Continue with rescan anyway
                    
                    except FileNotFoundError:
                        error_msg = f"Cycle {cycle_count}: Device remove file not found - device may be gone"
                        reseat_results['errors_detected'].append(error_msg)
                        self.logger.warning(error_msg)
                    
                    # Step 2: Rescan PCIe bus to re-enumerate device
                    try:
                        with open('/sys/bus/pci/rescan', 'w') as f:
                            f.write('1')
                        
                        # Wait for enumeration to complete
                        time.sleep(2)
                        
                        # Verify device reappeared
                        result = subprocess.run(['lspci', '-s', device_address], capture_output=True)
                        if result.returncode != 0:
                            # Device didn't come back - this is a problem
                            error_msg = f"Cycle {cycle_count}: Device failed to reappear after rescan"
                            reseat_results['errors_detected'].append(error_msg)
                            reseat_results['enumeration_failures'] += 1
                            reseat_results['status'] = 'FAIL'
                            self.logger.error(error_msg)
                            
                            # Try additional rescans to recover
                            for retry in range(3):
                                self.logger.info(f"Cycle {cycle_count}: Retry rescan {retry + 1}/3")
                                time.sleep(1)
                                with open('/sys/bus/pci/rescan', 'w') as f:
                                    f.write('1')
                                time.sleep(2)
                                result = subprocess.run(['lspci', '-s', device_address], capture_output=True)
                                if result.returncode == 0:
                                    self.logger.info(f"Cycle {cycle_count}: Device recovered on retry {retry + 1}")
                                    break
                            else:
                                # Device never came back
                                error_msg = f"Cycle {cycle_count}: Device permanently lost after rescan retries"
                                reseat_results['errors_detected'].append(error_msg)
                                self.logger.error(error_msg)
                                break  # Exit the test
                        else:
                            self.logger.debug(f"Cycle {cycle_count}: Device successfully re-enumerated")
                            reseat_results['cycles_successful'] += 1
                    
                    except PermissionError:
                        error_msg = f"Cycle {cycle_count}: Permission denied writing to rescan file"
                        reseat_results['errors_detected'].append(error_msg)
                        reseat_results['rescan_failures'] += 1
                        self.logger.error(error_msg)
                    
                    # Record cycle time
                    cycle_time = time.time() - cycle_start
                    reseat_results['cycle_times'].append(cycle_time)
                    
                    # Progress reporting every 30 seconds
                    if int(current_time) % 30 == 0 and current_time > 0:
                        remaining = duration - current_time
                        success_rate = (reseat_results['cycles_successful'] / cycle_count) * 100
                        self.logger.info(f"Progress: {current_time:.0f}/{duration}s, "
                                       f"Cycle {cycle_count}, "
                                       f"Success rate: {success_rate:.1f}%, "
                                       f"{remaining:.0f}s remaining")
                    
                    # Brief pause between cycles (but keep it short to maximize cycles)
                    time.sleep(0.5)
                
                except Exception as e:
                    error_msg = f"Cycle {cycle_count}: Exception during reseat: {e}"
                    reseat_results['errors_detected'].append(error_msg)
                    reseat_results['status'] = 'FAIL'
                    self.logger.error(error_msg)
        
        except KeyboardInterrupt:
            self.logger.info("Continuous reseat test interrupted by user")
        
        # Final statistics
        total_time = time.time() - start_time
        if reseat_results['cycles_attempted'] > 0:
            success_rate = (reseat_results['cycles_successful'] / reseat_results['cycles_attempted']) * 100
            avg_cycle_time = sum(reseat_results['cycle_times']) / len(reseat_results['cycle_times']) if reseat_results['cycle_times'] else 0
        else:
            success_rate = 0
            avg_cycle_time = 0
        
        reseat_results['total_time'] = total_time
        reseat_results['success_rate'] = success_rate
        reseat_results['avg_cycle_time'] = avg_cycle_time
        reseat_results['cycles_per_minute'] = (reseat_results['cycles_attempted'] / total_time) * 60 if total_time > 0 else 0
        
        self.logger.info(f"Continuous reseat test completed:")
        self.logger.info(f"  Duration: {total_time:.1f}s")
        self.logger.info(f"  Cycles attempted: {reseat_results['cycles_attempted']}")
        self.logger.info(f"  Cycles successful: {reseat_results['cycles_successful']}")
        self.logger.info(f"  Success rate: {success_rate:.1f}%")
        self.logger.info(f"  Average cycle time: {avg_cycle_time:.2f}s")
        
        return reseat_results
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
    
    def validate_adapter_full(self, device_address=None):
        """Run comprehensive validation with extended stress testing"""
        self.logger.info("Starting FULL NVMe adapter validation with extended testing...")
        
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
        
        # Test 2: Initial AER status check
        aer_status = self.check_nvme_aer_status(target_device)
        total_errors = aer_status.get('correctable', 0) + aer_status.get('uncorrectable', 0)
        validation_results['tests']['initial_aer_status'] = {
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
        
        # Test 5: Quick stress test (60 seconds)
        self.logger.info("Running quick stress test (60 seconds)...")
        quick_stress = self.run_nvme_stress_test(target_device, duration=60)
        validation_results['tests']['quick_stress'] = {
            'status': quick_stress['status'],
            'duration': quick_stress['duration'],
            'tests_executed': quick_stress['tests_run'],
            'errors_detected': len(quick_stress['errors_detected']),
            'error_details': quick_stress['errors_detected'][:5]
        }
        
        if quick_stress['status'] == 'FAIL':
            validation_results['overall_status'] = 'FAIL'
        
        # Test 6: Extended stress test (5 minutes)
        self.logger.info("Running extended stress test (300 seconds)...")
        extended_stress = self.run_nvme_stress_test(target_device, duration=300)
        validation_results['tests']['extended_stress'] = {
            'status': extended_stress['status'],
            'duration': extended_stress['duration'],
            'tests_executed': extended_stress['tests_run'],
            'errors_detected': len(extended_stress['errors_detected']),
            'error_details': extended_stress['errors_detected'][:10],
            'aer_before': extended_stress['aer_errors_before'],
            'aer_after': extended_stress['aer_errors_after']
        }
        
        if extended_stress['status'] == 'FAIL':
            validation_results['overall_status'] = 'FAIL'
        
        # Test 7: Thermal stress test
        self.logger.info("Running thermal stress test (120 seconds)...")
        thermal_results = self.run_thermal_stress(target_device, duration=120)
        validation_results['tests']['thermal_stress'] = thermal_results
        
        if thermal_results['status'] == 'FAIL':
            validation_results['overall_status'] = 'FAIL'
        
        # Test 8: Final AER check
        final_aer = self.check_nvme_aer_status(target_device)
        final_total = final_aer.get('correctable', 0) + final_aer.get('uncorrectable', 0)
        validation_results['tests']['final_aer_status'] = {
            'status': 'PASS' if final_total == total_errors else 'FAIL',
            'initial_errors': total_errors,
            'final_errors': final_total,
            'errors_added': final_total - total_errors,
            'details': final_aer.get('details', [])
        }
        
        if final_total > total_errors:
            validation_results['overall_status'] = 'FAIL'
        
        # Test 9: Post-stress functionality check
        post_stress_nvme = self.test_nvme_functionality(target_device)
        validation_results['tests']['post_stress_functionality'] = post_stress_nvme
        
        if post_stress_nvme['status'] == 'FAIL':
            validation_results['overall_status'] = 'FAIL'
        
        self.logger.info(f"Full validation completed. Overall status: {validation_results['overall_status']}")
        return validation_results
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
        
    def validate_adapter(self, device_address=None):
        """Standard NVMe adapter validation with basic stress test"""
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
            'initial_aer_status': 'Initial AER Status',
            'aer_status': 'Advanced Error Reporting',
            'nvme_functionality': 'NVMe Functionality Test',
            'recent_nvme_errors': 'Recent Error Log Scan',
            'quick_stress': 'Quick Stress Test (60s)',
            'extended_stress': 'Extended Stress Test (300s)',
            'intensive_stress': 'Intensive Stress Test',
            'thermal_stress': 'Thermal Stress Test',
            'final_aer_status': 'Final AER Status Check',
            'post_stress_functionality': 'Post-Stress Functionality'
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
    parser.add_argument('--full-test', action='store_true', help='Run ALL tests: validation + extended stress + thermal stress')
    parser.add_argument('--device', help='Specific PCIe device address to test (e.g., 01:00.0)')
    parser.add_argument('--monitor', type=int, metavar='HOURS', help='Monitor logs for NVMe errors (specify hours to look back)')
    parser.add_argument('--heavy-enum', type=int, metavar='SECONDS', help='Run heavy enumeration stress test (default: 300s)')
    parser.add_argument('--signal-stress', type=int, metavar='SECONDS', help='Run signal integrity stress test (default: 300s)')
    parser.add_argument('--bus-stress', type=int, metavar='SECONDS', help='Run advanced bus stress test (default: 300s)')
    parser.add_argument('--ultimate-hunter', action='store_true', help='Run ULTIMATE ERROR HUNTER - all advanced techniques simultaneously')
    parser.add_argument('--endurance', type=int, metavar='HOURS', help='Run extended endurance test for specified hours (default: 24h)')
    parser.add_argument('--burn-in', type=int, metavar='CYCLES', help='Run high-cycle burn-in test (default: 10000 cycles)')
    parser.add_argument('--continuous-reseat', action='store_true', help='Run continuous reseat cycles for 10 minutes (enumeration only)')
    parser.add_argument('--reseat-test', type=int, metavar='CYCLES', help='Simulate adapter reseating for specified cycles (default: 3)')
    parser.add_argument('--back-to-back', type=int, metavar='ROUNDS', help='Run back-to-back reseat+stress tests (default: 3 rounds)')
    parser.add_argument('--max-stress', action='store_true', help='Run MAXIMUM 10-minute stress test (simulates days of production load)')
    parser.add_argument('--stress-test', type=int, metavar='SECONDS', help='Run intensive stress test for specified duration (default: 300s)')
    parser.add_argument('--thermal-stress', type=int, metavar='SECONDS', help='Run thermal stress test for specified duration')
    parser.add_argument('--quick-stress', action='store_true', help='Run quick 60-second stress test')
    parser.add_argument('--list-nvme', action='store_true', help='List all detected NVMe devices')
    parser.add_argument('--log-file', help='Specify log file to monitor (default: /var/log/kern.log)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--output', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    if not any([args.validate, args.full_test, args.max_stress, args.heavy_enum, args.signal_stress, args.bus_stress, args.ultimate_hunter, args.endurance, args.burn_in, args.continuous_reseat, args.reseat_test, args.back_to_back, args.monitor, args.stress_test, args.thermal_stress, args.quick_stress, args.list_nvme]):
        parser.print_help()
        returntest, args.back_to_back, args.monitor, args.stress_test, args.thermal_stress, args.quick_stress, args.list_nvme]):
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
    
    elif args.validate or args.full_test:
        if args.full_test:
            results = monitor.validate_adapter_full(device_address=args.device)
        else:
            results = monitor.validate_adapter(device_address=args.device)
        
        monitor.generate_report(results)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to {args.output}")
    
    elif args.max_stress:
        # Find NVMe device first
        nvme_devices = monitor.find_nvme_devices()
        if not nvme_devices:
            print("No NVMe devices found for maximum stress testing")
            return
        
        target_device = args.device if args.device in nvme_devices else nvme_devices[0]
        
        print(f"\n🔥 MAXIMUM STRESS TEST STARTING 🔥")
        print(f"Target device: {target_device}")
        print(f"Duration: 10 minutes (600 seconds)")
        print(f"This test simulates DAYS of production workload in 10 minutes!")
        print(f"Press Ctrl+C to abort if needed...\n")
        
        input("Press ENTER to start the maximum stress test...")
        
        stress_results = monitor.run_maximum_stress_test(target_device, duration=600)
        
        # Handle case where stress test failed to return results
        if stress_results is None:
            print(f"\n❌ STRESS TEST FAILED TO COMPLETE PROPERLY")
            print(f"Check the log file for details about what went wrong.")
            return
        
        print(f"\n{'='*60}")
        print(f"🔥 MAXIMUM STRESS TEST RESULTS 🔥")
        print(f"{'='*60}")
        print(f"Status: {stress_results.get('status', 'UNKNOWN')}")
        print(f"Tests executed: {', '.join(stress_results.get('tests_run', []))}")
        print(f"Phases completed: {len(stress_results.get('stress_phases', []))}")
        print(f"Errors detected: {len(stress_results.get('errors_detected', []))}")
        
        errors_detected = stress_results.get('errors_detected', [])
        if errors_detected:
            print(f"\n⚠️ ERRORS FOUND:")
            for i, error in enumerate(errors_detected[:15], 1):
                print(f"  {i}. {error}")
            if len(errors_detected) > 15:
                print(f"  ... and {len(errors_detected) - 15} more errors")
        
        # Show AER error comparison
        before = stress_results.get('aer_errors_before', {})
        after = stress_results.get('aer_errors_after', {})
        before_total = before.get('correctable', 0) + before.get('uncorrectable', 0)
        after_total = after.get('correctable', 0) + after.get('uncorrectable', 0)
        
        print(f"\nAER Error Count: {before_total} → {after_total}")
        if after_total > before_total:
            print("⚠️  AER errors increased during maximum stress test!")
        
        final_status = stress_results.get('status', 'UNKNOWN')
        if final_status == 'FAIL':
            print(f"\n❌ ADAPTER FAILED MAXIMUM STRESS TEST")
            print(f"This adapter should NOT be deployed - return to workshop")
        elif final_status == 'PASS':
            print(f"\n✅ ADAPTER SURVIVED MAXIMUM STRESS TEST")
            print(f"This adapter appears robust for production deployment")
        else:
            print(f"\n⚠️ STRESS TEST STATUS: {final_status}")
            print(f"Check results carefully before deployment decision")
        
        print(f"{'='*60}")
    
    elif args.heavy_enum:
        # Find NVMe device first
        nvme_devices = monitor.find_nvme_devices()
        if not nvme_devices:
            print("No NVMe devices found for heavy enumeration testing")
            return
        
        target_device = args.device if args.device in nvme_devices else nvme_devices[0]
        duration = args.heavy_enum if args.heavy_enum else 300
        
        print(f"\n⚡ HEAVY ENUMERATION STRESS TEST")
        print(f"Target device: {target_device}")
        print(f"Duration: {duration} seconds")
        print(f"This test hammers PCIe enumeration to trigger bus errors")
        print(f"Techniques: Rapid lspci, config space hammering, capability scanning")
        
        input("Press ENTER to start heavy enumeration stress...")
        
        enum_results = monitor.run_heavy_enumeration_stress(target_device, duration)
        
        print(f"\n{'='*60}")
        print(f"⚡ HEAVY ENUMERATION RESULTS")
        print(f"{'='*60}")
        print(f"Duration: {enum_results['total_time']:.1f}s")
        print(f"Enumeration cycles: {enum_results['enumeration_cycles']:,}")
        print(f"Config reads: {enum_results['config_reads']:,}")
        print(f"Capability scans: {enum_results['capability_scans']:,}")
        print(f"Cycles per second: {enum_results['cycles_per_second']:.1f}")
        print(f"Errors detected: {len(enum_results['errors_detected'])}")
        print(f"Timing violations: {len(enum_results['timing_violations'])}")
        print(f"Status: {enum_results['status']}")
        
        if enum_results['errors_detected']:
            print(f"\n⚠️ ENUMERATION ERRORS:")
            for error in enum_results['errors_detected'][:10]:
                print(f"  {error}")
    
    elif args.signal_stress:
        # Find NVMe device first
        nvme_devices = monitor.find_nvme_devices()
        if not nvme_devices:
            print("No NVMe devices found for signal integrity testing")
            return
        
        target_device = args.device if args.device in nvme_devices else nvme_devices[0]
        duration = args.signal_stress if args.signal_stress else 300
        
        print(f"\n📡 SIGNAL INTEGRITY STRESS TEST")
        print(f"Target device: {target_device}")
        print(f"Duration: {duration} seconds")
        print(f"This test stresses electrical signal integrity")
        print(f"Techniques: Burst operations, bandwidth stress, EMI simulation")
        
        input("Press ENTER to start signal integrity stress...")
        
        signal_results = monitor.run_signal_integrity_stress(target_device, duration)
        
        print(f"\n{'='*60}")
        print(f"📡 SIGNAL INTEGRITY RESULTS")
        print(f"{'='*60}")
        print(f"Duration: {signal_results['total_time']:.1f}s")
        print(f"Burst cycles: {signal_results['burst_cycles']:,}")
        print(f"Concurrent operations: {signal_results['concurrent_operations']:,}")
        print(f"Bandwidth tests: {signal_results['bandwidth_tests']:,}")
        print(f"Cycles per second: {signal_results['cycles_per_second']:.1f}")
        print(f"Errors detected: {len(signal_results['errors_detected'])}")
        print(f"Link downgrades: {len(signal_results['link_downgrades'])}")
        print(f"Status: {signal_results['status']}")
        
        if signal_results['errors_detected']:
            print(f"\n⚠️ SIGNAL INTEGRITY ERRORS:")
            for error in signal_results['errors_detected'][:10]:
                print(f"  {error}")
    
    elif args.bus_stress:
        # Find NVMe device first
        nvme_devices = monitor.find_nvme_devices()
        if not nvme_devices:
            print("No NVMe devices found for bus stress testing")
            return
        
        target_device = args.device if args.device in nvme_devices else nvme_devices[0]
        duration = args.bus_stress if args.bus_stress else 300
        
        print(f"\n🚌 ADVANCED BUS STRESS TEST")
        print(f"Target device: {target_device}")
        print(f"Duration: {duration} seconds")
        print(f"This test stresses PCIe bus-level operations")
        print(f"Techniques: Bus arbitration, multi-device conflicts, rapid hotplug")
        
        input("Press ENTER to start advanced bus stress...")
        
        bus_results = monitor.run_advanced_bus_stress(target_device, duration)
        
        print(f"\n{'='*60}")
        print(f"🚌 ADVANCED BUS STRESS RESULTS")
        print(f"{'='*60}")
        print(f"Duration: {bus_results['total_time']:.1f}s")
        print(f"Bus cycles: {bus_results['bus_cycles']:,}")
        print(f"Arbitration tests: {bus_results['arbitration_tests']:,}")
        print(f"Multi-device conflicts: {bus_results['multi_device_conflicts']:,}")
        print(f"Hotplug cycles: {bus_results['hotplug_cycles']:,}")
        print(f"Cycles per second: {bus_results['cycles_per_second']:.1f}")
        print(f"Errors detected: {len(bus_results['errors_detected'])}")
        print(f"Bus hangs: {len(bus_results['bus_hangs'])}")
        print(f"Status: {bus_results['status']}")
        
        if bus_results['errors_detected']:
            print(f"\n⚠️ BUS STRESS ERRORS:")
            for error in bus_results['errors_detected'][:10]:
                print(f"  {error}")
    
    elif args.ultimate_hunter:
        # Find NVMe device first
        nvme_devices = monitor.find_nvme_devices()
        if not nvme_devices:
            print("No NVMe devices found for ultimate error hunter")
            return
        
        target_device = args.device if args.device in nvme_devices else nvme_devices[0]
        
        print(f"\n🎯 ULTIMATE ERROR HUNTER TEST")
        print(f"Target device: {target_device}")
        print(f"Duration: 10 minutes (600 seconds)")
        print(f"This test runs ALL advanced techniques SIMULTANEOUSLY:")
        print(f"  • Heavy enumeration stress")
        print(f"  • Signal integrity stress") 
        print(f"  • Advanced bus stress")
        print(f"  • Real-time error monitoring")
        print(f"This is the most aggressive test possible!")
        print(f"Press Ctrl+C to abort if needed...\n")
        
        input("Press ENTER to start the ULTIMATE ERROR HUNTER...")
        
        ultimate_results = monitor.run_ultimate_error_hunter(target_device, duration=600)
        
        print(f"\n{'='*60}")
        print(f"🎯 ULTIMATE ERROR HUNTER RESULTS")
        print(f"{'='*60}")
        print(f"Total duration: {ultimate_results['total_time']:.1f}s")
        print(f"Overall status: {ultimate_results['status']}")
        print(f"Total errors detected: {len(ultimate_results['overall_errors'])}")
        
        # Show results from each phase
        for phase_name, phase_results in ultimate_results['phase_results'].items():
            if phase_results:
                phase_errors = len(phase_results.get('errors_detected', []))
                phase_status = phase_results.get('status', 'UNKNOWN')
                print(f"{phase_name.replace('_', ' ').title()}: {phase_status} ({phase_errors} errors)")
        
        # Show AER comparison
        before = ultimate_results['aer_before']
        after = ultimate_results['aer_after']
        before_total = before.get('correctable', 0) + before.get('uncorrectable', 0)
        after_total = after.get('correctable', 0) + after.get('uncorrectable', 0)
        print(f"AER Error Count: {before_total} → {after_total}")
        
        if ultimate_results['overall_errors']:
            print(f"\n⚠️ ALL ERRORS DETECTED:")
            for i, error in enumerate(ultimate_results['overall_errors'][:15], 1):
                print(f"  {i}. {error}")
            if len(ultimate_results['overall_errors']) > 15:
                print(f"  ... and {len(ultimate_results['overall_errors']) - 15} more errors")
        
        if ultimate_results['status'] == 'FAIL':
            print(f"\n❌ ULTIMATE ERROR HUNTER FOUND ISSUES!")
            print(f"This adapter has PCIe bus problems - DO NOT DEPLOY")
        else:
            print(f"\n✅ ULTIMATE ERROR HUNTER PASSED")
            print(f"This adapter survived the most aggressive testing possible")
    
    elif args.endurance:
        # Find NVMe device first
        nvme_devices = monitor.find_nvme_devices()
        if not nvme_devices:
            print("No NVMe devices found for endurance testing")
            return
        
        target_device = args.device if args.device in nvme_devices else nvme_devices[0]
        hours = args.endurance if args.endurance else 24
        
        print(f"\n⏰ EXTENDED ENDURANCE TEST")
        print(f"Target device: {target_device}")
        print(f"Duration: {hours} hours")
        print(f"Test phases: 8 different stress patterns in rotation")
        print(f"This test simulates WEEKS of production use!")
        print(f"The test will run continuously for {hours} hours")
        print(f"You can monitor progress in the log file")
        print(f"Press Ctrl+C to abort if needed...\n")
        
        print(f"Phases that will run:")
        print(f"  1. Thermal Soak - High Activity")
        print(f"  2. Enumeration Hammering") 
        print(f"  3. Mixed I/O Patterns")
        print(f"  4. Power State Cycling")
        print(f"  5. Concurrent Operations")
        print(f"  6. Reseat Simulation")
        print(f"  7. Sustained Load Test")
        print(f"  8. Recovery Testing")
        print(f"Each phase runs for ~{hours/8:.1f} hours\n")
        
        input("Press ENTER to start the extended endurance test...")
        
        endurance_results = monitor.run_endurance_test(target_device, hours=hours)
        
        print(f"\n{'='*60}")
        print(f"⏰ ENDURANCE TEST RESULTS")
        print(f"{'='*60}")
        print(f"Target duration: {endurance_results['target_duration_hours']:.1f} hours")
        print(f"Actual duration: {endurance_results['actual_duration_hours']:.1f} hours")
        print(f"Completion: {endurance_results['completion_percentage']:.1f}%")
        print(f"Total cycles: {endurance_results['total_cycles']}")
        print(f"Phases completed: {len(endurance_results['phases_completed'])}/8")
        
        total_errors = sum(len(errors) for errors in endurance_results['errors_by_phase'].values())
        print(f"Total errors: {total_errors}")
        print(f"Status: {endurance_results['status']}")
        
        # Show phase results
        print(f"\nPhase Results:")
        for phase in endurance_results['phases_completed']:
            print(f"  {phase['name']}: {phase['cycles']} cycles, {phase['errors']} errors, {phase['duration']/3600:.1f}h")
        
        if total_errors > 0:
            print(f"\n⚠️ ERRORS BY PHASE:")
            for phase_name, errors in endurance_results['errors_by_phase'].items():
                if errors:
                    print(f"  {phase_name}: {len(errors)} errors")
                    for error in errors[:3]:  # Show first 3 errors
                        print(f"    {error}")
                    if len(errors) > 3:
                        print(f"    ... and {len(errors) - 3} more")
        
        if endurance_results['status'] == 'FAIL':
            print(f"\n❌ ENDURANCE TEST FAILED")
            print(f"Adapter has reliability issues over extended operation")
        else:
            print(f"\n✅ ENDURANCE TEST PASSED")
            print(f"Adapter demonstrates excellent long-term reliability")
    
    elif args.burn_in:
        # Find NVMe device first
        nvme_devices = monitor.find_nvme_devices()
        if not nvme_devices:
            print("No NVMe devices found for burn-in testing")
            return
        
        target_device = args.device if args.device in nvme_devices else nvme_devices[0]
        cycles = args.burn_in if args.burn_in else 10000
        
        print(f"\n🔥 HIGH-CYCLE BURN-IN TEST")
        print(f"Target device: {target_device}")
        print(f"Cycles: {cycles:,}")
        print(f"Estimated time: ~{cycles/1000:.1f} hours (1000 cycles/hour)")
        print(f"This test runs rapid operations to stress the device")
        print(f"Perfect for detecting early failure modes")
        print(f"Press Ctrl+C to abort if needed...\n")
        
        input("Press ENTER to start the burn-in test...")
        
        burn_in_results = monitor.run_burn_in_test(target_device, cycles=cycles)
        
        print(f"\n{'='*60}")
        print(f"🔥 BURN-IN TEST RESULTS")
        print(f"{'='*60}")
        print(f"Target cycles: {burn_in_results['target_cycles']:,}")
        print(f"Completed cycles: {burn_in_results['completed_cycles']:,}")
        print(f"Completion: {(burn_in_results['completed_cycles']/burn_in_results['target_cycles'])*100:.1f}%")
        print(f"Errors detected: {len(burn_in_results['errors_detected'])}")
        print(f"Status: {burn_in_results['status']}")
        
        if burn_in_results['cycle_times']:
            avg_cycle_time = sum(burn_in_results['cycle_times']) / len(burn_in_results['cycle_times'])
            total_time_hours = sum(burn_in_results['cycle_times']) / 3600
            cycles_per_hour = burn_in_results['completed_cycles'] / total_time_hours if total_time_hours > 0 else 0
            print(f"Average cycle time: {avg_cycle_time:.3f}s")
            print(f"Total time: {total_time_hours:.1f} hours")
            print(f"Cycles per hour: {cycles_per_hour:.0f}")
        
        if burn_in_results['errors_detected']:
            print(f"\n⚠️ ERRORS DETECTED:")
            for i, error in enumerate(burn_in_results['errors_detected'][:10], 1):
                print(f"  {i}. {error}")
            if len(burn_in_results['errors_detected']) > 10:
                print(f"  ... and {len(burn_in_results['errors_detected']) - 10} more errors")
        
        # Show AER progression
        if burn_in_results['aer_progression']:
            print(f"\nAER Error Progression:")
            for snapshot in burn_in_results['aer_progression']:
                cycle = snapshot['cycle']
                aer = snapshot['aer_status']
                total_errors = aer.get('correctable', 0) + aer.get('uncorrectable', 0)
                print(f"  Cycle {cycle:,}: {total_errors} AER errors")
        
        if burn_in_results['status'] == 'FAIL':
            print(f"\n❌ BURN-IN TEST FAILED")
            print(f"Adapter failed during high-cycle testing")
        else:
            print(f"\n✅ BURN-IN TEST PASSED")
            print(f"Adapter survived high-cycle stress testing")
    
    elif args.continuous_reseat:
        # Find NVMe device first
        nvme_devices = monitor.find_nvme_devices()
        if not nvme_devices:
            print("No NVMe devices found for continuous reseat testing")
            return
        
        target_device = args.device if args.device in nvme_devices else nvme_devices[0]
        
        print(f"\n🔄 CONTINUOUS RESEAT TEST (10 MINUTES)")
        print(f"Target device: {target_device}")
        print(f"Duration: 10 minutes (600 seconds)")
        print(f"Test: Continuous disconnect/connect cycles")
        print(f"Focus: Pure enumeration stability (no stress testing)")
        print(f"Goal: Maximum number of reseat cycles to test connection reliability")
        print(f"WARNING: Device will be removed/added repeatedly!")
        print(f"Press Ctrl+C to abort if needed...\n")
        
        input("Press ENTER to start continuous reseat testing...")
        
        reseat_results = monitor.run_continuous_reseat_test(target_device, duration=600)
        
        print(f"\n{'='*60}")
        print(f"🔄 CONTINUOUS RESEAT TEST RESULTS")
        print(f"{'='*60}")
        print(f"Duration: {reseat_results['total_time']:.1f} seconds")
        print(f"Cycles attempted: {reseat_results['cycles_attempted']}")
        print(f"Cycles successful: {reseat_results['cycles_successful']}")
        print(f"Success rate: {reseat_results['success_rate']:.1f}%")
        print(f"Cycles per minute: {reseat_results['cycles_per_minute']:.1f}")
        print(f"Average cycle time: {reseat_results['avg_cycle_time']:.2f}s")
        print(f"")
        print(f"Failure breakdown:")
        print(f"  Remove failures: {reseat_results['remove_failures']}")
        print(f"  Rescan failures: {reseat_results['rescan_failures']}")
        print(f"  Enumeration failures: {reseat_results['enumeration_failures']}")
        print(f"  Total errors: {len(reseat_results['errors_detected'])}")
        
        if reseat_results['errors_detected']:
            print(f"\n⚠️ ERRORS DETECTED:")
            for i, error in enumerate(reseat_results['errors_detected'][:10], 1):
                print(f"  {i}. {error}")
            if len(reseat_results['errors_detected']) > 10:
                print(f"  ... and {len(reseat_results['errors_detected']) - 10} more errors")
        
        # Determine final assessment
        if reseat_results['success_rate'] >= 95:
            print(f"\n✅ EXCELLENT CONNECTION STABILITY")
            print(f"Success rate ≥ 95% - Adapter has very reliable connections")
        elif reseat_results['success_rate'] >= 90:
            print(f"\n⚠️ GOOD CONNECTION STABILITY")
            print(f"Success rate ≥ 90% - Adapter is generally reliable")
        elif reseat_results['success_rate'] >= 80:
            print(f"\n⚠️ MARGINAL CONNECTION STABILITY")
            print(f"Success rate < 90% - Adapter may have connection issues")
        else:
            print(f"\n❌ POOR CONNECTION STABILITY")
            print(f"Success rate < 80% - Adapter has significant connection problems")
            print(f"DO NOT DEPLOY - Return to workshop")
        
        print(f"{'='*60}")
    
    elif args.reseat_test:
        # Find NVMe device first
        nvme_devices = monitor.find_nvme_devices()
        if not nvme_devices:
            print("No NVMe devices found for reseat testing")
            return
        
        target_device = args.device if args.device in nvme_devices else nvme_devices[0]
        cycles = args.reseat_test if args.reseat_test else 3
        
        print(f"\n🔄 RESEAT SIMULATION TEST")
        print(f"Target device: {target_device}")
        print(f"Cycles: {cycles}")
        print(f"This test simulates physically removing and reseating the adapter")
        print(f"WARNING: This will temporarily remove the device from the system!")
        print(f"Press Ctrl+C to abort if needed...\n")
        
        input("Press ENTER to start the reseat simulation...")
        
        reseat_results = monitor.simulate_reseat_cycle(target_device, cycles=cycles)
        
        print(f"\n{'='*60}")
        print(f"🔄 RESEAT SIMULATION RESULTS")
        print(f"{'='*60}")
        print(f"Cycles completed: {reseat_results['cycles_completed']}/{reseat_results['cycles_requested']}")
        print(f"Device disappeared: {len(reseat_results['device_disappeared'])} times")
        print(f"Device reappeared: {len(reseat_results['device_reappeared'])} times")
        print(f"Errors detected: {len(reseat_results['errors_detected'])}")
        print(f"Status: {reseat_results['status']}")
        
        if reseat_results['errors_detected']:
            print(f"\n⚠️ ERRORS:")
            for error in reseat_results['errors_detected']:
                print(f"  {error}")
        
        if reseat_results['status'] == 'FAIL':
            print(f"\n❌ RESEAT TEST FAILED - Adapter has connection issues")
        else:
            print(f"\n✅ RESEAT TEST PASSED - Adapter handles reseating well")
    
    elif args.back_to_back:
        # Find NVMe device first
        nvme_devices = monitor.find_nvme_devices()
        if not nvme_devices:
            print("No NVMe devices found for back-to-back testing")
            return
        
        target_device = args.device if args.device in nvme_devices else nvme_devices[0]
        rounds = args.back_to_back if args.back_to_back else 3
        
        print(f"\n🔄⚡ BACK-TO-BACK RESEAT + STRESS TEST")
        print(f"Target device: {target_device}")
        print(f"Rounds: {rounds}")
        print(f"Each round: Reseat simulation + 2-minute stress test")
        print(f"Total time: ~{rounds * 4} minutes")
        print(f"This is the ULTIMATE connection stability test!")
        print(f"Press Ctrl+C to abort if needed...\n")
        
        input("Press ENTER to start back-to-back testing...")
        
        b2b_results = monitor.run_back_to_back_stress(target_device, rounds=rounds, stress_duration=120)
        
        print(f"\n{'='*60}")
        print(f"🔄⚡ BACK-TO-BACK TEST RESULTS")
        print(f"{'='*60}")
        print(f"Rounds completed: {b2b_results['rounds_completed']}/{b2b_results['rounds_requested']}")
        print(f"Overall status: {b2b_results['status']}")
        print(f"Total errors: {len(b2b_results['overall_errors'])}")
        
        # Show results for each round
        for round_result in b2b_results['round_results']:
            round_num = round_result['round']
            round_status = round_result['status']
            print(f"\nRound {round_num}: {round_status}")
            
            if round_result['reseat_result']:
                reseat_errors = len(round_result['reseat_result']['errors_detected'])
                print(f"  Reseat: {reseat_errors} errors")
            
            if round_result['stress_result']:
                stress_errors = len(round_result['stress_result']['errors_detected'])
                print(f"  Stress: {stress_errors} errors")
        
        if b2b_results['overall_errors']:
            print(f"\n⚠️ OVERALL ERRORS:")
            for error in b2b_results['overall_errors']:
                print(f"  {error}")
        
        if b2b_results['status'] == 'FAIL':
            print(f"\n❌ BACK-TO-BACK TEST FAILED")
            print(f"Adapter has stability issues - DO NOT DEPLOY")
        else:
            print(f"\n✅ BACK-TO-BACK TEST PASSED")
            print(f"Adapter is extremely robust - SAFE TO DEPLOY")
    
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
          