"""
@package test.integration.test_scripts.workloads.blockIO.block_io_engine_workload

@brief Verify that device is able to handle seq/random block IOs

@author Naveen Kumar Vemulapalli

**Related Jira**: https://jira.micron.com/jira/browse/FTEVAL-9384

Steps
-----------------------------------------------------------------------------------------------------------------
    1. Setup workloads configuration
    2. Run workload

Arguments
-----------------------------------------------------------------------------------------------------------------
    - None
Depends On
-----------------------------------------------------------------------------------------------------------------
**VS dependencies:**
    - None

**Other Dependencies:**
    - None
"""

# standard library imports
# third-party imports
# N/A
import copy
import random
import threading
import time
# application specific imports
from common_infrastructure.ioengine_test_instance import IOEngineTestInstance
from common_infrastructure.test_exception import TestException
# from common_infrastructure.periodic_action_manager import PAM
from common_libs.eif import error_injection
from common_libs.frontend import namespace_manager


class BlockIOEngineWorkload(IOEngineTestInstance):
    """
    Test to ensure data integrity on a zone after performing writes to the zone.
    """

    def __init__(self, test_name=None, test_config=None, variations=None, test_type="Test", controller_index=0, num_variations_to_pick=-1, **kwargs):
        super(BlockIOEngineWorkload, self).__init__(test_name=test_name, test_config=test_config, variations=variations, test_type=test_type,
                                                    num_variations_to_pick=num_variations_to_pick, controller_index=controller_index, **kwargs)
        self.verify_policy = None
        self.read_percent = 100
        self.ioengine_random_slba = None
        self.prefill_count = 0
        self.pretrim_policy = False
        
        # Drive count monitoring attributes
        self._stop_monitoring = False
        self._stop_test = False
        self.monitor_thread = None
        
        # Configuration options for drive count check
        self.stop_on_single_drive = self.options.get("stop_on_single_drive", True)  # Default to True for safety
        self.monitor_drive_count_during_test = self.options.get("monitor_drive_count", True)  # Enable continuous monitoring

    def initialize_test(self):
        """
        Initialize test resources
        """
        super(BlockIOEngineWorkload, self).initialize_test()
        
        # Primary drive count check during initialization
        if self.stop_on_single_drive:
            try:
                micron_drive_count = self._get_micron_drive_count()
                self.logger.info(f"Current Micron drive count: {micron_drive_count}")
                
                if micron_drive_count == 1:
                    self.logger.warning(f"Test termination condition met: Micron drive count is {micron_drive_count}")
                    raise TestException("Test stopped: Only 1 Micron drive detected. This may indicate a drive failure or unexpected configuration.")
                elif micron_drive_count == 0:
                    self.logger.error("No Micron drives detected!")
                    raise TestException("Test stopped: No Micron drives found")
                else:
                    self.logger.info(f"Drive count check passed: {micron_drive_count} Micron drives detected")
            except Exception as e:
                self.logger.error(f"Error checking drive count: {e}")
                if "TestException" in str(type(e)):
                    raise  # Re-raise TestException
                else:
                    self.logger.warning("Could not verify drive count, proceeding with test")
        
        if self.options["ioengine_block_pretrim"]:
            self.pretrim_policy = True

    def _get_micron_drive_count(self):
        """
        Helper method to get Micron drive count with error handling
        """
        try:
            # Try different methods to get drive count
            if hasattr(self.dut, 'get_micron_drive_count'):
                return self.dut.get_micron_drive_count()
            elif hasattr(self.dut, 'get_device_count'):
                return self.dut.get_device_count()
            elif hasattr(self.dut, 'enumerate_drives'):
                drives = self.dut.enumerate_drives()
                return len(drives) if drives else 0
            else:
                # Fallback: check if we can access the device
                if hasattr(self.dut, 'controller_list') and self.dut.controller_list:
                    return len(self.dut.controller_list)
                else:
                    self.logger.warning("Cannot determine drive count - no suitable method found")
                    return -1  # Unknown count
        except Exception as e:
            self.logger.error(f"Error getting drive count: {e}")
            return -1

    def _start_drive_monitoring(self):
        """
        Start background thread to monitor drive count during test execution
        """
        if not self.monitor_drive_count_during_test:
            return
            
        def monitor_drive_count():
            """Background monitoring function"""
            check_interval = 30  # Check every 30 seconds
            failure_count = 0
            max_failures = 3
            
            self.logger.info("Starting drive count monitoring thread")
            
            while not self._stop_monitoring and not self._stop_test:
                try:
                    drive_count = self._get_micron_drive_count()
                    
                    if drive_count == 1:
                        self.logger.critical("ALERT: Drive count dropped to 1 during test execution!")
                        self.logger.critical("This may indicate a drive failure. Stopping test immediately.")
                        self._stop_test = True
                        break
                    elif drive_count == 0:
                        self.logger.critical("ALERT: No drives detected during test execution!")
                        self._stop_test = True
                        break
                    elif drive_count == -1:
                        failure_count += 1
                        if failure_count >= max_failures:
                            self.logger.error("Multiple failures checking drive count. Stopping monitoring.")
                            break
                    else:
                        failure_count = 0  # Reset on successful check
                        self.logger.debug(f"Drive count check: {drive_count} drives detected")
                    
                    time.sleep(check_interval)
                    
                except Exception as e:
                    failure_count += 1
                    self.logger.error(f"Error in drive monitoring thread: {e}")
                    if failure_count >= max_failures:
                        self.logger.error("Too many monitoring failures. Stopping drive monitoring.")
                        break
                    time.sleep(check_interval)
            
            self.logger.info("Drive count monitoring thread stopped")
        
        self.monitor_thread = threading.Thread(target=monitor_drive_count, daemon=True)
        self.monitor_thread.start()

    def _stop_drive_monitoring(self):
        """
        Stop the drive monitoring thread
        """
        self._stop_monitoring = True
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)

    def _check_stop_condition(self):
        """
        Check if test should be stopped due to drive count condition
        """
        if self._stop_test:
            self.logger.critical("Test stopped due to drive count condition")
            raise TestException("Test terminated: Drive count monitoring detected critical condition")

    def test(self):
        """
        Main test body
        """
        # Start drive monitoring if enabled
        self._start_drive_monitoring()
        
        try:
            config = copy.deepcopy(self.curr_config.__dict__)
            if self.options["ioengine_random_slba"]:
                self.ioengine_random_slba = random.randint(0, 95)
                self.ioengine_random_slba = str(self.ioengine_random_slba) + "%"
                self.logger.info(f"Random SLBA Selected: {self.ioengine_random_slba}")

            # Check stop condition before prefill
            self._check_stop_condition()

            if self.options["ioengine_prefill"] and self.prefill_count < self.options["ioengine_prefill_repeat"]:
                self.disable_periodic_actions(stop_condition_enabled=True)
                self.run_prefill()
                self.enable_periodic_actions()

            # Check stop condition before pretrim
            self._check_stop_condition()

            if self.pretrim_policy:
                self.disable_periodic_actions(stop_condition_enabled=True)
                self.run_pretrim()
                self.enable_periodic_actions()

            # Check stop condition before prefill policy
            self._check_stop_condition()

            if "prefill" in config:
                self.prefill_policy = config.pop('prefill')
                if self.prefill_policy:
                    self.run_prefill()

            # Check stop condition before main workload
            self._check_stop_condition()

            self.run_workload()
            
            # Check stop condition before verify
            self._check_stop_condition()
            
            if not self.options["disable_io_engine_verify"]:
                if self.options["enable_be_flow"]:
                    error_injection.auto_inject_disable_eif(dut=self.dut)
                    error_injection.disable_eif(self.dut)
                self.run_verify()
                if self.options["enable_be_flow"]:
                    error_injection.auto_inject_enable_eif(dut=self.dut)
                    error_injection.enable_eif(self.dut)
                    
        finally:
            # Always stop monitoring when test completes
            self._stop_drive_monitoring()

    def run_workload(self):
        """
        Method to run the workload
        """
        # Check stop condition before starting workload
        self._check_stop_condition()
        
        self.log_step("Starting Workload!!")
        if self.curr_config.nsid is None:
            nsm_dict = self.test_fixture.ns_dict_list[self.controller_index]
            nsid_list = namespace_manager.get_attached_nsid_list(nsm_dict, self.controller_index)
            if len(nsid_list):
                self.curr_config.nsid = nsid_list[0]
            else:
                raise TestException("No valid namespaces found on Controller {}".format(self.controller_index))
        config = copy.deepcopy(self.curr_config.__dict__)
        if 'verify_policy' in config:
            self.verify_policy = config.pop('verify_policy')
        if 'read_percent' in config:
            self.read_percent = config.pop('read_percent')
        if self.options["ioengine_random_slba"]:
            config['slba'] = self.ioengine_random_slba
        if not self.options["randomize_wl"]:
            self.configure(config)  # End of initialize_test()
        else:
            self.configure_randomize(config)
            
        # Final check before running
        self._check_stop_condition()
        self.run()

    def run_verify(self):
        """
        Method to run read verify
        """
        # Check stop condition before verify
        self._check_stop_condition()
        
        size = self.curr_config.size
        if self.verify_policy:
            if self.verify_policy == 'read_range':
                wltype = "sequential" if self.read_percent == 100 else "random"
                suffix = ''
                if self.curr_config.size[-1] in ('N', '%'):
                    suffix = self.curr_config.size[-1]
                    size = self.curr_config.size[:-1]
                size = int(size) * self.read_percent // 100
                size = str(size) + suffix
                self.logger.info("Running {} read of size {} to verify".format(wltype, size))
                config = copy.deepcopy(self.curr_config.__dict__)
                config_update = dict(wltype=wltype, workload='read', size=size, rwmixread=100, blocksize='max', bssplit="")
                config.update(config_update)
                if self.options["ioengine_random_slba"]:
                    config['slba'] = self.ioengine_random_slba
                if "bsrange" in config:
                    config.pop('bsrange')
                self.configure(config)
                
                # Check one more time before running verify
                self._check_stop_condition()
                self.run()
                
        self.logger.info("Sleeping 20 seconds to cleanup")
        self.dut.sleep(20)

    def run_pretrim(self):
        """
        Method to pretrim the drive
        """
        if self.pretrim_policy:
            # Check stop condition before pretrim
            self._check_stop_condition()
            
            self.log_step("--- Starting Pre-Trim!! ---")
            if self.curr_config.nsid is None:
                nsm_dict = self.test_fixture.ns_dict_list[self.controller_index]
                nsid_list = namespace_manager.get_attached_nsid_list(nsm_dict, self.controller_index)
                if len(nsid_list):
                    self.curr_config.nsid = nsid_list[0]
                else:
                    raise TestException("No valid namespaces found on Controller {}".format(self.controller_index))
            config = copy.deepcopy(self.curr_config.__dict__)
            config_update = dict(wltype="sequential", workload='trim', size="100%", slba=0, blocksize="max", bsrange="", bssplit="", verify_policy="no_read", fdp=0, runtime=0)
            config.update(config_update)
            self.configure(config)
            
            # Final check before running pretrim
            self._check_stop_condition()
            self.run()

    def run_prefill(self):
        """
        Method to prefill the drive
        """
        # Check stop condition before prefill
        self._check_stop_condition()
        
        self.log_step("--- Starting Prefill!! ---")
        if self.curr_config.nsid is None:
            nsm_dict = self.test_fixture.ns_dict_list[self.controller_index]
            nsid_list = namespace_manager.get_attached_nsid_list(nsm_dict, self.controller_index)
            if len(nsid_list):
                self.curr_config.nsid = nsid_list[0]
            else:
                raise TestException("No valid namespaces found on Controller {}".format(self.controller_index))
        config = copy.deepcopy(self.curr_config.__dict__)

        size = config["size"]
        slba = config["slba"]
        if self.options["ioengine_prefill"]:
            size = str(self.options["ioengine_prefill_percentage"]) + '%'
            if self.options["ioengine_prefill_percentage"] == 100:
                slba = '0'

        config_update = dict(wltype="sequential", workload='write', size=size, slba=slba, blocksize="max", bsrange="", bssplit="", verify_policy="")
        if self.options["ioengine_random_slba"]:
            config['slba'] = self.ioengine_random_slba
        if self.options["ioengine_prefill_time"]:
            config_update.update(runtime=self.options["ioengine_prefill_time"])
        config.update(config_update)
        for _ in range(self.options["ioengine_prefill_repeat"]):
            # Check stop condition before each prefill iteration
            self._check_stop_condition()
            
            self.configure(config)
            self.log_step("--- Loop inside Starting Prefill!! ---")
            self.run()
            self.prefill_count = self.prefill_count + 1

    def cleanup_test(self):
        """
        Perform any necessary clean-up
        """
        # Stop drive monitoring
        self._stop_drive_monitoring()
        
        # Log final drive count for reference
        try:
            final_drive_count = self._get_micron_drive_count()
            self.logger.info(f"Final drive count at test cleanup: {final_drive_count}")
        except Exception as e:
            self.logger.warning(f"Could not get final drive count: {e}")
        
        super(BlockIOEngineWorkload, self).cleanup_test()  # End of cleanup_test()


def main_test():
    """
    Execute test
    """
    test = BlockIOEngineWorkload()
    test.execute()


# End of main_test()


if __name__ == "__main__":
    main_test()