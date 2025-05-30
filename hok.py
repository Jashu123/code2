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

    def initialize_test(self):
        """
        Initialize test resources
        """
        super(BlockIOEngineWorkload, self).initialize_test()
        
        # Check drive count and stop if 0
        try:
            if hasattr(self.dut, 'get_micron_drive_count'):
                micron_drive_count = self.dut.get_micron_drive_count()
            elif hasattr(self.dut, 'get_device_count'):
                micron_drive_count = self.dut.get_device_count()
            else:
                micron_drive_count = len(self.dut.controller_list) if hasattr(self.dut, 'controller_list') and self.dut.controller_list else 0
            
            if micron_drive_count == 0:
                self.logger.info(f"Stopping test: Micron drive count is {micron_drive_count}")
                raise TestException("Test terminated: No Micron drives detected")
                
        except Exception as e:
            if "TestException" in str(type(e)):
                raise
            else:
                self.logger.warning(f"Could not check drive count: {e}")
        
        if self.options["ioengine_block_pretrim"]:
            self.pretrim_policy = True

    def test(self):
        """
        Main test body
        """
        config = copy.deepcopy(self.curr_config.__dict__)
        if self.options["ioengine_random_slba"]:
            self.ioengine_random_slba = random.randint(0, 95)
            self.ioengine_random_slba = str(self.ioengine_random_slba) + "%"
            self.logger.info(f"Random SLBA Selected: {self.ioengine_random_slba}")

        if self.options["ioengine_prefill"] and self.prefill_count < self.options["ioengine_prefill_repeat"]:
            self.disable_periodic_actions(stop_condition_enabled=True)
            self.run_prefill()
            self.enable_periodic_actions()

        if self.pretrim_policy:
            self.disable_periodic_actions(stop_condition_enabled=True)
            self.run_pretrim()
            self.enable_periodic_actions()

        if "prefill" in config:
            self.prefill_policy = config.pop('prefill')
            if self.prefill_policy:
                self.run_prefill()

        self.run_workload()
        if not self.options["disable_io_engine_verify"]:
            if self.options["enable_be_flow"]:
                error_injection.auto_inject_disable_eif(dut=self.dut)
                error_injection.disable_eif(self.dut)
            self.run_verify()
            if self.options["enable_be_flow"]:
                error_injection.auto_inject_enable_eif(dut=self.dut)
                error_injection.enable_eif(self.dut)

    def run_workload(self):
        """
        Method to run the workload
        """
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
        self.run()

    def run_verify(self):
        """
        Method to run read verify
        """
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
                self.run()
        self.logger.info("Sleeping 20 seconds to cleanup")
        self.dut.sleep(20)

    def run_pretrim(self):
        """
        Method to pretrim the drive
        """
        if self.pretrim_policy:
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
            self.run()

    def run_prefill(self):
        """
        Method to prefill the drive
        """
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
            self.configure(config)
            self.log_step("--- Loop inside Starting Prefill!! ---")
            self.run()
            self.prefill_count = self.prefill_count + 1

    def cleanup_test(self):
        """
        Perform any necessary clean-up
        """
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