import random
import math
import time

from common_infrastructure.test_instance import TestInstance
from common_infrastructure.test_exception import TestException
from common_libs.cs import low_level_format
from common_libs.ftl import defect_management


class OcpSmartAvailableSpare0(TestInstance):
    """
    @class SmartExtendCriticalWarning
    @brief This class is to test target die will be retired when BB count in the die reaches retirement threshold.
    @supplied by class TestInstance.
    """

    def __init__(self):
        """
        @fn __init__
        @brief Initialization of the test.
        @return This method returns no values.
        @exception This method raises no exceptions.
        """
        super(OcpSmartAvailableSpare0, self).__init__()
        self.log_page = None
        self.vs_cmds = None
        self.common_svc = None
        self.nvme_commands = None
        self.blocks_per_plane = None
        self.planes_per_lun = None
        self.namespace_id = None
        self.block_management = None
        self.media_operation = None
        self.cfg_ftl = None
        self.bb_list = None
        self.non_gbb_list = None
        self.bb_management = None
        self.lun_cnt = None
        self.address = None
        self.retired_block_count_threshold = None
        self.free_blk_stripe_list = None
        self.device_discovery = None
        self.garbage_blk_stripe_list = None
        self.ftl_cfg = None

    def initialize_test(self):
        """
        @fn initialize_test
        @brief Do some initialization for the test.
        @param This method takes no values.
        @return This method returns no values.
        @exception This method raises no exceptions.
        """
        super(OcpSmartAvailableSpare0, self).initialize_test()
        self.log_page = self.lib.LogPage
        self.nvme_commands = self.lib.NvmeCommands
        self.vs_cmds = self.lib.VsCmds
        self.common_svc = self.lib.CommonService
        self.device_discovery = self.lib.DeviceDiscovery
        self.bb_management = self.lib.BadBlockManagement
        self.ftl_cfg = self.lib.DeviceDiscovery.ftl_cfg
        self.cfg_ftl = self.cfg.ftl
        self.address = self.lib.Address
        self.media_operation = self.lib.MediaOperation
        self.block_management = self.lib.BlockManagement
        self.lun_cnt = self.ftl_cfg.lun_cnt
        self.free_blk_stripe_list = self.block_management.free_block_stripe_list
        self.garbage_blk_stripe_list = self.block_management.garbage_block_stripe_list
        self.retired_block_count_threshold = self.vs_cmds.get_ftl_configuration().retired_block_count_threshold
        self.blocks_per_plane = self.ftl_cfg.blocks_per_plane
        self.planes_per_lun = self.ftl_cfg.planes_per_lun
        self.namespace_id = 1
        self.args.check_high_concern_event = False

    def get_bb_desc_list(self, available_spare):
        """
        @fn get_bb_desc_list
        @brief The detail steps to build the test case.
        @param available_spare
        @return This method returns no values.
        @exception This method raises no exceptions.
        """
        non_gbb_in_usr_block = 0
        self.bb_list = self.bb_management.get_defect_list(use_raw_type=False)
        current_bb_count = len(self.bb_list.bibb_list) + len(self.bb_list.otp_bb_list) + len(
            self.bb_list.fwres_list) + len(self.bb_list.gbb_list)
        self.logger.info("Currently {} BB was detected: BIBB: {}, OTP BB: {}, FW Res: {}, GBB: {}"
                         .format(current_bb_count, len(self.bb_list.bibb_list), len(self.bb_list.otp_bb_list),
                                 len(self.bb_list.fwres_list), len(self.bb_list.gbb_list)))
        self.logger.info("retired_block_count_threshold = %d" % self.retired_block_count_threshold)
        for bb_addr in self.bb_list.otp_bb_list + self.bb_list.bibb_list + self.bb_list.fwres_list:
            if self.address.new_fla(bb_addr).block_stripe >= self.ftl_cfg.usr_blk_stp_id_st:
                non_gbb_in_usr_block += 1
        self.logger.info("non_gbb_in_usr_block = {}".format(non_gbb_in_usr_block))

        if self.lun_cnt >= self.cfg.dieFail.dr_lun_threshold:
            bb_desc_list = self.get_bb_desc_list_for_die_retire(available_spare, non_gbb_in_usr_block)
        else:
            bb_desc_list = self.get_bb_desc_list_for_no_die_retire(available_spare, non_gbb_in_usr_block)
        return bb_desc_list

    def get_bb_desc_list_for_no_die_retire(self, available_spare, non_gbb_in_usr_block):
        """
        @fn get_bb_desc_list_for_no_die_retire
        @brief The detail steps to build the test case.
        @param This method takes no values.
        @return This method returns no values.
        @exception This method raises no exceptions.
        """
        bb_desc_list = []
        self.non_gbb_list = self.bb_list.otp_bb_list + self.bb_list.bibb_list + self.bb_list.fwres_list
        lun_non_gbb_dict = {i: 0 for i in range(self.lun_cnt)}
        for index in range(len(self.non_gbb_list)):
            fla_ins = self.address.new_fla(fla=self.non_gbb_list[index])
            if fla_ins.block_stripe >= self.ftl_cfg.usr_blk_stp_id_st:
                lun_id = fla_ins.physical_lun_id
                lun_non_gbb_dict[lun_id] += 1
        self.logger.info("lun_non_gbb_dict is {}".format(lun_non_gbb_dict))

        total_gbb_num = self.retired_block_count_threshold - non_gbb_in_usr_block
        total_gbb_num_to_mark = total_gbb_num
        remain_bb = total_gbb_num_to_mark % self.lun_cnt
        lun_gbb_dict = {i: 0 for i in range(self.lun_cnt)}
        for lun_id in range(self.lun_cnt):
            if remain_bb > 0:
                lun_gbb_dict[lun_id] = total_gbb_num_to_mark // self.lun_cnt - lun_non_gbb_dict[lun_id] + 1
                remain_bb -= 1
            else:
                lun_gbb_dict[lun_id] = total_gbb_num_to_mark // self.lun_cnt - lun_non_gbb_dict[lun_id]

        self.logger.info("lun_gbb_dict is {}".format(lun_gbb_dict))
        self.logger.info("total_gbb_num is {}, total_gbb_num_to_mark is {}".format(total_gbb_num, total_gbb_num_to_mark))

        total_mark_gbb_num = 0
        for lun_id in range(self.lun_cnt):
            mark_gbb_num_in_lun = 0
            self.logger.info("before next lun, len(bb_desc_list) is %s" % len(bb_desc_list))
            self.logger.info("lun_id is %d" % lun_id)
            for plane in range(self.planes_per_lun):
                for block_upper in self.garbage_blk_stripe_list + self.free_blk_stripe_list:
                    if block_upper < self.ftl_cfg.usr_blk_stp_id_st:
                        continue

                    fla = self.address.fla_combine(page=0, plane=plane, lun_id=lun_id, block_stripe=block_upper)
                    fla_ins = self.address.new_fla(fla=fla)
                    status = self.block_management.get_block_stripe_info(bsid=block_upper)["Status"]

                    if (not fla_ins.is_bb) and (status == "Garbage" or status == "Free"):
                        bb_desc_list.append([fla_ins.ch, fla_ins.ce, fla_ins.lun, fla_ins.block_plane, 1, 0])
                        mark_gbb_num_in_lun += 1
                        total_mark_gbb_num += 1

                        if mark_gbb_num_in_lun >= lun_gbb_dict[lun_id]:
                            self.logger.info("mark_gbb_num_in_lun {} reach {}".format(mark_gbb_num_in_lun, lun_gbb_dict[lun_id]))
                            break
                if mark_gbb_num_in_lun >= lun_gbb_dict[lun_id]:
                    self.logger.info("mark_gbb_num_in_lun {} reach {}".format(mark_gbb_num_in_lun, lun_gbb_dict[lun_id]))
                    break

        self.logger.info("len(bb_desc_list) = {}".format(len(bb_desc_list)))
        return bb_desc_list

    def get_bb_desc_list_for_die_retire(self, available_spare, non_gbb_in_usr_block):
        """
        @fn get_bb_desc_list_for_die_retire
        @brief The detail steps to build the test case.
        @param This method takes no values.
        @return This method returns no values.
        @exception This method raises no exceptions.
        """
        bb_desc_list = []
        self.non_gbb_list = self.bb_list.otp_bb_list + self.bb_list.bibb_list + self.bb_list.fwres_list

        lun_non_gbb_dict = {i: 0 for i in range(self.lun_cnt)}
        for index in range(len(self.non_gbb_list)):
            fla_ins = self.address.new_fla(fla=self.non_gbb_list[index])
            lun_id = fla_ins.physical_lun_id
            lun_non_gbb_dict[lun_id] += 1
        self.logger.info("lun_non_gbb_dict is {}".format(lun_non_gbb_dict))

        bad_die_with_ftl_bs = [lun_id for lun_id in self.ftl_cfg.bad_die_array
                               if lun_id < self.ftl_cfg.lun_max_cnt_per_lun_stripe]
        total_gbb_num = self.retired_block_count_threshold - non_gbb_in_usr_block - len(
            self.ftl_cfg.bad_die_array) * (self.ftl_cfg.planes_per_lun * self.ftl_cfg.blocks_per_plane) \
                        + len(bad_die_with_ftl_bs) * (self.ftl_cfg.planes_per_lun * self.ftl_cfg.ftl_bs_cnt)
        total_gbb_to_mark = total_gbb_num
        self.logger.info("total_gbb_num is {}, total_gbb_to_mark is {}".format(total_gbb_num, total_gbb_to_mark))

        die_retire_threshold = self.ftl_cfg.die_retirement_threshold
        die_retire_count = math.ceil(total_gbb_to_mark / (self.ftl_cfg.planes_per_lun * self.ftl_cfg.blocks_per_plane)) + 1
        self.logger.info("die_retire_count = {} die_retire_threshold = {}".format(die_retire_count, die_retire_threshold))
        target_lun_list = list()
        good_lun_list = list(self.ftl_cfg.good_lun_id_list)
        self.logger.info("lun_list = {}".format(good_lun_list))
        mark_bb_lun_dict = dict()
        for _ in range(die_retire_count):
            self.logger.info("Choose a random Die for the test.")
            while True:
                target_lun = random.choice(good_lun_list)
                if target_lun not in target_lun_list:
                    target_lun_list.append(target_lun)
                    break
            channel, chip_enable, lun = self.address.get_ch_ce_lun_from_lun_id(target_lun)
            self.logger.info("Selected Target Die %d Info: channel %d, chip_enable %d physical_lun_id %d" % (target_lun,
                                                                                                             channel,
                                                                                                             chip_enable,
                                                                                                             lun))
            good_lun_list.remove(target_lun)
            lun_goodblock_count = defect_management.get_number_of_good_blocks_remaining_per_lun(self.dut, channel,
                                                                                                chip_enable, lun)
            self.logger.info("For target Die %d, now lun_goodblock_count %d, die_retire_threshold %d" % (target_lun,
                                                                                                         lun_goodblock_count,
                                                                                                         die_retire_threshold))
            blocks_to_markbb_in_lun_x = die_retire_threshold + 5
            self.logger.info(
                "For target Die {}, needs to mark {} bb with 5 BB margin to make Die Failure".format(target_lun,
                                                                                                      blocks_to_markbb_in_lun_x))
            target_blk_list = self.block_management.free_block_stripe_list + self.block_management.garbage_block_stripe_list
            target_blk_list.sort()
            target_blk_list.reverse()
            self.logger.info("Get {} BB to mark in targrt_lun: {}.".format(blocks_to_markbb_in_lun_x,
                                                                           target_lun))
            set_bb_list = []
            lun_stripe = target_lun // self.ftl_cfg.lun_max_cnt_per_lun_stripe
            target_blk_list_filter = [bs_id for bs_id in target_blk_list if
                                      bs_id in range(self.blocks_per_plane * lun_stripe,
                                                     self.blocks_per_plane * (lun_stripe + 1))]
            self.logger.info("Target Lun_Id {}: BS List = {}".format(target_lun, target_blk_list_filter))
            i = 0
            for target_blk in target_blk_list_filter:
                flag = False
                for plane in range(self.planes_per_lun):
                    combine_fla = self.address.fla_combine(fla_src=0, page=0, lun_id=target_lun, plane=plane,
                                                           block_stripe=target_blk)
                    fla_ins = self.address.new_fla(combine_fla)
                    if not fla_ins.is_bb:
                        bb_desc_list.append([fla_ins.ch, fla_ins.ce, fla_ins.lun, fla_ins.block_plane, 1, 0])
                        flag = True
                        i += 1
                if flag:
                    set_bb_list.append(target_blk)
                if i >= blocks_to_markbb_in_lun_x:
                    break
            self.logger.info("Target_lun {} will mark BB list info: {}".format(target_lun, bb_desc_list))
            mark_bb_lun_dict[target_lun] = [channel, chip_enable, lun, lun_goodblock_count, len(bb_desc_list)]
        for target_lun, lun_info in list(mark_bb_lun_dict.items()):
            self.logger.info("#### Target_lun {}: Mark {} BB to make DieFailure".format(target_lun, lun_info[4]))
        return bb_desc_list

    def test(self):
        """
        @fn test
        @brief The detail steps to build the test case.
        @param This method takes no values.
        @return This method returns no values.
        @exception This method raises no exceptions.
        """
        self.logger.info("STEP {}: LLF.".format(self.step_id))
        self.vs_cmds.low_level_format()
        # CONDORW2-3815
        self.free_blk_stripe_list = self.block_management.free_block_stripe_list
        self.garbage_blk_stripe_list = self.block_management.garbage_block_stripe_list
        bb_list = self.bb_management.get_defect_list(use_raw_type=False)
        current_bb_count = len(bb_list.bibb_list) + len(bb_list.otp_bb_list) + len(bb_list.fwres_list) + len(
            bb_list.gbb_list)
        self.logger.info("Currently {} BB was detected: BIBB: {}, OTP BB: {}, FW Res: {}, GBB: {}"
                         .format(current_bb_count, len(bb_list.bibb_list), len(bb_list.otp_bb_list),
                                 len(bb_list.fwres_list), len(bb_list.gbb_list)))

        self.logger.info("STEP {}: Check if the initial status of critical warning bits are all 0.".format(self.step_id))
        smart_value = self.log_page.parser_log("SmartHealthInfo", retain_async_event=0, show_log=True)
        if (smart_value["CriticalWarning"]["AvailableSpare"] != 0) or \
                (smart_value["CriticalWarning"]["NvmSubsystemReliability"] != 0) or \
                (smart_value["CriticalWarning"]["MediaReadOnly"] != 0):
            self.logger.warning("Initial status is error, CriticalWarning info is: {}".format(smart_value["CriticalWarning"]))
            return

        available_spare = 0
        self.logger.info("STEP {}: Add One GBB (available_spare={}) to avoid LLF impact."
                         .format(self.step_id, available_spare))
        while True:
            lun_id = random.choice(range(self.lun_cnt))
            plane = random.choice(range(4))
            block_upper_list = [bs_id for bs_id in self.garbage_blk_stripe_list + self.free_blk_stripe_list
                                if bs_id > self.ftl_cfg.usr_blk_stp_id_st]
            block_upper = random.choice(block_upper_list)
            fla = self.address.fla_combine(page=0, plane=plane, lun_id=lun_id, block_stripe=block_upper)
            fla_ins = self.address.new_fla(fla=fla)
            status = self.block_management.get_block_stripe_info(bsid=block_upper)["Status"]
            if (not fla_ins.is_bb) and (status == "Garbage" or status == "Free"):
                break
        bb_info = [fla_ins.ch, fla_ins.ce, fla_ins.lun, fla_ins.block_plane, 1, 0]
        self.logger.info("Mark one BB on {}".format(fla_ins))
        self.vs_cmds.set_defect_list(bad_block_descriptor_list=[bb_info], timeout_time=12 * 60, polling_time=12*60, check_bb=False)
        bb_list = self.bb_management.get_defect_list(use_raw_type=False)
        current_bb_count = len(bb_list.bibb_list) + len(bb_list.otp_bb_list) + len(bb_list.fwres_list) + len(
            bb_list.gbb_list)
        self.logger.info("Currently {} BB was detected: BIBB: {}, OTP BB: {}, FW Res: {}, GBB: {}"
                         .format(current_bb_count, len(bb_list.bibb_list), len(bb_list.otp_bb_list),
                                 len(bb_list.fwres_list), len(bb_list.gbb_list)))

        self.logger.info("STEP {}: Add GBB (available_spare={}), and check.".format(self.step_id, available_spare))
        bb_desc_list = self.get_bb_desc_list(available_spare)
        # https://jira.micron.com/jira/browse/FTEVAL-22645
        self.vs_cmds.set_defect_list(bad_block_descriptor_list=bb_desc_list, timeout_time=12 * 60, polling_time=30*60, check_bb=False)
        bb_list = self.bb_management.get_defect_list(use_raw_type=False)
        current_bb_count = len(bb_list.bibb_list) + len(bb_list.otp_bb_list) + len(bb_list.fwres_list) + len(
            bb_list.gbb_list)
        self.logger.info("Currently {} BB was detected: BIBB: {}, OTP BB: {}, FW Res: {}, GBB: {}"
                         .format(current_bb_count, len(bb_list.bibb_list), len(bb_list.otp_bb_list),
                                 len(bb_list.fwres_list), len(bb_list.gbb_list)))

        self.logger.info("STEP {}: Check if the SMART log is as expected.".format(self.step_id))
        available_spare_expect = 0
        smart_value = self.log_page.parser_log("SmartHealthInfo", retain_async_event=0, show_log=True)
        if smart_value["AvailableSpare"] != available_spare_expect:
            raise TestException("available_spare = {}, is not expected({})"
                                .format(smart_value["AvailableSpare"], available_spare_expect))
        time.sleep(10)
        if self.dut.project_constants['OCP_SUPPORTED'] is True:
            if (smart_value["CriticalWarning"]["AvailableSpare"] != 1) or \
                    (smart_value["CriticalWarning"]["NvmSubsystemReliability"] != 1) or \
                    (smart_value["CriticalWarning"]["MediaReadOnly"] != 1):
                raise TestException("Critical warning bit = {}, is not expected: AvailableSpare=1(bit0), "
                                    "NvmSubsystemReliability=1(bit2), MediaReadOnly=1(bit3)".format(smart_value["CriticalWarning"]))
        else:
            if (smart_value["CriticalWarning"]["AvailableSpare"] != 1) or \
                    (smart_value["CriticalWarning"]["NvmSubsystemReliability"] != 0) or \
                    (smart_value["CriticalWarning"]["MediaReadOnly"] != 1):
                raise TestException("Critical warning bit = {}, is not expected: AvailableSpare=1(bit0), "
                                    "NvmSubsystemReliability=0(bit2), MediaReadOnly=1(bit3)".format(smart_value["CriticalWarning"]))

    def cleanup_test(self):
        """
        @fn cleanup_test
        @brief Clear up test environment for the test.
        @param This method takes no values.
        @return This method returns no values.
        @exception This method raises no exceptions.
        """
        self.logger.info("low_level_format to clear VS setting and GBB.")
        low_level_format.vs_low_level_format(self.dut, options=low_level_format.LLF_OPTIONS["ExitEOL"])
        self.vs_cmds.low_level_format(clear_gbb=1, preserve_ec=0, clear_bibb=1, preserve_smart=0, preserve_el=0,
                                      preserve_program_count=0, preserve_nsp=0, quick_format=0, warm_reset=0,
                                      preserve_smart_counters=0, preserve_all_logs=0, reseeding=0, exit_eol=0)
        self.logger.info("Check Eixt EOL success, and Critical warning bit is clear to 0.")
        smart_value = self.log_page.parser_log("SmartHealthInfo", retain_async_event=0, show_log=True)
        if (smart_value["CriticalWarning"]["AvailableSpare"] != 0) or \
                (smart_value["CriticalWarning"]["NvmSubsystemReliability"] != 0) or \
                (smart_value["CriticalWarning"]["MediaReadOnly"] != 0):
            raise TestException("Critical warning bit = {}, is not expected: AvailableSpare=0(bit0), "
                                "NvmSubsystemReliability=0(bit2), MediaReadOnly=0(bit3)"
                                .format(smart_value["CriticalWarning"]))
        super(OcpSmartAvailableSpare0, self).cleanup_test()


def main_test():
    """
    @fn Main
    @brief This method is used to create a test instance and run the script.
    @param This method takes no values.
    @return This method returns no values.
    @exception This method raises no exceptions.
    """
    test = OcpSmartAvailableSpare0()
    exit(test.execute())


if __name__ == "__main__":
    main_test()