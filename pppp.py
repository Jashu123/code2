import os
import re
import sys
import time
import socket
import codecs
import logging
import subprocess
from datetime import datetime
from argparse import ArgumentParser

def initialize_log(log_file_name, level=logging.INFO, shell=True):
    global log

    log_path = os.path.join('/tmp', os.path.basename(log_file_name))

    log = logging.getLogger()
    log.setLevel(level)
    
    # File handler
    log_file_handler = logging.FileHandler(log_path)
    log_formatter = logging.Formatter('%(message)s')
    log_file_handler.setFormatter(log_formatter)
    log.addHandler(log_file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    log.addHandler(console_handler)

def cmdexe(cmd):
    logging.info('\n')
    process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    for val in process.stdout.splitlines():
        val = codecs.decode(val)
        print(val)
        logging.info(val)

def IdentifyCommandCNS01(device):
    idcns01 = {}
    identify_nvme_cmd = "nvme id-ctrl " + device
    process = subprocess.run(identify_nvme_cmd, shell=True, stdout=subprocess.PIPE)
    idcns01['ReturnCode'] = process.returncode

    for val in process.stdout.splitlines():
        val = codecs.decode(val)
        if 'fr ' in val:
            val = val.split(":")[1]
            idcns01['FirmwareVersion'] = val.strip()
        if 'frmw' in val:
            val = val.split(":")[1]
            ReadOnlySlot = int(((bin(int(val, 16))[2:]).zfill(8)[-1]), 2)
            idcns01['ReadOnlySlot'] = ReadOnlySlot
            NumberOfSlots = int(((bin(int(val, 16))[2:]).zfill(8)[4:7]), 2)
            idcns01['NumberOfSlots'] = NumberOfSlots
        if 'mdts' in val:
            val = (val.split(":")[1]).strip(' ')
            idcns01['mdts'] = int(val)
        if 'fwug' in val:
            val = (val.split(":")[1]).strip(' ')
            idcns01['fwug'] = int(val)
        if 'mtfa' in val:
            val = (val.split(":")[1]).strip(' ')
            idcns01['mtfa'] = int(val)
    return idcns01

def FirmwareDownload(device, fwpath, verbose=False):
    firmwaredownlaod_cmd = "nvme fw-download " + device + " --fw " + fwpath
    logging.info("Command Issued is - {} \n".format(firmwaredownlaod_cmd))
    process = subprocess.run(firmwaredownlaod_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode == 0:
        logging.info("FW Download command was successful")
    else:
        logging.info("FW Download command has failed")
        logging.info("Return code: {}".format(process.returncode))
        
        # Print stdout if available
        if process.stdout:
            stdout_msg = process.stdout.decode("utf-8")
            logging.info("STDOUT: {}".format(stdout_msg))
        
        # Print stderr if available
        if process.stderr:
            err_status = process.stderr.decode("utf-8")
            logging.info("STDERR: {}".format(err_status))
            
            # Try to parse error codes
            match = re.search(r'\((0x[\da-fA-F]+)\)', err_status)
            if match:
                hex_value = match.group(1)
                int_value = int(hex_value, 16)
                binary_str = format(int_value, '016b')
                SC = int(binary_str[-8:], 2)
                SCT = int(binary_str[-12:-8], 2)
                logging.info("FW Download command failed with SCT - {} and SC - {} \n".format(SCT, SC))
        
        # Check if firmware file exists
        if not os.path.exists(fwpath):
            logging.info("ERROR: Firmware file does not exist: {}".format(fwpath))
        else:
            logging.info("Firmware file exists: {}".format(fwpath))
            logging.info("File size: {} bytes".format(os.path.getsize(fwpath)))
        
        TestFail(start_testtime)

def FirmwareCommit(device, slot, CommitAction, verbose=False):
    fw_commit_status = {}
    logging.info("\n")
    firmwarecommit_cmd = "nvme fw-commit " + device + " -s " + str(slot) + " -a " + str(CommitAction)
    logging.info("Command Issued is - {} \n".format(firmwarecommit_cmd))
    process = subprocess.run(firmwarecommit_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ReturnCode = process.returncode
    fw_commit_status['ReturnCode'] = ReturnCode
    if ReturnCode != 0:
        err_status = process.stderr.decode("utf-8")
        match = re.search(r'\((0x[\da-fA-F]+)\)', err_status)
        if match:
            hex_value = match.group(1)
            int_value = int(hex_value, 16)
            binary_str = format(int_value, '016b')
            fw_commit_status['SC'] = int(binary_str[-8:], 2)
            fw_commit_status['SCT'] = int(binary_str[-12:-8], 2)

    return fw_commit_status

def TestFail(start_testtime):
    end_testtime = datetime.now()
    duration = end_testtime - start_testtime
    print("****************Test Failed, Please check the logs!****************")
    logging.info("****************Test Failed****************")
    logging.info("End Time of the Test: " + str(end_testtime))
    logging.info("Duration of the Test: " + str(duration))
    sys.exit()

def FWUpdate(fw_path, verify=False):
    identify_ctrl = IdentifyCommandCNS01(device)
    logging.info("\n")
    FirmwareRevisionBeforeFWUpdate = identify_ctrl['FirmwareVersion']
    logging.info("Firmware Revision before Firmware Update - {} \n ".format(FirmwareRevisionBeforeFWUpdate))

    ReadOnlySlot = identify_ctrl['ReadOnlySlot']
    NumberOfSlots = identify_ctrl['NumberOfSlots']

    for slot in range(1, NumberOfSlots + 1):
        if slot != ReadOnlySlot:
            break

    FirmwareDownload(device=device, fwpath=fw_path)

    StartingTimestamp = datetime.now()
    fw_commit_status = FirmwareCommit(device, slot, 3)
    if fw_commit_status['ReturnCode'] == 0:
        logging.info("FW Commit command completed successfully \n")
    else:
        logging.info("FW Commit Command has failed with SCT - {} and SC - {} \n".format(fw_commit_status['SCT'], fw_commit_status['SC']))
        TestFail(start_testtime)
    EndingTimestamp = datetime.now()

    time.sleep(2)
    identify_ctrl = IdentifyCommandCNS01(device)
    try:
        FR = identify_ctrl["FirmwareVersion"]
    except KeyError:
        print("GetLog 0x3 return None to verify Firmware Revision!")
        logging.info("GetLog 0x3 return None to verify Firmware Revision!")
        TestFail(start_testtime)
    FirmwareRevisionAfterFWUpdate = identify_ctrl['FirmwareVersion']
    logging.info("Firmware Revision after Firmware Update- {} \n ".format(FirmwareRevisionAfterFWUpdate))

    if FirmwareRevisionBeforeFWUpdate != FirmwareRevisionAfterFWUpdate:
        logging.info("{} - Firmware Updated Successfully!".format(FirmwareRevisionAfterFWUpdate))
    else:
        if not verify:
            logging.info("Firmware update Failed, Please check !")
            print("Firmware update Failed, Please check !")
            TestFail(start_testtime)
        else:
            logging.info("Please run the test with baseline (N) Firmware, Please check !")
            print("Please run the test with baseline (N) Firmware, Please check !")
            TestFail(start_testtime)

    if not verify:
        fw_update_duration = (EndingTimestamp - StartingTimestamp).total_seconds()
        if fw_update_duration >= 1:
            print("Failed, FW update process not completed within 1 second duration and it took - {} seconds to finish \n".format(fw_update_duration))
            logging.info("Failed, FW update process not completed within 1 second duration and it took - {} seconds to finish \n".format(fw_update_duration))
            TestFail(start_testtime)
        else:
            logging.info("FW update process took less than 1 seconds to complete, duration - {} seconds \n".format(fw_update_duration))

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-d", "--device")
    parser.add_argument("-fw_upgrade", "--fw_upgrade")
    parser.add_argument("-fw_downgrade", "--fw_downgrade")

    args, emptyargs = parser.parse_known_args()

    if args.device is not None:
        device = str(args.device)
    else:
        print("Please run the test, ex: sudo python3 FwActivationWithReducedFreeBlocks.py -d /dev/nvmexn1 -fw_upgrade <N Firmware> -fw_downgrade<N-1 Firmware>")
        sys.exit()

    if args.fw_upgrade is not None:
        fw_upgrade = str(args.fw_upgrade)
    else:
        print("Please run the test, ex: sudo python3 FwActivationWithReducedFreeBlocks.py -d /dev/nvmexn1 -fw_upgrade <N Firmware> -fw_downgrade<N-1 Firmware>")
        sys.exit()

    if args.fw_downgrade is not None:
        fw_downgrade = str(args.fw_downgrade)
    else:
        print("Please run the test, ex: sudo python3 FwActivationWithReducedFreeBlocks.py -d /dev/nvmexn1 -fw_upgrade <N Firmware> -fw_downgrade<N-1 Firmware>")
        sys.exit()

    Testname = os.path.basename(__file__).split('.')[0]
    hostname = socket.gethostname()
    hostip = socket.gethostbyname(hostname)

    logtimestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    test_dir = os.getcwd()

    initialize_log(test_dir + '/' + Testname + '-' + logtimestamp + '.txt')

    start_testtime = datetime.now()
    logging.info("Start Time of the Test: " + str(start_testtime))
    logging.info(Testname + " is Running on Host - " + hostname + ' IP : ' + socket.gethostbyname(hostip))
    logging.info("Running Script Version : V1.1")

    logging.info('\n')
    logging.info("Previous N-1 FW, being used for the validation : {}".format(fw_downgrade))
    logging.info("Original N FW, being used for the validation   : {}".format(fw_upgrade))

    cmd = "nvme list {}".format(device)
    cmdexe(cmd)

    FWUpdate(fw_downgrade, True)

    logging.info('\n')
    cmd = "nvme format -f " + device
    cmdexe(cmd)
    cmd = ('nvme id-ns ' + device + ' | grep nuse')
    process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)

    for val in process.stdout.splitlines():
        val = codecs.decode(val)
        logging.info('\n')
        logging.info(val)
        if 'nuse' in val:
            val = val.split()[2].strip()
            if val == str(0):
                logging.info("Nuse : {}".format(val))
                logging.info("Success, NUSE reports 0")
                logging.info('\n')
            else:
                logging.info('\n')
                logging.info("Failed, After nvmeformat NUSE reports : {}".format(val))
                logging.info('\n')

    SeqWriteFIO = "fio --name=seqfill --ioengine=libaio --direct=1 --thread=1 --numjobs=1 --iodepth=256 --rw=write --bs=128k --loops=1 --size=100% --filename={}".format(device)
    print("FIO Running : {}".format(SeqWriteFIO))
    logging.info("FIO Command : {}".format(SeqWriteFIO))
    cmdexe(SeqWriteFIO)

    RandWriteFIO = "fio --name=randwr --ioengine=libaio --direct=1 --thread=1 --numjobs=1 --iodepth=256 --randrepeat=0 --norandommap --rw=randwrite --bs=4k --time_based --runtime=600 --filename={}".format(device)
    print("FIO Running : {}".format(RandWriteFIO))
    logging.info("FIO Command : {}".format(RandWriteFIO))
    cmdexe(RandWriteFIO)

    FWUpdate(fw_upgrade)

    Iteration = 1
    while Iteration < 21:
        logging.info("-" * 15)
        logging.info("Iteration : {}".format(Iteration))
        logging.info("-" * 15)

        RandWriteFIO = "fio --name=randwr --ioengine=libaio --direct=1 --thread=1 --numjobs=1 --iodepth=256 --randrepeat=0 --norandommap --rw=randwrite --bs=4k --time_based --runtime=300 --filename={}".format(device)
        print("FIO Running : {}".format(RandWriteFIO))
        logging.info("FIO Command : {}".format(RandWriteFIO))
        cmdexe(RandWriteFIO)

        if Iteration % 2 == 1:
            FWUpdate(fw_downgrade)
        else:
            FWUpdate(fw_upgrade)

        Iteration += 1

    logging.info('\n')
    print("****************Test Passed, Please check the logs!****************")
    logging.info("****************Test Passed****************")
    end_testtime = datetime.now()
    duration = end_testtime - start_testtime
    logging.info("End Time of the Test: " + str(end_testtime))
    logging.info("Duration of the Test: " + str(duration))