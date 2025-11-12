#1) Issue Identify Cmd with invalid destination ID
#---------------------------------------------------------------------------------------------------------------------
self.log("10.a) Issue Identify command with Invalid destination ID") 
self.log("Issuing Get endpoint ID control message for fetching current endpoint ID") 
mctp_header = self.dal.mi_device.create_mctp_header(som=1, eom=1)
endpoint_id = self.dal.mi_device.mctp_control_messages.get_endpoint_id(mctp_header=mctp_header).response_dict["EID"]
self.log("Current Endpoint ID : {}".format(endpoint_id))    

new_dest_eid = random.choice(list(set(range(nvme_mi_constants.SPL_EID_RSVD_MAX + 1, endpoint_id)) |
                                      set(range(endpoint_id + 1, nvme_mi_constants.SPL_EID_BROADCAST)))) 
self.log("Randomly selected endpoint ID : {}".format(new_dest_eid)) 
self.log("Issuing Identify Command with Destination ID : {}".format(new_dest_eid)) 

command_sent = False
mctp_response = None

try:
    command_msg = struct.pack("BBH15I",0x6,3,0,1,0,0,0,0,0,4096,0,0,0,0,0,0,0,0)
    mi_header = self.dal.mi_device.create_nvme_mi_header(nmimt=2, ic=1, msg_type=0x4, ror=0, 
                                                          csi=self.command_slot_id, ciap=0, meb=0)
    cmd = self.dal.mi_device.build_mctp_packets(mi_header, command_msg, max_tu_size=64, mic=None, 
                                                  src_eid=endpoint_id, dest_eid=new_dest_eid, 
                                                  msg_tag=0, tag_owner=1)
    
    self.log("MCTP packets built successfully, sending to device...")
    mctp_response = self.dal.mi_device.send_mctp_packets(cmd, transport=self.options['transfer_protocol'], 
                                                           phy_addr=0x1D, slave_addr=0x72)
    
    # Verify command was sent
    self.log(f"MCTP send_mctp_packets returned: {mctp_response}")
    self.log(f"Response type: {type(mctp_response)}")
    
    if mctp_response is not None:
        command_sent = True
        self.log("Command was successfully sent to the device")
    else:
        self.log("WARNING: send_mctp_packets returned None")
        
except TimeoutError as e:
    self.log(f"Command timeout (command likely reached device but no response): {e}")
    command_sent = True  # Timeout means command was sent but no response
    
except Exception as e:
    self.log(f"Exception during command send: {type(e).__name__}: {e}")
    self.log(f"Exception details: {str(e)}")
    
    # Check if it's a transport-level error vs application-level error
    if any(keyword in str(e).lower() for keyword in ['transport', 'i2c', 'smbus', 'connection']):
        self.log("ERROR: Transport layer failure - command may not have reached device")
        command_sent = False
    else:
        self.log("Command likely reached device but failed at application layer")
        command_sent = True

# Verify command actually reached the device
if not command_sent:
    raise TestException("CRITICAL: Command was not sent to the device - cannot verify UDSTID behavior")

self.log("Confirmed: Command was sent to device")

#---------------------------------------------------------------------------------------------------------------------

#1b) Additional verification - Check if device received the command
#---------------------------------------------------------------------------------------------------------------------
self.log("10.a.1) Verifying device received the command by checking command slot status")

# Option 1: Read command slot status to see if command was received
try:
    slot_status = self.dal.mi_device.control_primitive.GetState(csi=self.command_slot_id).response_dict
    
    # Check SSTA (Slot Status) to confirm command processing
    if slot_status["SSTA"] != 0:
        self.log(f"Command slot {self.command_slot_id} shows activity (SSTA={slot_status['SSTA']})")
        self.log("Device received and is processing/processed the command")
    else:
        self.log(f"WARNING: Command slot {self.command_slot_id} shows no activity (SSTA=0)")
        self.log("Command may not have reached the device")
        
except Exception as e:
    self.log(f"Could not verify command reception via slot status: {e}")

# Option 2: Check SMBus/I2C transaction logs if available
if hasattr(self.dal, 'get_smbus_transaction_log'):
    try:
        smbus_log = self.dal.get_smbus_transaction_log()
        self.log(f"SMBus transaction log: {smbus_log}")
        
        # Verify write transactions occurred
        if smbus_log and len(smbus_log) > 0:
            self.log(f"SMBus transactions detected: {len(smbus_log)} transactions")
            self.log("Command reached SMBus interface")
        else:
            self.log("WARNING: No SMBus transactions detected")
            
    except Exception as e:
        self.log(f"Could not retrieve SMBus logs: {e}")

# Option 3: Check device error counters/logs
try:
    # Read any error logs or counters that might show invalid destination ID was detected
    # This depends on your device's capabilities
    if hasattr(self.dal.mi_device, 'get_error_log'):
        error_log = self.dal.mi_device.get_error_log()
        self.log(f"Device error log: {error_log}")
        
        if "invalid destination" in str(error_log).lower() or "unknown eid" in str(error_log).lower():
            self.log("CONFIRMED: Device detected invalid destination ID")
            
except Exception as e:
    self.log(f"Could not check device error logs: {e}")

#---------------------------------------------------------------------------------------------------------------------

#2) Check Get State immediately, if not set then sleep and check again
#---------------------------------------------------------------------------------------------------------------------
self.log("10.b) Issue Get State control primitive to Command slot : {} (immediate check)".format(self.command_slot_id))
rep_msg = self.dal.mi_device.control_primitive.GetState(csi=self.command_slot_id).response_dict
self.logger.info("Control Primitive GET STATE response (immediate):\n{}".format(rep_msg))

# Check if UDSTID is set immediately
if rep_msg["UDSTID"] != 1:
    self.log("UDSTID flag is NOT set immediately. Sleeping for 2 seconds...")
    time.sleep(2)
    
    self.log("10.c) Issue Get State control primitive again to Command slot : {}".format(self.command_slot_id))
    rep_msg = self.dal.mi_device.control_primitive.GetState(csi=self.command_slot_id).response_dict
    self.logger.info("Control Primitive GET STATE response (after sleep):\n{}".format(rep_msg))

# Final verification
self.log("Verifying if UDSTID is set.")
if rep_msg["UDSTID"] != 1:
    # Additional debug info before failing
    self.log("=== DEBUG: Command reached device but UDSTID not set ===")
    self.log(f"Final state: {rep_msg}")
    self.log(f"Command was sent: {command_sent}")
    self.log(f"MCTP response: {mctp_response}")
    raise TestException("Failed !!! The UDSTID flag is not set")    
else:
    self.log("UDSTID flag is set as expected.")
#-------------------------------------