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

# Clear any previous state first
initial_state = self.dal.mi_device.control_primitive.GetState(csi=self.command_slot_id).response_dict
self.log(f"Initial state before test: UDSTID={initial_state['UDSTID']}")

self.log("Issuing Identify Command with Destination ID : {}".format(new_dest_eid)) 

command_sent = False
try:
    command_msg = struct.pack("BBH15I",0x6,3,0,1,0,0,0,0,0,4096,0,0,0,0,0,0,0,0)
    mi_header = self.dal.mi_device.create_nvme_mi_header(nmimt=2, ic=1, msg_type=0x4, ror=0, 
                                                          csi=self.command_slot_id, ciap=0, meb=0)
    # Use valid source EID
    cmd = self.dal.mi_device.build_mctp_packets(mi_header, command_msg, max_tu_size=64, mic=None, 
                                                  src_eid=endpoint_id,  # Changed from 0
                                                  dest_eid=new_dest_eid, 
                                                  msg_tag=0, tag_owner=1)
    
    smbus_mctp_packets = self.dal.mi_device.send_mctp_packets(cmd, 
                                                                transport=self.options['transfer_protocol'], 
                                                                phy_addr=0x1D, slave_addr=0x72)
    self.log(f"MCTP packets sent successfully: {smbus_mctp_packets}")
    command_sent = True
    
except TimeoutError as e:
    self.log(f"Command timeout (may be expected with invalid dest): {e}")
    command_sent = True  # Command was sent, just timed out
except Exception as e:
    self.log(f"Exception during send: {type(e).__name__}: {e}")
    # Re-raise if it's an unexpected error
    if "invalid" not in str(e).lower() and "destination" not in str(e).lower():
        raise
    command_sent = True

if not command_sent:
    raise TestException("Command was not sent to device")

#2) Wait and verify the UDSTID Flag 
#---------------------------------------------------------------------------------------------------------------------
# Give firmware time to process the invalid destination and set the flag
self.log("Waiting for FW to process invalid destination...")
time.sleep(2)

# Poll for the flag with retry
max_retries = 5
retry_interval = 1
udstid_set = False

for attempt in range(max_retries):
    self.log(f"10.b) Attempt {attempt + 1}: Issue Get State control primitive to Command slot : {self.command_slot_id}")
    rep_msg = self.dal.mi_device.control_primitive.GetState(csi=self.command_slot_id).response_dict
    
    # Log all non-zero flags
    non_zero_flags = {k: v for k, v in rep_msg.items() if v != 0}
    if non_zero_flags:
        self.log(f"Non-zero flags detected: {non_zero_flags}")
    
    self.logger.info("Control Primitive GET STATE response:\n{}".format(rep_msg))
    
    if rep_msg["UDSTID"] == 1:
        self.log(f"UDSTID flag is set after {attempt + 1} attempts (expected)")
        udstid_set = True
        break
    elif attempt < max_retries - 1:
        self.log(f"UDSTID not set yet, waiting {retry_interval}s before retry...")
        time.sleep(retry_interval)

if not udstid_set:
    # Log full state for debugging
    self.log(f"Final state after {max_retries} attempts: {rep_msg}")
    raise TestException(f"Failed !!! The UDSTID flag is not set after {max_retries} attempts")