self.log("5.a) Issue Identify Command with invalid PEC")
try:
    command_msg = struct.pack("BBH15I", 0x6, 3, 0, 1, 0, 0, 0, 0, 0, 4096, 0, 0, 0, 0, 0, 0, 0, 0)
    self.log(f"Packed command message: {command_msg.hex()}")
    mi_header = self.dal.mi_device.create_nvme_mi_header(nmimt=2, ic=1, msg_type=0x4, ror=0, csi=self.command_slot_id, ciap=0, meb=0)
    self.log(f"MI header: {mi_header.hex()}")
    cmd = self.dal.mi_device.build_mctp_packets(mi_header, command_msg, max_tu_size=64, mic=None, src_eid=0, dest_eid=0, msg_tag=0, tag_owner=1)
    if cmd:
        print("MCTP Packet is built")
        self.log(f"Number of MCTP packets built: {len(cmd)}")
    else:
        print("Fail to build packet")
        self.log("ERROR: Failed to build MCTP packets")

    if self.options['transfer_protocol'] == "smbus":               
        smbus_mctp_packets = self.dal.mi_device.add_smbus_header_mctp_packets(cmd, phy_addr=0x1D, slave_addr=0x72)
        print("Inside SMBUS transfer")
        self.log(f"Number of SMBus MCTP packets: {len(smbus_mctp_packets)}")
        
        # Log original packets before corruption
        self.log(f"Original SMBus MCTP packets (before PEC corruption):")
        for idx, packet in enumerate(smbus_mctp_packets):
            self.log(f"  Packet {idx}: {packet.hex()}, PEC: 0x{packet[-1]:02x}")
        
        # Corrupt PEC in each packet
        self.log("Corrupting PEC values...")
        for idx, packet in enumerate(smbus_mctp_packets):
            original_pec = packet[-1]
            packet[-1] = 100  # Invalid PEC value
            print(f"Inside first loop - packet {idx}")
            self.log(f"  Packet {idx}: Corrupted PEC from 0x{original_pec:02x} to 0x{packet[-1]:02x}")
            self.log(f"  Packet {idx} after corruption: {packet.hex()}")
        
        # Send corrupted packets
        self.log("Sending corrupted packets to device...")
        for idx, packet in enumerate(smbus_mctp_packets):
            self.log(f"  Sending packet {idx}: {packet.hex()}")
            try:
                self.dal.mi_device.smbus.smbus_master_write(0x1D, packet[1:])
                self.log(f"  Packet {idx} sent successfully")
            except Exception as send_error:
                self.log(f"  ERROR sending packet {idx}: {str(send_error)}")
            time.sleep(1 / 2)
            print(f"Inside second loop - packet {idx}")
        
        # Capture and log response
        self.log("Retrieving SMBus response...")
        try:
            response = self.dal.mi_device.smbus.smbus_response_data()
            self.log(f"SMBus response data: {response}")
            if response:
                self.log(f"SMBus response hex: {response.hex() if hasattr(response, 'hex') else response}")
            else:
                self.log("WARNING: No response received from device")
        except Exception as resp_error:
            self.log(f"ERROR retrieving response: {str(resp_error)}")
            response = None
        print("At the end of SMBUS transfer")

    if self.options['transfer_protocol'] == "pcievdm":
        # DRVSL-7915: mctp_vdm_code value should be in between 0 to 0xF since mctp_vdm_code contains 4 bits
        self.log("Using PCIe VDM transfer protocol")
        smbus_mctp_packets = self.dal.mi_device.send_mctp_packets(cmd, transport=self.options['transfer_protocol'], phy_addr=0x1D, slave_addr=0x72, mctp_vdm_code=0xF)
        
except BaseException as e:
    self.log(f"Identify command with invalid PEC failed as expected Exception: {str(e)}")
    import traceback
    self.log(f"Full traceback: {traceback.format_exc()}")

# ---------------------------------------------------------------------------------------------------------------------
# 2) Issue Get State Control Primitive and verify
# ---------------------------------------------------------------------------------------------------------------------
self.log("5.b) Issue Get State Control primitive to command slot : {}".format(self.command_slot_id))
self.log(f"DEBUG: Waiting briefly before checking BPOPL state...")
time.sleep(0.5)  # Give device time to process error

rep_msg = self.dal.mi_device.control_primitive.GetState(csi=self.command_slot_id).response_dict
self.logger.info("control_primitive_get_state response:\n{}".format(rep_msg))

# Enhanced BPOPL verification with detailed logging
self.log("=" * 80)
self.log("Verifying if BPOPL is set after sending corrupted PEC packets")
self.log("=" * 80)
self.log(f"Complete GetState response: {rep_msg}")
self.log(f"BPOPL value: {rep_msg.get('BPOPL', 'NOT FOUND')}")
self.log(f"BPOPL type: {type(rep_msg.get('BPOPL', None))}")

# Log all relevant state fields
for key, value in rep_msg.items():
    self.log(f"  {key}: {value}")

if rep_msg["BPOPL"] != 1:
    self.log("FAILED: BPOPL flag is NOT set (expected 1, got {})".format(rep_msg["BPOPL"]))
    self.log("=" * 80)
    self.log("DEBUG INFORMATION:")
    self.log(f"  - Transfer protocol: {self.options['transfer_protocol']}")
    self.log(f"  - Command slot ID: {self.command_slot_id}")
    self.log(f"  - Number of corrupted packets sent: {len(smbus_mctp_packets) if 'smbus_mctp_packets' in locals() else 'UNKNOWN'}")
    self.log(f"  - Physical address: 0x1D")
    self.log(f"  - Slave address: 0x72")
    self.log("=" * 80)
    self.log("POSSIBLE CAUSES:")
    self.log("  1. Device may not have detected PEC errors")
    self.log("  2. PEC validation might be disabled in device")
    self.log("  3. Timing issue - device hasn't processed error yet")
    self.log("  4. Wrong command slot being checked")
    self.log("  5. BPOPL flag might have been cleared by another operation")
    self.log("=" * 80)
    raise TestException("Failed !!! The BPOPL field is not set")
else:
    self.log("SUCCESS: BPOPL flag is set as expected (value: {})".format(rep_msg["BPOPL"]))
    self.log("=" * 80)