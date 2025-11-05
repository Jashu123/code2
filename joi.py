self.log("5.a) Issue Identify Command with invalid PEC")
try:
    command_msg = struct.pack("BBH15I", 0x6, 3, 0, 1, 0, 0, 0, 0, 0, 4096, 0, 0, 0, 0, 0, 0, 0, 0)
    self.log(f"Packed command message: {command_msg.hex()}")
    mi_header = self.dal.mi_device.create_nvme_mi_header(nmimt=2, ic=1, msg_type=0x4, ror=0, csi=self.command_slot_id, ciap=0, meb=0)
    self.log(f"MI header: {mi_header.hex()}")
    cmd = self.dal.mi_device.build_mctp_packets(mi_header, command_msg, max_tu_size=64, mic=None, src_eid=0, dest_eid=0, msg_tag=0, tag_owner=1)
    if cmd:
        print("MCTP Packet is built")
    else:
        print("Fail to build packet")

    if self.options['transfer_protocol'] == "smbus":               
        smbus_mctp_packets = self.dal.mi_device.add_smbus_header_mctp_packets(cmd, phy_addr=0x1D, slave_addr=0x72)
        print("Inside SMBUS transfer")
        
        # Fix: Log each packet's hex representation
        self.log(f"Original SMBus MCTP packets (before PEC corruption): {[packet.hex() for packet in smbus_mctp_packets]}")
        
        # Corrupt PEC in each packet
        for packet in smbus_mctp_packets:
            original_pec = packet[-1]
            packet[-1] = 100
            print("Inside first loop")
            self.log(f"Corrupted PEC from {original_pec} to {packet[-1]} in packet: {packet.hex()}")
        
        # Send corrupted packets
        for packet in smbus_mctp_packets:
            self.dal.mi_device.smbus.smbus_master_write(0x1D, packet[1:])
            time.sleep(1 / 2)
            print("Inside second loop")
        
        # Fix: Capture response before logging it
        response = self.dal.mi_device.smbus.smbus_response_data()
        self.log(f"SMBus response data: {response}")
        print("At the end of SMBUS transfer")

    if self.options['transfer_protocol'] == "pcievdm":
        # DRVSL-7915: mctp_vdm_code value should be in between 0 to 0xF since mctp_vdm_code contains 4 bits
        smbus_mctp_packets = self.dal.mi_device.send_mctp_packets(cmd, transport=self.options['transfer_protocol'], phy_addr=0x1D, slave_addr=0x72, mctp_vdm_code=0xF)
        
except BaseException as e:
    self.log(f"Identify command with invalid PEC failed as expected Exception: {str(e)}")