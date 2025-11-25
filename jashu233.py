# Use RESERVED EID range (0-7) which are explicitly invalid per MCTP spec
RESERVED_INVALID_EIDS = [0, 1, 2, 3, 4, 5, 6, 7]

# Make sure we don't accidentally use the current endpoint's ID
endpoint_id = self.dal.mi_device.mctp_control_messages.get_endpoint_id(mctp_header=mctp_header).response_dict["EID"]
self.log("Current Endpoint ID : {}".format(endpoint_id))

# Select a reserved EID that's different from current
invalid_eids = [eid for eid in RESERVED_INVALID_EIDS if eid != endpoint_id]
new_dest_eid = random.choice(invalid_eids)

self.log("Using RESERVED invalid Endpoint ID : {}".format(new_dest_eid))
