from analyser import safe_dict_get

def analyse(packets, attach_packets, ue_info):
    # check for possible disruption of service because of invalid MAC
    mac_invalid_behaviour(packets, attach_packets)

    # check if security options are used correctly if there is a security mode command in pcap
    if safe_dict_get(ue_info['locations'], 'rrc_smc'):
        correct_security_options(packets, ue_info)


def correct_security_options(packets, ue_info):
    """Checks if correct security options are used every time for PDCP."""
    rrc_smc = ue_info['locations']['rrc_smc']
    secure_packets = packets[rrc_smc:]
    ca = ue_info['rrc_ca'][-1]
    ia = ue_info['rrc_ia'][-1]
    for packet in secure_packets:
        if 'RRC' in packet.summary:
            packet_ca = packet.data.get('pdcp-lte.security-config.ciphering')
            if not ca == packet_ca:
                packet.add_analysis('PDCP ciphering algorithm does not match configured algorithm.', 2)
            packet_ia = packet.data.get('pdcp-lte.security-config.integrity')
            if not ia == packet_ia:
                packet.add_analysis('PDCP integrity algorithm does not match configured algorithm.', 2)
            packet.category.append('Analysed')



def mac_invalid_behaviour(packets, attach_packets):
    """Finds if unfinished attach occurred and looks if behaviour could be caused by an invalid PDCP MAC.

    In this case, behaviour caused by an invalid MAC is defined as follows:
    * Attach must be incomplete (RRCConnectionReconfiguration is not sent)
    * If last packet in capture is not part of attach procedure, send error.
      An example of this could be that the last packet is an attach release.
      This behaviour can be found in enb_mac_invalid.pcap
    * If last packet in capture is part of attach procedure, sent warning.
      Capture file could simply be incomplete, or could be because of invalid MAC.
      This behaviour can be found in enb_mac_incomplete.pcap
    """

    # find if RRCConnectionReconfiguration occurred, if not, attach procedure is incomplete
    complete = False
    for packet in packets:
        if 'RRCConnectionReconfiguration' in packet.summary:
            complete = True
    if complete:
        return

    # find if attach packet is last packet of capture
    last_attach = attach_packets[-1]
    if last_attach == packets[-1]:
        # send warning for possible incomplete file or invalid PDCP MAC
        last_attach.add_analysis('Attach procedure incomplete.\nIf there are no possible causes listed in this packet, it might be because of an invalid MAC.', 1)
    else:
        # send error for probable invalid PDCP MAC
        last_attach.add_analysis('Attach procedure incomplete.\nThis might be because of an invalid PDCP MAC.', 3)
