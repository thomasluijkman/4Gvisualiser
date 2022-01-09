from analyser import safe_dict_get, get_attach_message

def analyse(packets, attach_packets, ue_info):
    # check for possible disruption of service because of invalid MAC
    mac_invalid_behaviour(packets, attach_packets, ue_info)

    # check if security options are used correctly if there is a security mode command in pcap
    if safe_dict_get(ue_info['locations'], 'rrc_smc'):
        correct_security_options(packets, ue_info)

    # check if the right bearers are used in analysis, and if RLC uses acknowledged mode
    correct_bearer_in_attach(attach_packets, ue_info)
    correct_rlc_mode(attach_packets)

    # check if UE capabilities are transmitted after security options are set
    capability_after_security(attach_packets, ue_info)



def capability_after_security(attach_packets, ue_info):
    # find UE capability information
    capability = None
    for packet in attach_packets:
        if 'UECapabilityInformation' in packet.full_summary:
            capability = packet
    if not capability:
        return

    if capability.id < ue_info['locations']['rrc_smc']:
        capability.add_analysis('Capabilities sent before security options were set.\nA malicious actor could perform downgrade attacks or accelerated battery draining.', 2)


def correct_rlc_mode(attach_packets):
    """Checks if every attach packet uses RLC acknowledged mode."""
    rrc_conn_setup_complete = get_attach_message(attach_packets, '65')
    if not rrc_conn_setup_complete:
        return  # no attach procedure should happen so no need to check for correct RLC mode
    for packet in attach_packets:
        if not packet.data.get('rlc-lte.mode') == '4':
            packet.add_analysis('RLC not travelling over acknowledged mode. In the attach process, every packet should be acknowledged.', 2)


def correct_bearer_in_attach(attach_packets, ue_info):
    """Checks if correct SRB is used in packets and if correct RLC modes are used."""
    # get RRCConnectionSetupComplete to find where SRB1 should be used
    rrc_conn_setup_complete = get_attach_message(attach_packets, '65')
    if rrc_conn_setup_complete:
        ue_info['locations']['attach_accept'] = rrc_conn_setup_complete.id

    # get RRCConnectionReconfiguration to find where SRB2 should be used
    rrc_conn_reconf = get_attach_message(attach_packets, '66')
    if rrc_conn_reconf:
        ue_info['locations']['attach_accept'] = rrc_conn_reconf.id

    if rrc_conn_reconf and not rrc_conn_reconf.data.get('lte-rrc.SRB_ToAddMod_element'):
        rrc_conn_reconf.add_analysis('No SRB-ToAddMod present. From attach accept, NAS/RRC should travel over SRB2.', 2)

    # for all packets, check for correct SRB
    for packet in attach_packets:
        if rrc_conn_reconf and packet.id > rrc_conn_reconf.id + 1:
            if packet.data.get('rlc-lte.channel-type') != '4':
                packet.add_analysis('Attach message not travelling over SRB. This should always be the case.', 3)
            elif packet.data.get('rlc-lte.channel-id') == '1':
                packet.add_analysis('Attach message travelling over SRB1 after attach accept.', 2)
            elif packet.data.get('rlc-lte.channel-id') != '2':
                packet.add_analysis('Attach message not travelling over SRB1 or SRB2 after attach accept.', 3)
        elif packet.id >= rrc_conn_setup_complete.id:
            if packet.data.get('rlc-lte.channel-type') != '4':
                packet.add_analysis('Attach message not travelling over SRB. This should always be the case.', 3)
            elif packet.data.get('rlc-lte.channel-id') != '1' and 'Ciphered message' not in packet.full_summary:
                packet.add_analysis('Attach message not travelling over SRB1. This should always be the case during the attach procedure.', 3)


def correct_security_options(packets, ue_info):
    """Checks if correct security options are used every time for PDCP."""
    rrc_smc = ue_info['locations']['rrc_smc'] + 1
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



def mac_invalid_behaviour(packets, attach_packets, ue_info):
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
    if complete or safe_dict_get(ue_info, 'rrc_ca') != 'eea0':
        return

    # find if attach packet is last packet of capture
    last_attach = attach_packets[-1]
    if last_attach == packets[-1]:
        # send warning for possible incomplete file or invalid PDCP MAC
        last_attach.add_analysis('Attach procedure incomplete.\nIf there are no possible causes listed in this packet, it might be because of an invalid MAC.', 1)
    else:
        # send error for probable invalid PDCP MAC
        last_attach.add_analysis('Attach procedure incomplete.\nThis might be because of an invalid PDCP MAC.', 3)
