def analyse(packets, ue_info):
    for packet in packets:
        if packet.data.layers[2].get('nas_eps.nas_msg_emm_type') == '93':
            nas_smc93(packet, packets, ue_info)  # NAS-EPS SecurityModeCommand
        elif packet.data.layers[2].get('nas_eps.nas_msg_emm_type') == '94':
            pass  # NAS-EPS SecurityModeComplete
        elif packet.data.layers[2].get('nas_eps.nas_msg_emm_type') == '95':
            pass  # NAS-EPS SecurityModeFailure
        elif packet.data.layers[2].get('lte-rrc.securityModeCommand_element') == 'securityModeCommand':
            rrc_smc_command(packet, packets, ue_info)  # RRC SecurityModeCommand
        elif packet.data.layers[2].get('lte-rrc.securityModeComplete_element') == 'securityModeComplete':
            rrc_smc_complete(packet, packets, ue_info)  # RRC SecurityModeComplete
        elif packet.data.layers[2].get('lte-rrc.securityModeFailure_element') == 'securityModeFailure':
            pass  # RRC SecurityModeFailure
        packet.category.append('Analysed')



def nas_smc93(packet, packets, ue_info):
    """Analyses the NAS-EPS SecurityModeCommand message."""
    from analyser.analysis import filter_dictionary
    filter_list = [k for (k, v) in ue_info['security_capabilities'].items()]
    packet_info = {k.split('.')[-1]: v for (k, v) in
                   filter_dictionary(vars(packet.data.layers[2])['_all_fields'], filter_list).items()}

    # gather chosen values
    ca, ia = smc_algorithms(packet, 'nas_eps.emm.toc', 'nas_eps.emm.toi')

    # check for accurate security capabilities (matching from attach request)
    if not packet_info == ue_info['security_capabilities']:
        packet.add_analysis(
            'WARNING: Security capabilities in NAS security mode command do not match capabilities in attach request.',
            1)

    # check if UE capable of ciphering algorithm
    if ue_info['security_capabilities'][ca] == '0':
        packet.add_analysis('ERROR: UE not capable of using NAS chosen ciphering algorithm.', 3)
        nas_smc_fail_sent(packet, packets)

    # check if UE capable of integrity algorithm
    if ue_info['security_capabilities'][ia] == '0':
        packet.add_analysis('ERROR: UE not capable of using NAS chosen integrity algorithm.', 3)
        nas_smc_fail_sent(packet, packets)

    # check if ciphering and integrity protection are used
    smc_algo_used(packet, ca, ia)

    # save ciphering and integrity algorithm
    ue_info['nas_ca'] = ca
    ue_info['nas_ia'] = ia


def rrc_smc_command(packet, packets, ue_info):
    """Analyses the RRC SecurityModeCommand message."""

    # gather chosen values
    ca, ia = smc_algorithms(packet, 'lte-rrc.cipheringAlgorithm', 'lte-rrc.integrityProtAlgorithm')

    # check if UE capable of ciphering algorithm
    if ue_info['security_capabilities'][ca] == '0':
        packet.add_analysis('ERROR: UE not capable of RRC chosen ciphering algorithm.')
        rrc_smc_fail_sent(packet, packets)

    # check if UE capable of integrity protection algorithm
    if ue_info['security_capabilities'][ia] == '0':
        packet.add_analysis('ERROR: UE not capable of RRC chosen integrity protection algorithm.')
        rrc_smc_fail_sent(packet, packets)

    # check if ciphering and integrity protection are used
    smc_algo_used(packet, ca, ia)

    # save ciphering and integrity algorithm
    ue_info['rrc_ca'] = ca
    ue_info['rrc_ia'] = ia

def rrc_smc_complete(packet, packets, ue_info):
    """Analyses the RRC SecurityModeComplete message."""

    # gather configured values
    try:
        ca = ue_info['rrc_ca']
    except KeyError:
        ca = None

    try:
        ia = ue_info['rrc_ia']
    except KeyError:
        ia = None

    # check if PDCP uses configured values
    pdcp_ca, pdcp_ia = smc_algorithms(packet, 'pdcp-lte.security-config.ciphering', 'pdcp-lte.security-config.integrity')
    if ca and not pdcp_ca == ca:
        packet.add_analysis('WARNING: PDCP does not use configured RRC ciphering algorithm.')
    if ia and not pdcp_ia == ia:
        packet.add_analysis('WARNING: PDCP does not use configured RRC integrity protection algorithm.')

def smc_algorithms(packet, ca_loc, ia_loc):
    ca = 'eea' + packet.data.layers[2].get(ca_loc)
    if ca == 'eea1' or ca == 'eea2':
        ca = '128' + ca
    ia = 'eia' + packet.data.layers[2].get(ia_loc)
    if ia == 'eia1' or ia == 'eia2':
        ia = '128' + ia
    return ca, ia


def smc_algo_used(packet, ca, ia):
    """Checks if the ciphering and integrity algorithms are used. Warns the user if any of them are not used."""

    # check if ciphering is used
    if ca == 'eea0':
        packet.add_analysis(
            'WARNING: Null ciphering algorithm in use. Data is not encrypted over air interface.\n\t Data could be read by third parties.',
            1)

    # check if integrity algorithm is used
    if ia == 'eia0':
        packet.add_analysis(
            'WARNING: No integrity protection algorithm in use. \n\t Data could be tampered with by third parties.', 2)


def nas_smc_fail_sent(packet, packets):
    """Checks if the packet capture contains a NAS-EPS SecurityModeFailure message."""
    failure_known = False
    # check if SecurityModeFailure message sent
    for packet in packets:
        if packet.data.layers[2].get('nas_eps.nas_msg_emm_type') == '95':
            failure_known = True
    if not failure_known:
        packet.add_analysis('\tUE has not sent a failure message for incapability.', 2)


def rrc_smc_fail_sent(packet, packets):
    """Checks if the packet capture contains a RRC SecurityModeFailure message."""
    failure_known = False
    # check if SecurityModeFailure message sent
    for packet in packets:
        if packet.data.layers[2].get('lte-rrc.securityModeFailure_element') == 'securityModeFailure':
            failure_known = True
    if not failure_known:
        packet.add_analysis('\tUE has not sent a failure message for incapability.', 2)
