from analyser import safe_dict_get


def analyse(packets, ue_info):
    for packet in packets:
        if packet.data.layers[2].get('nas_eps.nas_msg_emm_type') == '85':
            nas_identity_85(packet, ue_info)  # Information request
        elif packet.data.layers[2].get('nas_eps.nas_msg_emm_type') == '86':
            nas_identity_86(packet, ue_info)  # Information response
        packet.category.append('Analysed')


def nas_identity_85(packet, ue_info):
    # check if asked value is IMSI
    request_type = packet.data.layers[2].get('nas_eps.emm.id_type2')
    if not request_type == '1':
        packet.add_analysis('ELVis only follows srsRAN implementation, which only requests IMSI.', 0)
        packet.add_analysis('Analysis results might not be completely accurate.', 0, custom_preamble='\t')
    ue_info['identity_request_type'] = request_type


def nas_identity_86(packet, ue_info):
    # check if requested type is response type
    response_type = packet.data.layers[2].get('gsm_a.ie.mobileid_type')
    if not ue_info['identity_request_type'] == response_type:
        packet.add_analysis('Identity response does not contain queried value by MME.', 3)

    # check if response matches known value
    imsi = safe_dict_get(ue_info, 'imsi')
    if imsi and not imsi == packet.data.layers[2].get('e212.imsi'):
        packet.add_analysis('IMSI in response does not match value from SIM configuration.', 1)
        packet.add_analysis('Changing stored value to value read from identity response.', 0)
    ue_info['imsi'] = packet.data.layers[2].get('e212.imsi')
