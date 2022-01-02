from analyser import *
from CryptoMobile.Milenage import Milenage


def analyse(packets, ue_info):
    for packet in packets:
        if packet.data.get('nas_eps.nas_msg_emm_type') == '82':
            nas_authentication_82(packet, packets, ue_info)  # NAS authentication request
        elif packet.data.get('nas_eps.nas_msg_emm_type') == '83':
            nas_authentication_83(packet, packets, ue_info)  # NAS authentication response
        elif packet.data.get('nas_eps.nas_msg_emm_type') == '84':
            nas_authentication_84(packet, packets, ue_info)  # NAS authentication reject
        elif packet.data.get('nas_eps.nas_msg_emm_type') == '92':
            nas_authentication_92(packet, packets, ue_info)  # NAS authentication failure
        packet.category.append('Analysed')


def nas_authentication_82(packet, packets, ue_info):
    # initialise authentication field for UE info
    ue_info['authentication'] = {}
    ue_info['locations']['nas_82'] = packet.id

    # check for RAND value
    rand = ''.join(packet.data.get('gsm_a.dtap.rand').split(':'))
    if rand:
        ue_info['authentication']['rand'] = rand
    else:
        packet.add_analysis('RAND value not present.', 3)

    # check for AUTN value
    autn = ''.join(packet.data.get('gsm_a.dtap.autn').split(':'))
    if autn:
        ue_info['authentication']['autn'] = autn
    else:
        packet.add_analysis('AUTN value not present.', 3)

    # calculate expected values
    calculate_auth_response(packet, packets, ue_info)


def nas_authentication_83(packet, packets, ue_info):
    # get values received from authentication request
    ue_info['locations']['nas_83'] = packet.id

    # check if authentication should be successful by comparing RES and XRES
    res = bytes.fromhex(''.join(packet.data.get('nas_eps.emm.res').split(':')))
    xres = safe_dict_get(ue_info['authentication'], 'xres')
    if not xres:
        packet.add_analysis('RES value not analysed.', 1)
    elif res != xres:
        packet.add_analysis(f'RES ({bytes.hex(res)}) does not match expected value ({bytes.hex(xres)})', 3)
        ue_info['authentication']['passed'] = False
        if not get_attach_message(packets, '84'):
            packet.add_analysis('No authentication reject was sent after mismatch in RES values.', 3)
    else:
        ue_info['authentication']['passed'] = True


def nas_authentication_84(packet, packets, ue_info):
    # check if authentication procedure happened
    autn_response = safe_dict_get(ue_info['locations'], 'nas_83')

    # if no authentication procedure happened when this message was sent, add error
    if not autn_response or autn_response > packet.id:
        packet.add_analysis('Authentication reject sent before authentication response.\nThis could be because of a malicious eNodeB carrying out a disruption of service attack.', 4)
    # if authentication response is present and reject happened after response, check if rejection is justified
    else:
        passed = safe_dict_get(ue_info['authentication'], 'passed')
        # add note if RES was not calculated
        if passed is None:
            packet.add_analysis('RES was not analysed in authentication response.\nTo analyse RES, use -sim option.', 0)
        # add error if RES != XRES
        elif passed:
            packet.add_analysis('Authentication reject was sent, though RES matched XRES.', 3)


def nas_authentication_92(packet, packets, ue_info):
    # check if authentication procedure happened
    autn_response = safe_dict_get(ue_info['locations'], 'nas_82')

    # if no authentication procedure happened when this messgae was sent, add error
    if not autn_response or autn_response > packet.id:
        packet.add_analysis('Authentication failure sent before authentication response.', 3)
    else:
        passed = safe_dict_get(ue_info['authentication'], 'mac_passed')
        # add note if MAC was not calculated
        if passed is None:
            packet.add_analysis('MAC was not analysed in authentication response.\nTo analyse MAC, use -sim option.', 0)
        elif passed and packet.data.get('nas_eps.emm.cause') == '20':
            packet.add_analysis('Authentication failure was sent with cause 20 (MAC failure), though MAC was as expected.', 3)


def calculate_auth_response(packet, packets, ue_info):
    # get values received from authentication request
    autn_str = safe_dict_get(ue_info['authentication'], 'autn')
    rand_str = safe_dict_get(ue_info['authentication'], 'rand')

    # if values exist, calculate expected response
    if rand_str and autn_str:
        # convert to bytes
        autn = bytes.fromhex(autn_str)
        rand = bytes.fromhex(rand_str)

        if not safe_dict_get(ue_info, 'sim_info'):
            packet.add_analysis('No SIM info available.\nTo analyse authentication response, use -sim option.', 0)
            return
        key = safe_dict_get(ue_info['sim_info'], 'key')
        algo = safe_dict_get(ue_info['sim_info'], 'auth')
        # print warning if correctness of res can not be checked
        if not key:
            packet.add_analysis(
                'RES value can not be analysed, due to the key not being known.\nTo analyse RES value, use -sim option.',
                1)
            return
        # check correctness for milenage algorithm
        else:
            if algo == 'mil':
                # create cipher
                if op := safe_dict_get(ue_info['sim_info'], 'op'):
                    cipher = Milenage(op)
                else:
                    opc = bytes.fromhex(safe_dict_get(ue_info['sim_info'], 'opc'))
                    cipher = Milenage(op)
                    cipher.set_opc(opc)

                # get RES, CK, IK and AK values
                xres, ck, ik, ak = cipher.f2345(key, rand)

                # get MAC
                sqn = bytes([autn[i] ^ ak[i] for i in range(0, 6)])
                mac = autn[8:]
                amf = safe_dict_get(ue_info['sim_info'], 'amf')

                xmac = cipher.f1(key, rand, sqn, amf)
            elif algo == 'xor':
                # get RES, CK, IK and AK values
                xdout = bytes([key[i] ^ rand[i] for i in range(len(key))])
                xres = bytes.hex(xdout)
                ck = bytes([xdout[(i + 1) % len(xdout)] for i in range(len(xdout))])
                ik = bytes([xdout[(i + 2) % len(xdout)] for i in range(len(xdout))])
                ak = bytes([xdout[(i + 3)] for i in range(6)])

                # get MAC
                sqn = bytes([autn[i] ^ ak[i] for i in range(6)])
                mac = autn[8:]
                amf = safe_dict_get(ue_info['sim_info'], 'amf')
                cdout = sqn + amf

                xmac = bytes([xdout[i] ^ cdout[i] for i in range(8)])
            else:
                packet.add_analysis(
                    'RES value can not be analysed, due to the algorithm not being known.\nTo analyse RES value, use -sim option.',
                    1)
                return

            # check if message authentication should be successful by comparing MAC and our own calculations
            if mac != xmac:
                packet.add_analysis(f'MAC ({bytes.hex(mac)}) does not match calculated value ({bytes.hex(xmac)})', 4)
                if not get_attach_message(packets, '92'):
                    packet.add_analysis(
                        'No authentication failure message sent after mismatch in expected value.', 3)
                ue_info['authentication']['mac_passed'] = False
            else:
                ue_info['authentication']['mac_passed'] = True

            ue_info['authentication']['xres'] = bytes(xres)

            # update keys
            ue_info['keys'] = {}
            ue_info['keys']['ck'] = ck
            ue_info['keys']['ik'] = ik
            ue_info['keys']['ak'] = ak