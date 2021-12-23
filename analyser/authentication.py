from analyser import *
from CryptoMobile.Milenage import Milenage


def analyse(packets, ue_info):
    for packet in packets:
        if packet.data.get('nas_eps.nas_msg_emm_type') == '82':
            nas_authentication_82(packet, ue_info)  # NAS authentication request
        elif packet.data.get('nas_eps.nas_msg_emm_type') == '83':
            nas_authentication_83(packet, packets, ue_info)  # NAS authentication response
        packet.category.append('Analysed')


def nas_authentication_82(packet, ue_info):
    # initialise authentication field for UE info
    ue_info['authentication'] = {}

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


def nas_authentication_83(packet, packets, ue_info):
    # get values received from authentication request
    autn = bytes.fromhex(safe_dict_get(ue_info['authentication'], 'autn'))
    rand = bytes.fromhex(safe_dict_get(ue_info['authentication'], 'rand'))

    # if values exist, calculate expected response
    if rand and autn:
        key = safe_dict_get(ue_info['sim_info'], 'key')
        algo = safe_dict_get(ue_info['sim_info'], 'auth')
        # print warning if correctness of res can not be checked
        if not key:
            packet.add_analysis('RES value can not be analysed, due to the key not being known.\nTo analyse RES value, use -sim option.', 1)
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
            elif algo == 'xor':
                # get RES, CK, IK and AK values
                xdout = bytes([key[i] ^ rand[i] for i in range(len(key))])
                xres = bytes.hex(xdout)
                ck = [xdout[(i + 1) % len(xdout)] for i in range(len(xdout))]
                ik = [xdout[(i + 2) % len(xdout)] for i in range(len(xdout))]
                ak = [xdout[(i + 3)] for i in range(6)]
            else:
                packet.add_analysis('RES value can not be analysed, due to the algorithm not being known.\nTo analyse RES value, use -sim option.', 1)
                return

            # check if authentication should be successful by comparing RES and XRES
            res = ''.join(packet.data.get('nas_eps.emm.res').split(':'))
            xres = bytes.hex(xres)
            if res != xres:
                packet.add_analysis(f'RES ({res}) does not match expected value ({xres})', 4)
                if not get_attach_message(packets, '92'):
                    packet.add_analysis('No authentication failure message sent after mismatch in expected value.', 3)

            # update keys
            ue_info['keys'] = {}
            ue_info['keys']['ck'] = ck
            ue_info['keys']['ik'] = ik
            ue_info['keys']['ak'] = ak
