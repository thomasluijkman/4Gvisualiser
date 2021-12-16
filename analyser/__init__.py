def safe_dict_get(dictionary, key, default=None):
    try:
        retval = dictionary[key]
    except KeyError:
        retval = default
    return retval


def get_attach_message(packets, msg_type):
    for packet in packets:
        if packet.data.layers[2].get('nas_eps.nas_msg_emm_type') == msg_type:
            return packet
    return None
