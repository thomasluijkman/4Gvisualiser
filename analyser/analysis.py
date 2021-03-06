from analyser import safe_dict_get

import analyser.smc as smc
import analyser.identity as identity
import analyser.authentication as authentication
import analyser.attach as attach

def filter_dictionary(dictionary, flist):
    new_dict = {}
    for (k, v) in dictionary.items():
        for fstring in flist:
            if fstring in k:
                new_dict[k] = v
                break
    return new_dict


def split_packets(data, categories):
    packets = {}
    for category in categories:
        category_data = []
        for packet in data:
            if category in packet.category:
                category_data.append(packet)
        packets[category] = category_data
    return packets


class Analyser:
    def __init__(self, data, categories, ue_info=None):
        """Class representing the 4G/LTE network analyser."""
        if ue_info is None:
            ue_info = {}
        self.data = data
        self.split_data = split_packets(data, categories)
        self.ue_info = ue_info

    def analyse(self):
        self.get_ue_info()
        if safe_dict_get(self.split_data, 'Identity Request/Response'):
            identity.analyse(self.split_data['Identity Request/Response'], self.ue_info)
        if safe_dict_get(self.split_data, 'Authentication Procedure'):
            authentication.analyse(self.split_data['Authentication Procedure'], self.ue_info)
        if safe_dict_get(self.split_data, 'Security Mode Command'):
            smc.analyse(self.split_data['Security Mode Command'], self.ue_info)
        if safe_dict_get(self.split_data, 'Attach Procedure'):
            attach.analyse(self.data, self.split_data['Attach Procedure'], self.ue_info)

    def get_ue_info(self):
        """Get UE info based on attach request packet."""

        # find interesting packets
        request = None
        for (_, category) in self.split_data.items():
            for packet in category:
                if 'Attach request' in packet.full_summary:
                    request = packet.data
                    break
        if not request:
            raise MissingUserEquipmentInfoException

        # get interesting values
        self.ue_info['locations'] = {}
        self.ue_info['m-tmsi'] = request.get('nas_eps_emm_m_tmsi')
        self.ue_info['security_capabilities'] = filter_dictionary(vars(request)['_all_fields'], ['eea', 'eia', 'uea', 'uia', '.gea'])
        self.ue_info['security_capabilities'] = {k.split('.')[-1]: v for (k, v) in self.ue_info['security_capabilities'].items()}


class MissingUserEquipmentInfoException(Exception):
    def __init__(self):
        self.message = 'No attach request found, making it impossible to receive UE information.'
        super().__init__(self.message)
