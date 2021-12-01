def categorise(packet, summary):
    categories = []
    layer = packet.layers[2]
    if 'RRCConnectionRequest' in summary:
        categories.append('RRC Connection Establishment')
    if 'RRCConnectionSetup' in summary:
        categories.append('RRC Connection Establishment')
    if 'RRCConnectionSetupComplete' in summary:
        categories.append('RRC Connection Establishment')
    if 'RRCConnectionReconfiguration' in summary:
        categories.append('RRC Connection Establishment')
    if 'ULInformationTransfer' in summary:
        categories.append('Information Transfer')
    if 'DLInformationTransfer' in summary:
        categories.append('Information Transfer')
    if 'SecurityMode' in summary or 'Security mode' in summary:
        categories.append('Security Mode Command')
    if layer.get('rlc-lte.am.ack-sn'):
        categories.append('ACK packet')
    if len(categories) == 0:
        categories.append('Unassigned')
    return categories

