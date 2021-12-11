def categorise(packet, summary):
    categories = []
    layer = packet.layers[2]
    if 'RRCConnection' in summary:
        categories.append('RRC Connection Establishment')
    if 'Attach' in summary:
        categories.append('Attach Procedure')
    if 'InformationTransfer' in summary:
        categories.append('Information Transfer')
    if 'Identity' in summary:
        categories.append('Identity Request/Response')
    if 'Authentication' in summary:
        categories.append('Authentication Procedure')
    if 'SecurityMode' in summary or 'Security mode' in summary:
        categories.append('Security Mode Command')
    if 'UECapability' in summary:
        categories.append('UE Capability Information')
    if 'Information Transfer' in categories or 'Security Mode Command' in categories or 'UE Capability Information' in categories:
        categories.append('Attach Procedure')
    if 'Detach' in summary and 'Attach procedure' in categories:
        categories.remove('Attach procedure')
    if layer.get('rlc-lte.am.ack-sn'):
        categories.append('ACK packet')
    if len(categories) == 0:
        categories.append('Unassigned')
    categories = list(dict.fromkeys(categories))
    return categories

