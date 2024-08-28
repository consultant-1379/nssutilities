import datetime

from nssutils.lib import enm_user_2


LCMADM_LIST_CMD = 'lcmadm list -cu'
LCMADM_DATETIME_FORMAT = '%b %d %Y %H:%M:%S %Z'
LICENCE_PERSISTENCE_KEY = 'licence-%s'
SUPPORTED_NODE_TYPES = ["ERBS", "SGSN", "MME", "RadioNode", "MSRBS_V1",
                        "MGW", "EPG", 'VEPG', 'SAPC', 'RNC', 'RBS', "RadioTNode", "MTAS", "SBG", "CSCF", "WMG", "vWMG", "DSC",
                        "CSCF-TSP", "MTAS-TSP", "HSS-FE-TSP", "cSAPC-TSP", "CCN-TSP", "VPN-TSP", "SIU02", "TCU02", "SBG-IS"]


def parse_licence_list(enm_cli_response):
    """
    B{Parses licence list given the script engine response}

    @type enm_cli_response: list[string]
    @param enm_cli_response: response from ENM CLI
    @rtype: dict
    """
    if len(enm_cli_response) < 3:
        return

    headers = _get_values_from_row(enm_cli_response[2])
    for line in enm_cli_response[3:]:
        yield dict(zip(headers, _get_values_from_row(line)))


def _get_values_from_row(row):
    """
    B{Get the list of values from the response row}

    @type row: string
    @param row: script engine row list
    @rtype: list[string]
    """
    return [val.strip() for val in row.split('\t')]


def get_valid_licence(node_type='ERBS'):
    """
    B{Returns the valid licence with parsedDate field as well}

    @type node_type: str
    @param node_type: type of nodes to check licence for
    @rtype: dict
    """
    assert node_type in SUPPORTED_NODE_TYPES

    # Hack to get the node_type, since the parsed response doesn't provide us with the node type,
    # we have to check for the specific substring presence in the "Vendor Info" field
    # There is no capacity licence for EPG, VEPG, SAPC or RNC at the moment
    # A capacity licence will be needed for RBS once the licence has been confirmed
    node_type_vendor_info_substring_mapping = {
        'ERBS': '5mhzsc',
        'SGSN': 'ksau',
        'MME': 'ksau',
        'MGW': 'scc',
        'RadioNode': '5mhzsc',
        'MSRBS_V1': '5mhzsc',
        'EPG': '',
        'VEPG': '',
        'SAPC': '',
        'MTAS': '',
        'SBG': '',
        'SBG-IS': '',
        'CSCF': '',
        'RNC': '',
        'RBS': '',
        'RadioTNode': '',
        'WMG': '',
        'vWMG': '',
        'DSC': '',
        'CSCF-TSP': '',
        'MTAS-TSP': '',
        'HSS-FE-TSP': '',
        'cSAPC-TSP': '',
        'CCN-TSP': '',
        'VPN-TSP': '',
        'SIU02': '',
        'TCU02': ''
    }

    user = enm_user_2.get_admin_user()
    response = user.enm_execute(LCMADM_LIST_CMD)
    if "Error" in "\n".join(response.get_output()):
        raise RuntimeError("Could not get licenses in ENM: {error}".format(error=response.get_output()))

    for licence in parse_licence_list(response.get_output()):
        if 'Never' in licence['Expiry Date'] or 'never' in licence['Expiry Date']:
            if licence.has_key('Vendor Info') and node_type_vendor_info_substring_mapping.has_key(node_type):
                if licence['Vendor Info'].lower().endswith(node_type_vendor_info_substring_mapping[node_type]):
                    return licence
        elif 'expired' not in licence['Expiry Date']:
            now = datetime.datetime.now()
            date = datetime.datetime.strptime(licence['Expiry Date'], LCMADM_DATETIME_FORMAT)
            if date > now:
                licence['parsedDate'] = date
                if licence['Vendor Info'].lower().endswith(node_type_vendor_info_substring_mapping[node_type]):
                    return licence
