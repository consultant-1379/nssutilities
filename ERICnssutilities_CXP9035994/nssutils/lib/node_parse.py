#!/usr/bin/env python
import os
import re
import csv
import base64
import collections
import log
from nssutils.lib.enm_node import SnmpVersion, SnmpAuthenticationMethod, SnmpEncryptionMethod, Site
import cache
import config
import network
import exception
import model_info
import filesystem
import lxml.etree as et

node_removal_fault_dict = None

INVALID_MIM_ERROR_MESSAGE = "mim_version:could not retrieve oss model identity"


def validate_xml_dir(xml_dir, operation):
    """
    Validates the user-specified input directory.

    :param xml_dir: The absolute path to the directory that contains all xml's to be parsed
    :type xml_dir: str
    :param operation: An operation from the tools netsim and node_populator (i.e. fetch or parse)
    :type operation: str
    """

    if not xml_dir:
        exception.handle_invalid_argument("%s operation requires an XML input directory" % operation)

    if not filesystem.does_dir_exist(xml_dir):
        if operation == 'parse':
            exception.handle_invalid_argument("Specified XML input directory ({0}) doesn't exist".format(xml_dir))
        filesystem.create_dir(xml_dir)
    else:
        if operation == 'parse' and not os.listdir(xml_dir):
            exception.handle_invalid_argument("Specified XML input directory ({0}) is empty".format(xml_dir))


def create_csv_file(csv_file, input_dir, verbose=False, warn_validation_errors=False):
    """
    Parses the xml files in a given directory. Writes the nodes to a csv file

    :param csv_file: File to write to
    :type csv_file: str
    :param input_dir: Location of the xml files to parse
    :type input_dir: str
    :param verbose: Flag controlling whether additional information is printed to console during execution
    :type verbose: bool
    :param warn_validation_errors: Flag indicating whether or not to log validation errors
    :type warn_validation_errors: bool
    """

    files = get_xml_files(input_dir)
    nodes = []

    for xml_file in files:
        parsed_data = parse(xml_file, verbose=verbose)
        validated_data = validate(parsed_data, warn_validation_errors=warn_validation_errors)
        nodes.append(validated_data)
    write_csv(nodes, csv_file)


def get_xml_files(directory):
    """
    Gets the xml files in a given directory

    :param directory: Directory to check
    :type directory: str

    :returns: A list of xml files
    :rtype: list
    """

    xml_files = []
    if filesystem.does_dir_exist(directory):
        files = filesystem.get_files_in_directory(directory, ends_with=".xml")
        for filename in files:
            xml_files.append(os.path.realpath(os.path.join(directory, filename)))
    return xml_files


def update(nodes_file, treatas_file=None):
    """
    Updates simulations in the parsed nodes file with new OSS model identities

    :param nodes_file: Parsed nodes file
    :type nodes_file: str
    :param treatas_file: Treat As file
    :type treatas_file: str
    """

    model_ids = None
    if treatas_file:
        if not filesystem.does_file_exist(treatas_file):
            exception.handle_invalid_argument()

        # Load the model ids from the Treat As file
        model_ids = _load_model_ids(treatas_file)
        if not model_ids:
            exception.process_exception("The treat as file you supplied is empty", fatal=True, print_msg_to_console=True)

    updated_nodes = update_nodes(nodes_file, model_ids)
    if len(updated_nodes) > 0:
        write_csv([updated_nodes], nodes_file)


def _load_model_ids(treatas_file):
    """
    Load OSS model identity from file

    :param treatas_file: Treat As file
    :type treatas_file: str

    :return: A dict with simulations as keys
    :rtype: dict
    """

    treat_as = {}
    header_found = False
    with open(treatas_file) as fh:
        for sim_info in csv.reader(fh):
            if not sim_info or len(sim_info) < 4:
                continue

            sim_info = [field.strip() for field in sim_info]

            # Skip the header
            if not header_found:
                if "simulation" in sim_info or "oss_model_identity" in sim_info or "SIMULATION" in sim_info or "OSS_MODEL_IDENTITY" in sim_info:
                    header_found = True
                    continue

            treat_as[sim_info[0]] = {"oss_model_identity": sim_info[1], "product_identity": sim_info[2], "revision": sim_info[3]}

    return treat_as


def update_nodes(nodes_file, model_ids):
    """
    Updates simulations in the parsed nodes file with new OSS model identities

    :param nodes_file: Parsed nodes file
    :type nodes_file: string
    :param model_ids: Dictionary of simulations to OSS model identities
    :type model_ids: dict

    :return: A list of OrderedDicts
    :rtype: list
    """
    ordered_dicts = []
    header_found = False
    csv_headings = config.get_prop("csv_headings")

    with open(nodes_file) as fh:
        for node_info in csv.reader(fh, skipinitialspace=True):
            ordered_dict = collections.OrderedDict()

            if not header_found:
                if "simulation" in node_info or "oss_model_identity" in node_info:
                    header_found = True
                    continue

            # Use ordered dict for writing later
            if len(csv_headings) != len(node_info):
                continue
            for i in xrange(0, len(csv_headings)):
                ordered_dict[csv_headings[i]] = node_info[i]

            # Check model ids
            if model_ids.has_key(ordered_dict['simulation']):
                entry = model_ids[ordered_dict['simulation']]
                ordered_dict['oss_model_identity'] = entry['oss_model_identity']
                ordered_dict['revision'] = entry['revision']
                ordered_dict['identity'] = entry['product_identity']
                # Clear if this is one of our simulations.
                ordered_dict['invalid_fields'] = ''

            ordered_dicts.append(ordered_dict)

    return ordered_dicts


def performIsiteParamParse(node_data):
    """ Performs Isite specific key/value updation to keep it aligned with generic node key/values """
    node_data['primary_type'] = 'SBG-IS'
    csv_headings = config.get_prop("csv_headings")
    additional_keys = set(node_data.keys()) - set(csv_headings)
    for key in additional_keys:
        if key.startswith("isite_"):
            node_data[key.replace("isite_", "")] = node_data.pop(key)
    return node_data


def parse(xml_file, network_elements=None, verbose=False):
    """
    Parses data from one xml file. Returns a list of OrderedDict

    :param xml_file: File to parse data from
    :type xml_file: str
    :param network_elements: List of NetworkElements that we want to parse from the xml file
    :type network_elements: list
    :param verbose: Flag controlling whether additional information is printed to console during execution
    :type verbose: bool

    :returns: A list of OrderedDict, each dictionary contains information for one node
    :rtype: list
    """
    network_elements = network_elements or []
    parser = Parser(xml_file, network_elements)
    return parser.parse_data(verbose=verbose)


def load_model_info(primary_type):
    """
    Retrieves the model information from ENM for the supplied model

    :type primary_type: str
    :param primary_type: The primary type to retrieve a model information of

    :rtype: dict
    :return: Dict of models matching the primary type supplied
    """
    model_info_dict = {}
    model_identities = {
        "LH": "MINI-LINK-Indoor",
        "MLTN": "MINI-LINK-Indoor",
        "SpitFire": "Router6672",
        "Router_6672": "Router6672",
        "SGSN": "SGSN-MME",
        "PT2020": "MINI-LINK-PT2020",
        "PT": "MINI-LINK-PT2020",
        "switch-6391": "Switch-6391",
        "Fronthaul-6080": "FRONTHAUL-6080",
        "JUNIPER": "JUNIPER-MX",
        "C608": "RadioTNode",
        "TCU04": "RadioTNode",
        "EPDG": "WMG",
        "WCG": "vWCG",
        "EME": "vEME"

    }
    model_id = model_identities.get(primary_type) or primary_type
    key = "{0}-models".format(model_id)
    if not cache.has_key(key):
        model_info_map = model_info.get_supported_model_info(models=[model_id])[model_id]
        if primary_type in config.get_prop("cpp_primary_types"):

            for model in model_info_map:
                model_info_dict[model.mim_version] = model.model_id
        else:
            for model in model_info_map:
                model_info_dict[model.ne_release] = {'oss_model_identity': model.model_id, 'revision': model.revision,
                                                     'identity': model.software_version}
                model_info_dict[model.model_id] = {'oss_model_identity': model.model_id, 'revision': model.revision,
                                                   'identity': model.software_version}
        cache.set(key, model_info_dict)
    else:
        model_info_dict = cache.get(key)
    return model_info_dict


def validate(parsed_data, warn_validation_errors=False):
    """
    Validates the list of OrderedDicts. Returns a list of OrderedDicts

    :type parsed_data: list
    :param parsed_data: List of OrderedDicts
    :type warn_validation_errors: bool
    :param warn_validation_errors: Flag indicating whether or not to log validation errors

    :returns: A list of OrderedDict, each dictionary contains information for one node
    :rtype: list
    """

    d = Duplicates()
    validation_failed = False
    non_cpp_isite = (config.get_prop("com_ecim_primary_types") + config.get_prop("er6000_primary_types") +
                     config.get_prop("stn_primary_types") + config.get_prop("mltn_primary_types") +
                     config.get_prop("apg_primary_types"))
    for node_data in parsed_data:
        if "primary_type" not in node_data.keys():
            node_data['invalid_fields'] = "primary_type: key missing from properties.conf"
            continue
        if node_data['primary_type'] in ["ECM"]:
            node_data['primary_type'] = "vMSC"
        if node_data['primary_type'] in ["STP"]:
            node_data['primary_type'] = "IP-STP"
        if node_data['primary_type'] in ["BSP", "BSPHybrid", "BSP8100"]:
            node_data['primary_type'] = "MSC-BC-BSP"
        if node_data['primary_type'] in ["STN"]:
            node_data['primary_type'] = node_data["simulation"].split("-")[-1]
        if node_data['primary_type'] in config.get_prop("cpp_primary_types"):
            v = CppValidate(node_data, d, load_model_info(node_data['primary_type']))
        elif node_data['primary_type'] in non_cpp_isite:
            v = COMECIMValidate(node_data, d, load_model_info(node_data['primary_type']))
        elif node_data['primary_type'] in config.get_prop("isite_primary_types"):
            v = IsiteValidate(node_data, d, load_model_info(node_data['primary_type']))
        else:
            v = Validate(node_data, d)
        if not _skip_validation():
            v.validate()

        if node_data.get('invalid_fields') and not _skip_validation():
            validation_failed = True
    if warn_validation_errors:
        if validation_failed:
            log.logger.warn("Warning: Validation failed - please check the invalid fields column of your "
                            "parsed file in int/nodes")
    return parsed_data


class Duplicates(object):
    def __init__(self):
        self.ips = {}
        self.managed_element_ids = {}


class Validate(object):
    def __init__(self, node_data, duplicates):
        self.supported_primary_types = config.get_prop("supported_primary_types")
        self.node_data = node_data
        self.duplicates = duplicates

    def validate(self):
        """
        Performs validation central to all primary types of node

        """

        # Key checks. We checked primary_type already
        keys = self.node_data.keys()
        if 'node_name' not in keys:
            self.node_data['invalid_fields'] = "node_name: key missing from properties.conf"
            return
        if 'node_ip' not in keys:
            self.node_data['invalid_fields'] = "node_ip: key missing from properties.conf"
            return
        if 'invalid_fields' not in keys:
            self.node_data['invalid_fields'] = "invalid_keys: key missing from properties.conf"

        if self.node_data['primary_type'] not in self.supported_primary_types:
            self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], "primary_type:(warning) may not be supported"))

        if self.node_data['primary_type'] == "" or self.node_data['primary_type'] is None:
            self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], "primary_type:empty field"))

        node_name = self.node_data['node_name']
        if not self.node_data['node_ip'] and 'cluster_ip' in self.node_data.keys():
            self.node_data['node_ip'] = self.node_data['node_ip'] or self.node_data['cluster_ip']
        node_ip = self.node_data['node_ip']

        if node_name == "":
            self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], "node_name:empty field"))

        if node_ip == "":
            self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], "node_ip:empty field"))

        if self.duplicates.ips.has_key(node_ip):
            self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], "node_ip:duplicate ip"))

        else:
            self.duplicates.ips[node_ip] = 0

        if self.duplicates.managed_element_ids.has_key(node_name):
            self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], "node_name:duplicate id"))

        else:
            self.duplicates.managed_element_ids[node_name] = 0

        if not network.is_valid_ip(node_ip):
            self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], "node_ip:bad ip address"))


class CppValidate(Validate):
    def __init__(self, node_data, duplicates, MODEL_INFO_MAP):
        super(CppValidate, self).__init__(node_data, duplicates)
        self.MODEL_INFO_MAP = MODEL_INFO_MAP

    def validate(self):
        """
        Performs validation for a CPP node

        """
        super(CppValidate, self).validate()
        # Key checks
        keys = self.node_data.keys()
        if 'mim_version' not in keys:
            self.node_data['invalid_fields'] = "mim_version: key missing from definition"
            return
        if 'oss_model_identity' not in keys:
            self.node_data['invalid_fields'] = "oss_model_identity: key missing from definition"
            return

        mim_version = self.node_data['mim_version']
        if mim_version != "":
            if mim_version.startswith("v"):
                mim_version = mim_version.strip("v")

            model_info = self.MODEL_INFO_MAP
            if model_info.has_key(mim_version):
                self.node_data['oss_model_identity'] = model_info[mim_version]
            else:
                self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], INVALID_MIM_ERROR_MESSAGE))
        else:
            self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], "mim_version:bad mim version"))


class COMECIMValidate(Validate):
    def __init__(self, node_data, duplicates, MODEL_INFO_MAP):
        super(COMECIMValidate, self).__init__(node_data, duplicates)
        self.MODEL_INFO_MAP = MODEL_INFO_MAP

    def validate(self):
        """
        Performs validation for a COMECIM node

        """
        super(COMECIMValidate, self).validate()

        # Further key checks
        keys = self.node_data.keys()
        if 'node_version' not in keys:
            self.node_data['invalid_fields'] = "node_version: key missing from properties.conf"
            return
        if 'oss_model_identity' not in keys:
            self.node_data['invalid_fields'] = "oss_model_identity: key missing from properties.conf"
            return
        if 'revision' not in keys:
            self.node_data['invalid_fields'] = "revision: key missing from properties.conf"
            return
        if 'identity' not in keys:
            self.node_data['invalid_fields'] = "identity: key missing from properties.conf"
            return
        if self.node_data['primary_type'] in ['STN', 'TCU02', 'SIU02']:
            node_version = self.node_data['node_version'].split('T')[-1]
        else:
            node_version = self.node_data['node_version']
        if node_version == "" or node_version is None:
            self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], "node_version:empty field"))

        keys = self.MODEL_INFO_MAP.keys()

        search_key = ""
        if self.node_data['oss_model_identity'] in keys:
            search_key = self.node_data['oss_model_identity']
        elif node_version in keys:
            search_key = node_version

        if not search_key:
            self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], "WARNING NE Release (node_version) {0} not found with cmedit describe --netype <netype>".format(node_version)))
            return

        model_info = self.MODEL_INFO_MAP[search_key]
        if model_info.has_key('oss_model_identity') and model_info.has_key('identity') and model_info.has_key('revision'):
            self.node_data['oss_model_identity'] = model_info['oss_model_identity']
            if self.node_data['primary_type'] not in ['STN', 'TCU02', 'SIU02', 'MLTN', 'Router_6672', 'SpitFire']:
                self.node_data['revision'] = model_info['revision']
                self.node_data['identity'] = model_info['identity']
        else:
            self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], "oss_model_identity:could not retrieve oss model identity"))


class IsiteValidate(Validate):
    def __init__(self, node_data, duplicates, MODEL_INFO_MAP):
        super(IsiteValidate, self).__init__(node_data, duplicates)
        self.MODEL_INFO_MAP = MODEL_INFO_MAP

    def validate(self):
        """
        Performs validation for a Isite  node
        """

        super(IsiteValidate, self).validate()

        # Further key checks
        keys = self.node_data.keys()
        if 'node_version' not in keys:
            self.node_data['invalid_fields'] = "node_version: key missing from properties.conf"
            return
        if 'oss_model_identity' not in keys:
            self.node_data['invalid_fields'] = "oss_model_identity: key missing from properties.conf"
            return
        if 'revision' not in keys:
            self.node_data['invalid_fields'] = "revision: key missing from properties.conf"
            return
        if 'identity' not in keys:
            self.node_data['invalid_fields'] = "identity: key missing from properties.conf"
            return

        if self.node_data['node_version'] == "" or self.node_data['node_version'] is None:
            self.node_data['invalid_fields'] = " - ".join((self.node_data['invalid_fields'], "node_version:empty field"))
        else:
            print self.node_data['node_version']


def write_csv(validated_data, csv_file, verbose=True):
    """
    Writes the validated data to a csv file

    :param validated_data: List of OrderedDicts
    :type validated_data: list
    :param csv_file: File to write to
    :type csv_file: str
    :param verbose: Flag controlling whether additional information is printed to console during execution
    :type verbose: bool
    """

    # Write the sorted nodes out to file
    with open(csv_file, "w") as file_handle:
        # Write out the header row
        file_handle.write(", ".join(config.get_prop("csv_headings")) + "\n")

        for data_list in validated_data:
            for data_dict in data_list:
                for key, value in data_dict.iteritems():
                    if not isinstance(value, str):
                        if value is None:
                            data_dict[key] = ""
                        else:
                            data_dict[key] = str(value)
                file_handle.write(", ".join(data_dict.values()) + "\n")

    if verbose:
        log.logger.info("\nNode data written to {0}\n".format(csv_file))


def read_csv(input_file, range_start, range_end):
    """
    Read the node data from the csv file

    :param input_file: File with node data
    :type input_file: str
    :param range_start: Start position in the file (i.e. 1 takes the first node)
    :type range_start: str
    :param range_end: Finish position in the file
    :type range_end: str

    :returns: list of enm_node.Node objects
    :rtype: list
    """

    return build_nodes(get_node_data(input_file), range_start, range_end)


def get_node_data(input_file):
    """
    Gets the node data from the csv file

    :param input_file: File with node data
    :type input_file: string

    :returns: List of lists. Each list has node data
    :rtype: list
    :raises RuntimeError: raises if TypeError occurs and if file doesn't exists
    """
    if not filesystem.does_file_exist(input_file):
        raise RuntimeError("Could not find specified input file {0}".format(input_file))

    data = []
    with open(input_file) as node_file:
        reader = csv.DictReader(node_file, skipinitialspace=True)

        for row in reader:
            controlling_rnc = None
            try:
                primary_type = row.get('primary_type', None)
                if row.get('group_data') and row.get('netsim_fqdn') and primary_type in ["RBS", "RadioNode", "MSRBS_V2"]:
                    rnc = re.search(r'RNC\d+', row.get('group_data'))
                    controlling_rnc = "{0}_{1}".format(row.get('netsim_fqdn').replace('.vts.com', '').replace('.athtem.eei.ericsson.se', ''), rnc.group(0))
                if primary_type in config.get_prop('mltn_primary_types'):
                    security_name = row.get('snmp_security_name', None)
                    snmp_authentication_method = "MD5"
                    snmp_encryption_method = "DES"
                    if security_name:
                        snmp_authentication_method = "SHA1" if "SHA1" in security_name else snmp_authentication_method
                        snmp_encryption_method = "DES" if "DES" in security_name else snmp_encryption_method
                else:
                    snmp_encryption_method = SnmpEncryptionMethod.from_arne_value(row["snmp_encryption_method"]) if row.get("snmp_encryption_method") else None
                    snmp_authentication_method = SnmpAuthenticationMethod.from_arne_value(row["snmp_authentication_method"]) if row.get("snmp_authentication_method") else None
                data.append(dict(
                    node_id=row['node_name'],
                    node_ip=row['node_ip'],
                    mim_version=row['mim_version'],
                    model_identity=row['oss_model_identity'],
                    security_state=row['security_state'],
                    normal_user=base64.b64decode(row['normal_user']),
                    normal_password=base64.b64decode(row['normal_password']),
                    secure_user=base64.b64decode(row['secure_user']),
                    secure_password=base64.b64decode(row['secure_password']),
                    subnetwork=row['subnetwork'],
                    invalid_fields=row['invalid_fields'],
                    netconf_port=row['netconf'],
                    snmp_port=row['snmp'],
                    snmp_version=SnmpVersion.from_arne_value(row['snmp_versions']) if row['snmp_versions'] else SnmpVersion.SNMP_V2C,
                    snmp_community=row.get('snmp_community', None),
                    snmp_security_name=row.get('snmp_security_name', None),
                    snmp_authentication_method=snmp_authentication_method,
                    snmp_encryption_method=snmp_encryption_method,
                    revision=row.get('revision', None),
                    identity=row.get('identity', None),
                    primary_type=primary_type,
                    node_version=row.get('node_version', None),
                    netsim=row.get('netsim_fqdn', None),
                    simulation=row.get('simulation', None),
                    managed_element_type=row.get('managed_element_type', None),
                    source_type=row.get('source_type', None),
                    time_zone=row.get('time_zone', None),
                    controlling_rnc=controlling_rnc,
                    apnodeAIpAddress=row.get('apnodeAIpAddress'),
                    apnodeBIpAddress=row.get('apnodeBIpAddress')
                ))
            except ValueError as e:
                log.logger.debug('Invalid value provided, ignoring node "%s". Error raised: %s' % (row['node_name'], str(e)))
            except KeyError as e:
                log.logger.debug('Missing mandatory key "%s", ignoring node "%s"' % (str(e), row['node_name']))
            except TypeError as e:
                log.logger.debug("TypeError due to base64 change: {0}".format(str(e)))
                raise RuntimeError("Failed to read csv data. Please re-parse node xml file.")
    return data


def build_nodes(data_list, range_start, range_end):
    """
    Read the node data from the csv file

    :param data_list: List of lists, each list with node data
    :type data_list: list
    :param range_start: Start position in the file (i.e. 1 takes the first node)
    :type range_start: str
    :param range_end: Finish position in the file
    :type range_end: str

    :returns: list of enm_node.Node objects
    :rtype: list
    """
    from enm_node import NODE_CLASS_MAP
    nodes = []

    # Calculate the correct range of nodes.
    if range_start is None:
        start = 0
    if range_end is None:
        end = len(data_list)
    else:
        if range_start == 0:
            if range_end == 0:
                return []
            start = 0
        else:
            start = range_start - 1

        if range_end == range_start:
            end = range_start
        else:
            end = range_end

    for node_dict in data_list[start: end]:
        if 'invalid_fields' in node_dict and ':' in node_dict['invalid_fields']:
            log.logger.debug("Not using {0} because there are invalid fields".format(node_dict['node_id']))
            continue
        if node_dict['primary_type'] in NODE_CLASS_MAP:
            if node_dict['source_type'] == 'TCU02':
                node = NODE_CLASS_MAP['TCU02'](**node_dict)
            elif node_dict['source_type'] == 'SIU':
                node = NODE_CLASS_MAP['SIU02'](**node_dict)
            else:
                node = NODE_CLASS_MAP[node_dict['primary_type']](**node_dict)
        else:
            log.logger.debug('Node type "%s" not supported. Skipping' % node_dict['primary_type'])
            continue
        nodes.append(node)
    return nodes


def check_node_range_in_result_file(identifier, range_start, range_end):
    """
    Checks that the range specified by the user is within the scope of the input file

    :param identifier: The name of the input file containing nodes data
    :type identifier: str
    :param range_start: Start node index of the input file to run command on
    :type range_start: int
    :param range_end: Last node index from the input file to run command on
    :type range_end: int
    """

    nodes_file = os.path.join(config.get_nodes_data_dir(), identifier)
    file_lines = filesystem.get_lines_from_file(nodes_file)

    if range_end > (len(file_lines) - 1) or range_start > (len(file_lines) - 1):
        exception.handle_invalid_argument("The specified range '{0}' exceeds the node range for file '{1}'".format(range_end, nodes_file))


def reparse_nodes_file(input_file, failed_nodes):
    """
    Reparses the nodes file

    :param input_file: The path to the file location
    :type input_file: str
    :param failed_nodes: List of nodes that failed to create successfully
    :type failed_nodes: list
    """

    file_lines = list(get_lines_from_file_gen(input_file))
    header = file_lines[0]
    failed_node_lines = []
    for node in failed_nodes:
        # Start reading the file from the second line because the first line will be a header
        for line in file_lines[1:]:
            if node in line:
                failed_node_lines.append(line)
                break

    # Now lets sort the file and add a header
    failed_node_lines.sort()
    failed_node_lines = [header] + failed_node_lines

    # Now we need to write information on created nodes to the original nodes file
    # And information on uncreated nodes to a new nodes file
    filesystem.write_data_to_file("\n".join(failed_node_lines), "{0}-failed".format(input_file))
    log.logger.warn("\nNodes that FAILED or ERRORED can be found at {0}\n".format('{0}-failed'.format(input_file)))


def get_lines_from_file_gen(data_file):
    """
    Generator function which returns the next line from the specified node input file when called

    :param data_file: The name of the input file containing the data attributes for the nodes
    :type data_file: str

    :return: yield
    :rtype: yield
    :raises RuntimeError: raises if file doesn't exists
    """

    if not filesystem.does_file_exist(data_file):
        raise RuntimeError("Could not find specified input file {0}".format(data_file))

    with open(data_file, "r") as file_handle:
        for line in file_handle:
            yield line.strip()


class Parser(object):
    def __init__(self, xml_file, network_elements):
        self.arne_parse_dict = self.build_arne_parse_dict()
        self.csv_headings = config.get_prop("csv_headings")
        self.network_elements = network_elements if isinstance(network_elements, list) else []
        self.xml_file = xml_file
        self.netsim = ""
        self.simulation = ""
        self.com_ecim_primary_types = config.get_prop("com_ecim_primary_types")

    def build_arne_parse_dict(self):
        """
        Gets the arne parse data from properties

        :return: Returns a dictionary of dictionaries. Each dictionary has the xpath and attribute to search for
        :rtype: dict[string, tuple[string, string]]
        """
        return {
            "node_name": ("ManagedElementId", "string"),
            "node_ip": ("Connectivity/DEFAULT/ipAddress", "[string;ip_v4]"),
            "cluster_ip": ("Connectivity/AXE/APG/IPAddressing/ioIpAddressCluster", "[string;ip_v4]"),
            "apnodeAIpAddress": ("Connectivity/AXE/APG/IPAddressing/ioIpAddressNodeA", "[string;ip_v4]"),
            "apnodeBIpAddress": ("Connectivity/AXE/APG/IPAddressing/ioIpAddressNodeB", "[string;ip_v4]"),
            "isite_node_ip": ("Connectivity/ISBlade/ISIO/ipAddress", "[string;ip_v4]"),
            "mim_version": ("neMIMVersion", "string"),
            "security_state": ("Connectivity/DEFAULT/nodeSecurityState", "state"),
            "supported_protocols": ("Connectivity/DEFAULT//protocolType", "string"),
            "netconf": ("Connectivity/DEFAULT//protocolType[@string='Netconf']/../port", "int"),
            "snmp": ("Connectivity/DEFAULT//protocolType[@string='SNMP']/../port", "int"),
            "isite_snmp": ("Connectivity/ISBlade/ISIO//protocolType[@string='SNMP']/../port", "int"),
            "snmp_versions": ("Connectivity/DEFAULT//protocolType[@string='SNMP']/../protocolVersion", "string"),
            "isite_snmp_versions": ("Connectivity/ISBlade/ISIO//protocolType[@string='SNMP']/../protocolVersion", "string"),
            "snmp_community": ("Connectivity/DEFAULT//protocolType[@string='SNMP']/../communityString", "string"),
            "isite_snmp_community": ("Connectivity/ISBlade/ISIO//protocolType[@string='SNMP']/../communityString", "string"),
            "snmp_security_name": ("Connectivity/DEFAULT//protocolType[@string='SNMP']/../securityName", "string"),
            "isite_snmp_security_name": ("Connectivity/ISBlade/ISIO//protocolType[@string='SNMP']/../securityName", "string"),
            "snmp_authentication_method": ("Connectivity/DEFAULT//protocolType[@string='SNMP']/../authenticationMethod", "string"),
            "isite_snmp_authentication_method": ("Connectivity/ISBlade/ISIO//protocolType[@string='SNMP']/../authenticationMethod", "string"),
            "snmp_encryption_method": ("Connectivity/DEFAULT//protocolType[@string='SNMP']/../encryptionMethod", "string"),
            "isite_snmp_encryption_method": ("Connectivity/ISBlade/ISIO//protocolType[@string='SNMP']/../encryptionMethod", "string"),
            "normal_user": ("Tss/Entry/Type[@string='NORMAL']/../User", "string"),
            "normal_password": ("Tss/Entry/Type[@string='NORMAL']/../Password", "string"),
            "secure_user": ("Tss/Entry/Type[@string='SECURE']/../User", "string"),
            "secure_password": ("Tss/Entry/Type[@string='SECURE']/../Password", "string"),
            "primary_type": ("primaryType", "type"),
            "node_version": ("nodeVersion", "string"),
            "em_url": ("Connectivity/DEFAULT/emUrl", "url"),
            "isite_em_url": ("Connectivity/ISBlade/emUrl", "url"),
            "managed_element_type": ("managedElementType", "types"),
            "group_data": ("Relationship/AssociableNode[@AssociationType='Group_to_MeContext' or @AssociationType='Group_to_ManagedElement']", "TO_FDN"),
            "source_type": (".", "sourceType"),
            "associated_site": ("associatedSite", "string")
        }

    def parse_data(self, verbose=False):
        """
        Parses the data from the xml file. Returns a list of OrderedDicts

        :returns: List or OrderedDicts containing node information
        :rtype: list
        """
        xml_tree = self.get_xml_tree(self.xml_file, verbose=verbose)
        element_list = self.get_element_list(xml_tree, verbose=verbose)
        sites = self.get_sites(xml_tree)
        return self.parse_elements(element_list, sites)

    def get_xml_tree(self, xml_file, verbose=False):
        """
        Gets the xml tree from the xml file

        :param xml_file: The file which node info is to be parsed from
        :type xml_file: str
        :param verbose: Flag controlling whether additional information is printed to console during execution
        :type verbose: bool

        :returns: Returns an ElementTree object
        :rtype: ElementTree
        :raises RuntimeError: if exception occurs
        """
        xml_tree = None
        try:
            xml_tree = et.parse(xml_file)

            if verbose:
                log.logger.info("Parsing XML file {0}".format(xml_file))
        except:
            raise RuntimeError("Unable to parse XML file {0}".format(xml_file))

        return xml_tree

    def get_element_list(self, xml_tree, verbose=False):
        """
        Gets a list of Element objects from the xml tree

        :param xml_tree: The ElementTree object
        :type xml_tree: ElementTree
        :param verbose: Flag controlling whether additional information is printed to console during execution
        :type verbose: bool
        :returns: List of lists containing a string for the SubNetwork and an Element object
        :rtype: list
        :raises RuntimeError: if exception occurs
        """
        elements = []
        total_nodes = 0
        subnetwork_xpath = config.get_prop("subnetwork_xpath")
        netsim_xpath = config.get_prop("netsim_xpath")
        simulation_xpath = config.get_prop("simulation_xpath")

        # Set the netsim and simulation for each file if its in the xml file
        if xml_tree.find(simulation_xpath) is not None:
            self.simulation = xml_tree.find(simulation_xpath).get("string")
        if xml_tree.find(netsim_xpath) is not None:
            self.netsim = xml_tree.find(netsim_xpath).get("string")

        # Get all ManagedElements recursively in all nested SubNetworks.
        if xml_tree.find(subnetwork_xpath) is not None:
            list_returned_tuples = self.find_subnetwork(xml_tree, subnetwork_xpath, "")

            for subnetwork, mecontext in list_returned_tuples:
                total_nodes = total_nodes + 1
                elements.append([subnetwork, mecontext])

        # In case some export xml has ManagedElements in the root tag, get them as well. However, this should never be done in a normal OSS ARNE export
        mecontext_without_subnetwork_xpath = subnetwork_xpath.replace("SubNetwork", "ManagedElement")
        if xml_tree.find(mecontext_without_subnetwork_xpath) is not None:
            try:
                matching_mecontexts = xml_tree.findall(mecontext_without_subnetwork_xpath).__iter__()
            except:
                raise RuntimeError("Could not find all MeContext elements in XML tree with xpath %s" % mecontext_without_subnetwork_xpath)

            for mecontexts in matching_mecontexts:
                elements.append(["None", mecontexts])
                total_nodes = total_nodes + 1

        if verbose:
            log.logger.info(log.green_text("Found {0} nodes(s) in {1}").format(str(total_nodes), str(self.xml_file)))

        return elements

    def find_subnetwork(self, xml_tree, subnetwork_xpath, subnetwork_path_value):
        """
        Generator function which finds all SubNetworks and gets all ManagedElements. It then returns a generator of tuples with the subnetwork path for a ManagedElement and ManagedElement object itself.

        :param xml_tree: It contains a tree of SubNetworks and ManagedElements objects
        :type xml_tree: ElementTree object
        :param subnetwork_xpath: Contains the SubNetwork xpath that is going to be used to find SubNetworks objects in the xml_tree
        :type subnetwork_xpath: str
        :param subnetwork_path_value: Contains the values of the subnetworks that lead to a specific ManagedElement. It's the SubNetwork path for a ManagedElement
        :type subnetwork_path_value: str

        :returns: Generator of tuples (subnetwork path that leads to the ManagedElement, ManagedElement object)
        :rtype: generator
        :raises RuntimeError: if exception occurs
        """

        elements = []
        mecontext_xpath = config.get_prop("mecontext_xpath")

        try:
            matching_elements = xml_tree.findall(subnetwork_xpath).__iter__()
        except:
            raise RuntimeError("Could not find all SubNetwork elements in XML tree with xpath " + subnetwork_xpath)

        for subnetwork_element in matching_elements:
            subnetwork_name = "%s%s" % (subnetwork_path_value, subnetwork_element.get("userLabel"))

            if subnetwork_element.find('./SubNetwork') is not None:
                subnetwork_name = "%s|" % subnetwork_name
                for x, y in self.find_subnetwork(subnetwork_element, "./SubNetwork", subnetwork_name):
                    elements.append([x, y])

            if subnetwork_element.find(mecontext_xpath) is not None:
                try:
                    matching_mecontexts = subnetwork_element.findall(mecontext_xpath).__iter__()
                except:
                    raise RuntimeError("Could not find all MeContext elements in XML tree with xpath " + mecontext_xpath)

                for mecontexts in matching_mecontexts:
                    elements.append([subnetwork_name, mecontexts])

        return elements

    def parse_elements(self, elements, sites):
        """
        Gets the data from the a list of Element objects

        :param elements: A list of lists containing a string for the SubNetwork and an Element object
        :type elements: list
        :param sites: A list of sites
        :type sites: list[site]

        :returns: List of OrderedDicts containing node information
        :rtype: list
        """
        element_data = []

        for element in elements:
            subnetwork, managed_element = element
            data = self.parse_element(managed_element)
            self.update(data, subnetwork)
            data = self.order(data)

            if len(self.network_elements) == 0:
                element_data.append(data)
            else:
                if data['node_name'] in self.network_elements:
                    element_data.append(data)
        for element in element_data:
            for site in sites:
                if element["associated_site"].split("=")[1] == site.site_name:
                    try:
                        element["time_zone"] = site.world_time_zone
                    except (RuntimeError, ValueError) as e:
                        exception.process_exception("An error occured while validating the Time Zone information of network element {ne_name}: {error}".format(ne_name=element["node_name"], error=e))

        return element_data

    def update(self, data, subnetwork):
        """
        Adds additional data to the node data dictionary

        :param data: Dict containing parsed data
        :type data: dict
        :param subnetwork: The SubNetwork
        :type subnetwork: str
        """

        additional_headings = set(self.csv_headings) - set(self.arne_parse_dict.keys())

        for heading in additional_headings:
            if heading == "subnetwork" and config.get_prop('skip_subnetwork_in_parsing') == 'false':
                if subnetwork != "None":
                    subnetwork = [x for x in (subnetwork.split("|")) if x != ""]
                    subnetwork = "|".join(["SubNetwork=" + x for x in subnetwork])
                data[heading] = subnetwork
            elif heading == "netsim_fqdn":
                data[heading] = self.netsim
            elif heading == "simulation":
                data[heading] = self.simulation
            else:
                data[heading] = ""

        if data["primary_type"] in ["CSCF", "MTAS", "HSS-FE", "CCN", "VPN"] and data["source_type"] == "TSP":
            data["primary_type"] += "-TSP"

        if data["primary_type"] == "SAPC" and data["source_type"] == "TSP":
            data["primary_type"] = "cSAPC-TSP"

        if data["primary_type"] == "STN":
            if "SIU" in data["source_type"]:
                data["primary_type"] = "SIU02"
            elif "TCU02" in data["source_type"]:
                data["primary_type"] = "TCU02"

        if data['primary_type'] == 'Isite':
            data = performIsiteParamParse(data)

    def order(self, data):
        """
        Orders the dictionary according to our csv_headings in properties

        :param data: Dict containing parsed data
        :type data: dict
        :return: ordered data
        :rtype: OrderedDict
        """

        ordered_data = collections.OrderedDict()

        for heading in self.csv_headings:
            ordered_data[heading] = data[heading]

        return ordered_data

    def parse_element(self, managed_element):
        """
        The method that parses the data

        :param managed_element: An Element object
        :type managed_element: Element

        :returns: Dictionary of parsed data
        :rtype: dict
        """
        # Add element values to this list you want exempt from replacing , with |
        do_not_substitute_element = ["Password", "User"]
        row_data = {}

        for heading, value_location in self.arne_parse_dict.iteritems():
            xpath, attribute = value_location
            value = None
            value_list = []

            try:
                matching_elements = managed_element.xpath(xpath)
            except:
                log.logger.debug("Could not find any elements in ManagedElement sub-tree with xpath {0}".format(xpath))
                row_data[heading] = ""
                continue

            # If we have a list of different attribute types in our configuration property then put them in a list and search for each one until we get a match
            attributes_to_check = attribute.strip("[").strip("]").split(";")
            for element in matching_elements:
                for attribute in attributes_to_check:
                    value = element.get(attribute)
                    if value is not None:
                        if element.tag not in do_not_substitute_element:
                            value = value.replace(",", "|")
                        else:
                            value = base64.b64encode(value)
                        value_list.append(value)
                        break

            if value_list > 1:
                delimiter = config.get_prop("multi_value_delimiter")
                value = delimiter.join(value_list)

            row_data[heading] = value if value else ""

        # Needed for making node names unique
        self._add_netsim_host_to_node_name(row_data)

        self._remove_lowercase_from_mim_versions(row_data)

        return row_data

    @staticmethod
    def _remove_lowercase_from_mim_versions(row_data):
        if row_data.has_key('mim_version') and len(row_data.get('mim_version')) > 2:
            value = re.sub(r"^v", "", row_data['mim_version'])
            row_data['mim_version'] = value

    def _add_netsim_host_to_node_name(self, row_data):
        if row_data.has_key('primary_type') and row_data['primary_type'].strip() in config.get_prop("cpp_primary_types") and self.netsim != "":
            if config.get_prop('add_netsim_host_to_node_name') == 'true':
                netsim = re.sub(r"\..*", "", self.netsim)
                if row_data.has_key('node_name'):
                    value = "{0}_{1}".format(netsim, row_data['node_name'])
                    row_data['node_name'] = value

    def get_sites(self, xml_tree):
        """
        Creates site objects

        :param xml_tree: The ElementTree object
        :type xml_tree: ElementTree

        :returns: list of Site objects
        :rtype: list[site]
        """
        site_elements = []
        for site_tree in xml_tree.iterfind("./Create/Site"):
            site_elements.append(Site(site_tree.get("userLabel"), site_tree.find("altitude").get("string"),
                                      site_tree.find("location").get("string"),
                                      site_tree.find("longitude").get("string"), site_tree.find("latitude").get("string"),
                                      site_tree.find("worldTimeZoneId").get("string")))

        return site_elements


def _skip_validation():
    return True if config.has_prop('skip_validation') and config.get_prop('skip_validation') is True else False
