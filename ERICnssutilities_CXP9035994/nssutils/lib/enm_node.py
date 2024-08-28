import re
from enum import Enum
from nssutils.lib import log, config, python_utils, security
from nssutils.lib.enm_node_management import (FmManagement, CmManagement, ShmManagement, PmManagement)
from nssutils.lib.enm_user_2 import get_admin_user, is_session_available
from nssutils.lib.exceptions import ScriptEngineResponseValidationError
from requests.exceptions import HTTPError

ONE_INSTANCE_UPDATED_VERIFICATION = "1 instance(s) updated"
DELETED_INSTANCE_VERIFICATION = 'instance(s) deleted'
ZERO_INSTANCE_VERIFICATION = r"(?<=\D)(0 instance\(s\))"
ONE_INSTANCE_VERIFICATION = "1 instance(s)"
MULTIPLE_INSTANCES_DELETE_VERIFICATION = r"[1-9][0-9]* instance\(s\) deleted"
MULTIPLE_INSTANCES_VERIFICATION = r"[1-9][0-9]* instance\(s\)"

NETEX_ENDPOINT = '/managedObjects/query?searchQuery=select%20NetworkElement'
SSH = "SSH"
TLS = "TLS"


class Subnetwork(object):
    CHECK_CMD = "cmedit get {subnetwork}"
    CREATE_CMD = "cmedit create {subnetwork} SubNetworkId={subnetwork_id} -ns={namespace} -version={version}"
    CHECK_CHILD_CMD = "cmedit get * SubNetwork.SubNetworkId=={subnetwork},*"

    DELETE_CMD = "cmedit delete {subnetwork}"
    NAMESPACE = "OSS_TOP"
    VERSION = "3.0.0"

    def __init__(self, id, user=None):  # pylint: disable=redefined-builtin
        self.id = id if id != 'None' else ''
        self.user = user

    @property
    def name(self):
        return self.id.split(",")[-1].split("=")[-1]

    def exists(self):
        """
        Checks if the subnetwork exists on the ENM already.

        :return: True if there is instance verification in response output else False
        :rtype: bool
        """

        exists = False
        user = self.user or get_admin_user()

        response = user.enm_execute(
            command=self.CHECK_CMD.format(subnetwork=self.id))
        if any(ONE_INSTANCE_VERIFICATION in line for line in response.get_output()):
            exists = True
        else:
            log.logger.debug(str('Subnetwork "%s" does not exist in ENM' % self.name))
        return exists

    def has_no_child_mos(self):
        """
        Checks if the subnetwork has child MOs on the ENM already

        :return: True if there is zero instance verification else False
        :rtype: bool
        """

        user = self.user or get_admin_user()
        response = user.enm_execute(
            command=self.CHECK_CHILD_CMD.format(subnetwork=self.name))

        match = re.search(ZERO_INSTANCE_VERIFICATION, ",".join(response.get_output()))

        return True if match else False

    def create(self, print_summary=False):
        """
        Creates the subnetwork on ENM

        :param print_summary: check if it has to print summary of subnetwork
        :type print_summary: bool
        :raises ScriptEngineResponseValidationError: if there is no instance verification
        """

        user = self.user or get_admin_user()

        log.logger.debug(str('Subnetwork "%s" does not exist on ENM. Creating one.' % self.name))
        response = user.enm_execute(
            command=self.CREATE_CMD.format(
                namespace=self.NAMESPACE, version=self.VERSION,
                subnetwork=self.id, subnetwork_id=self.name))
        if not any(ONE_INSTANCE_VERIFICATION in line for line in response.get_output()):
            raise ScriptEngineResponseValidationError(
                'Cannot create subnetwork "%s". Response was "%s"' % (
                    self.id, ', '.join(response.get_output())), response=response)
        elif print_summary:
            log.logger.info(log.purple_text("Subnetwork Name {0}".format(self.name)))
            for line in response.get_output():
                log.logger.info(line)
        log.logger.debug(str('Successfully created subnetwork "%s"' % self.name))

    def delete(self):
        """
        Deletes the subnetwork from ENM

        :raises ScriptEngineResponseValidationError: if there is no instance verification
        """

        user = self.user or get_admin_user()

        log.logger.debug(str('Subnetwork "%s" does not have any children MOs. Trying to delete it.' % self.id))
        response = user.enm_execute(
            command=self.DELETE_CMD.format(subnetwork=self.id))
        if not any(ONE_INSTANCE_VERIFICATION in line for line in response.get_output()):
            raise ScriptEngineResponseValidationError(
                'Cannot delete subnetwork "%s". Response was "%s"' % (
                    self.name, ', '.join(response.get_output())), response=response)
        log.logger.debug(str('Successfully deleted subnetwork "%s"' % self.name))


class Site(object):

    _valid_time_zones = None

    def __init__(self, site_name, altitude, location, longitude, latitude, world_time_zone):
        """
        Site Constructor

        :type site_name: string
        :param site_name: site name
        :type altitude: string
        :param altitude: site altitude
        :type location: string
        :param location: site location
        :type longitude: string
        :param longitude: site longitude
        :type latitude: string
        :param latitude: site latitude
        :type world_time_zone: string
        :param world_time_zone: site time zone
        """

        self.site_name = site_name
        self.altitude = altitude
        self.location = location
        self.longitude = longitude
        self.latitude = latitude
        self.world_time_zone = world_time_zone

    def __str__(self):
        return "Site: {site_name}, TimeZone: {timeZone}".format(site_name=self.site_name, timeZone=self.world_time_zone)

    @classmethod
    def _get_valid_time_zones(cls):
        """
        Deprecated 18.02 To be deleted 18.14 Torf-240292
        """

        pass


class BaseNode(object):

    _ignore_attrs = []
    _new_attrs = {'mos': {},
                  'managed_element_type': ''}

    def __init__(self, node_id='', node_ip='', mim_version='', model_identity='',
                 security_state='', normal_user='', normal_password='', secure_user='',
                 secure_password='', subnetwork='', netsim=None,
                 simulation=None, revision=None, identity=None, primary_type=None,
                 node_version=None, user=None, invalid_fields='', netconf_port='', snmp_port='', snmp_version=None,
                 snmp_community='', snmp_security_name='', snmp_authentication_method=None,
                 snmp_encryption_method=None, snmp_auth_password=None, snmp_priv_password=None, time_zone='',
                 controlling_rnc=None, transport_protocol=None, oss_prefix='', apnodeAIpAddress="", apnodeBIpAddress="",
                 **kwargs):
        """
        Node Constructor

        :param node_id: Node ID (unique across all nodes)
        :type node_id: str
        :param node_ip: IP address of the node (unique across all nodes)
        :type node_ip: str
        :param mim_version: The node MIM version (in the format x.y.zzz)
        :type mim_version: str
        :param model_identity: The node model identity (in the format xxxx-yyy-zzz)
        :type model_identity: str
        :param security_state: The security state of the node
        :type security_state: str
        :param normal_user: The non secure username
        :type normal_user: str
        :param normal_password: The non secure username password
        :type normal_password: str
        :param secure_user: The secure username
        :type secure_user: str
        :param secure_password: The secure username password
        :type secure_password: str
        :param subnetwork: The node subnetwork
        :type subnetwork: str
        :param netsim: Netsim host
        :type netsim: str
        :param simulation: Netsim simulation
        :type simulation: str
        :param revision: Node revision
        :type revision: str
        :param identity: Node identity
        :type identity: str
        :param primary_type: The node's primary type
        :type primary_type: str
        :param node_version: Version of Node
        :type node_version: int
        :param user: User object
        :type user: enm_user_2.User
        :param invalid_fields:
        :type invalid_fields:
        :param netconf_port: Netconf Port to access on
        :type netconf_port: int
        :param snmp_port: Snmp Port to access on
        :type snmp_port: int
        :param snmp_version: Version of the SNMP protocol used
        :type snmp_version: SnmpVersion
        :param snmp_community: Community name
        :type snmp_community: str
        :param snmp_security_name: Security name
        :type snmp_security_name: str
        :param snmp_authentication_method: Algorithm used for authentication
        :type snmp_authentication_method: SnmpAuthenticationMethod
        :param snmp_encryption_method: Algorithm used for encryption
        :type snmp_encryption_method: SnmpEncryptionMethod
        :param snmp_auth_password: Authorization password for snmp V3
        :type snmp_auth_password: str
        :param snmp_priv_password: privacy password for snmp V3
        :type snmp_priv_password: str
        :param time_zone: node time zone
        :type time_zone: str
        :param controlling_rnc: The controlling RNC
        :type controlling_rnc: str
        :param transport_protocol: Transport Protocol used by the Node
        :type transport_protocol: str
        :param oss_prefix: Oss Prefix of the node
        :type oss_prefix: str
        :param apnodeAIpAddress: IP address for apnodeA
        :type apnodeAIpAddress: str
        :param apnodeBIpAddress: IP address for apnodeB
        :type apnodeBIpAddress: str
        :param kwargs: A dictionary of optional keyword arguments
        :type kwargs: dict
        """

        self.node_id = node_id
        self.node_ip = node_ip
        self.mim_version = mim_version
        self.model_identity = model_identity
        self.security_state = security_state
        self.normal_user = normal_user
        self.normal_password = normal_password
        self.secure_user = secure_user
        self.secure_password = secure_password
        self.subnetwork = subnetwork if subnetwork != 'None' else ''
        self.netsim = netsim
        self.simulation = simulation
        self.time_zone = time_zone
        self.controlling_rnc = controlling_rnc
        self.oss_prefix = oss_prefix or self.subnetwork_str
        if config.has_prop("create_mecontext") and "MeContext" not in self.oss_prefix:
            self.oss_prefix = "{},MeContext={}".format(self.oss_prefix, self.node_id).lstrip(',')

        # Required to differentiate node types
        self.revision = revision
        self.identity = identity
        self.primary_type = primary_type
        self.node_version = node_version
        self.netconf_port = netconf_port
        self.transport_protocol = transport_protocol
        self.tls_mode = "LDAPS" if self.transport_protocol == TLS else ""
        self.snmp_port = snmp_port
        self.snmp_version = self._get_snmp_version() or snmp_version
        self.snmp_community = snmp_community
        self.snmp_security_name = snmp_security_name
        self.snmp_authentication_method = snmp_authentication_method
        self.snmp_encryption_method = snmp_encryption_method
        self.snmp_auth_password = snmp_auth_password
        self.snmp_priv_password = snmp_priv_password
        self.managed_element_type = kwargs.pop('managed_element_type', '')

        self.invalid_fields = invalid_fields
        self.user = user or get_admin_user() if is_session_available() else None
        self.fdn = kwargs.pop('fdn', '')
        self.poid = kwargs.pop('poid', '')
        self.mos = kwargs.pop('mos', {})
        self.apnodeAIpAddress = apnodeAIpAddress
        self.apnodeBIpAddress = apnodeBIpAddress

    def _get_snmp_version(self):
        """
        Temporary method to get the snmp version if it exists
        To be removed when we are sure all node objects in persistence have this attribute 29-11-2016
        Original code in __init__: self.snmp_version = SnmpVersion.SNMP_V3 if config.has_prop("use_snmp_v3") else snmp_version

        :return: Snmp Version
        :rtype: str or None
        """

        version = None
        snmp_instance = None

        try:
            snmp_instance = SnmpVersion
        except (NameError, AttributeError) as e:
            log.logger.debug(str("Exception trying to load SnmpVersion: {0}".format(str(e))))

        if config.has_prop("use_snmp_v3") and hasattr(snmp_instance, "SNMP_V3"):
            version = getattr(snmp_instance, "SNMP_V3")

        return version

    def __str__(self):
        return "\nNode ID {0} ({1}) [Model Identity {2}; MIM version {3}; security state {4}]".format(
            self.node_id, self.node_ip, self.model_identity, self.mim_version, self.security_state)

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.node_name)

    def __cmp__(self, other):
        return cmp(self.node_id, other.node_id)

    def compare_with(self, other_node, ignore_attributes=("user")):
        if not isinstance(other_node, type(self)):
            return ValueError(
                "Argument should be of type {}, but got {}".format(self.__class__.__name__, other_node.__class__.__name__))
        return set(attr for attr in vars(self) if attr not in ignore_attributes and getattr(self, attr) != getattr(other_node, attr))

    @property
    def node_name(self):
        """
        Returns the node name removing .*_ from id

        :return: node name
        :rtype: str
        """

        return re.sub(r".*_", "", self.node_id)

    @property
    def subnetwork_str(self):
        """
        Name of the subnetwork

        :return: subnetwork name
        :rtype: str
        """

        return "%s" % self.subnetwork.replace("|", ",") if self.subnetwork else ''

    @property
    def subnetwork_id(self):
        return self.subnetwork.split(",")[-1].split("=")[-1] if self.subnetwork else ''

    @property
    def mim(self):
        if not self.model_identity:
            return ''
        return "%s:%s" % (self.NE_TYPE, self.model_identity)

    @property
    def snmp_security_level(self):
        """

        :return: snmp security level
        :rtype: str
        """

        if self.snmp_authentication_method and self.snmp_encryption_method:
            return SnmpSecurityLevel.AUTH_PRIV
        elif self.snmp_authentication_method:
            return SnmpSecurityLevel.AUTH_NO_PRIV
        else:
            return SnmpSecurityLevel.NO_AUTH_NO_PRIV

    def to_dict(self, encryption_password=None):
        """

        :type encryption_password: string
        :param encryption_password: If provided, passwords are encrypted
        :return: node in dictionary
        :rtype: dict[string]
        """

        normal_password = self.normal_password
        secure_password = self.secure_password
        if encryption_password:
            if normal_password:
                normal_password = "".join(security.encrypt(normal_password, encryption_password))
            if secure_password:
                secure_password = "".join(security.encrypt(secure_password, encryption_password))

        return {
            "node_id": self.node_id,
            "primary_type": self.primary_type,
            "node_ip": self.node_ip,
            "mim_version": self.mim_version,
            "model_identity": self.model_identity,
            "revision": self.revision,
            "identity": self.identity,
            "security_state": self.security_state,
            "normal_user": self.normal_user,
            "normal_password": normal_password,
            "secure_user": self.secure_user,
            "secure_password": secure_password,
            "node_version": self.node_version,
            "subnetwork": self.subnetwork,
            "snmp_port": self.snmp_port,
            "snmp_version": self.snmp_version.enm_representation if self.snmp_version else None,
            "snmp_community": self.snmp_community,
            "snmp_security_name": self.snmp_security_name,
            "snmp_authentication_method": self.snmp_authentication_method.enm_representation if self.snmp_authentication_method else None,
            "snmp_encryption_method": self.snmp_encryption_method.enm_representation if self.snmp_encryption_method else None,
            "snmp_auth_password": self.snmp_auth_password,
            "snmp_priv_password": self.snmp_priv_password,
            "time_zone": self.time_zone,
            "tls_mode": self.tls_mode,
            "netconf_port": self.netconf_port,
            "controlling_rnc": self.controlling_rnc,
            "transport_protocol": self.transport_protocol,
            "oss_prefix": self.oss_prefix
        }

    @classmethod
    def from_dict(cls, node_attributes, decryption_password=None):
        """

        :param node_attributes: takes node attributes
        :type node_attributes: dict[string]
        :param decryption_password: If provided, passwords are decrypted
        :type decryption_password: str
        :return: Node from dictionary
        :rtype: BaseNode
        """

        normal_password = node_attributes["normal_password"]
        secure_password = node_attributes["secure_password"]
        if decryption_password:
            if normal_password:
                normal_password = security.decrypt(node_attributes["normal_password"][:-8], decryption_password, node_attributes["normal_password"][-8:])
            if secure_password:
                secure_password = security.decrypt(node_attributes["secure_password"][:-8], decryption_password, node_attributes["secure_password"][-8:])

        node_class = cls.get_class_for_node_type(node_attributes["primary_type"])
        return node_class(
            node_id=node_attributes["node_id"],
            primary_type=node_attributes["primary_type"],
            node_ip=node_attributes["node_ip"],
            mim_version=node_attributes["mim_version"],
            model_identity=node_attributes["model_identity"],
            revision=node_attributes.get("revision", ""),
            identity=node_attributes.get("identity", ""),
            security_state="ON",
            normal_user=node_attributes["normal_user"],
            normal_password=normal_password,
            secure_user=node_attributes["secure_user"],
            secure_password=secure_password,
            node_version=node_attributes["node_version"],
            subnetwork=node_attributes["subnetwork"],
            snmp_port=node_attributes["snmp_port"],
            snmp_version=SnmpVersion.from_enm_value(node_attributes["snmp_version"]) if node_attributes["snmp_version"] else None,
            snmp_community=node_attributes["snmp_community"],
            snmp_security_name=node_attributes["snmp_security_name"],
            snmp_authentication_method=SnmpAuthenticationMethod.from_enm_value(node_attributes["snmp_authentication_method"]) if node_attributes["snmp_authentication_method"] else None,
            snmp_encryption_method=SnmpEncryptionMethod.from_enm_value(node_attributes["snmp_encryption_method"]) if node_attributes["snmp_encryption_method"] else None,
            snmp_auth_password=node_attributes["snmp_auth_password"],
            snmp_priv_password=node_attributes["snmp_priv_password"],
            time_zone=node_attributes["time_zone"],
            netconf_port=node_attributes["netconf_port"],
            controlling_rnc=node_attributes["controlling_rnc"],
            transport_protocol=node_attributes["transport_protocol"],
            oss_prefix=node_attributes["oss_prefix"]
        )

    @classmethod
    def get_class_for_node_type(cls, node_type):
        """

        :param node_type: type of the node to be used
        :type node_type: str
        :return: subclass if it has attribute of NE_TYPE
        :rtype: BaseNode
        :raises Exception: if not a subclass
        """

        subclass = next((node_class for node_class in python_utils.get_all_subclasses(BaseNode) if hasattr(node_class, "NE_TYPE") and node_class.NE_TYPE == node_type), None)
        if not subclass:
            raise Exception("Unable to find class {subclass}".format(subclass=subclass))

        return subclass

    @classmethod
    def nodes_to_dict(cls, nodes, encryption_password=None):
        """

        :param nodes: list of nodes
        :type nodes: set[BaseNode]
        :param encryption_password: If provided, passwords are encrypted
        :type encryption_password: str
        :return: dictionary of nodes, version and password validation
        :rtype: Dict[string, Dict[string]]
        """

        return {
            "version": 1.2,
            "nodes": {node.node_id: node.to_dict(encryption_password) for node in nodes},
            "password_validation": "".join(security.encrypt("password validation string", encryption_password))
        }

    @classmethod
    def nodes_from_dict(cls, nodes_data, decryption_password=None):
        """

        :param nodes_data: node data for password validation
        :type nodes_data: Dict[string, Dict[string]]
        :param decryption_password: If provided, passwords are decrypted
        :type decryption_password: str
        :return: Node from dictionary from node_data
        :rtype: set[BaseNode]
        :raises ValueError: if the decryption password in not None and decryption is not equal password validation string
        """

        encrypted_text, salt = nodes_data["password_validation"][:-8], nodes_data["password_validation"][-8:],
        if decryption_password is not None and security.decrypt(encrypted_text, decryption_password, salt) != "password validation string":
            raise ValueError("The provided password is invalid")
        return {cls.from_dict(node_attributes, decryption_password) for node_name, node_attributes in nodes_data["nodes"].iteritems()}


class Node(BaseNode):

    MECONTEXT_NAMESPACE = "OSS_TOP"
    MECONTEXT_VERSION = "3.0.0"
    NETWORK_ELEMENT_NAMESPACE = "OSS_NE_DEF"
    NETWORK_ELEMENT_VERSION = "2.0.0"

    # Delete commands
    DELETE_NETWORKELEMENT_VERIFY_SUPERVISION_DISABLED_CMD = "cmedit action NetworkElement={node_id},CmFunction=1 deleteNrmDataFromEnm"
    DELETE_NETWORKELEMENT_TREE_CMD = "cmedit delete NetworkElement={node_id} -ALL"

    # Delete MeContext commands
    DELETE_MECONTEXT_CMD = 'cmedit delete {subnetwork}MeContext={node_id}'

    def create_mecontext(self):
        """
        Creates the mecontext on ENM

        :raises ScriptEngineResponseValidationError: if there is no instance verification
        """

        response = self.user.enm_execute(
            self.CREATE_MECONTEXT_CMD.format(**self.create_mecontext_kwargs))
        if not any(ONE_INSTANCE_VERIFICATION in line for line in response.get_output()):
            raise ScriptEngineResponseValidationError(
                'Cannot create mecontext for node "%s". Response was "%s"' % (
                    self.node_id, ', '.join(response.get_output())), response=response)
        log.logger.debug(str('Successfully created mecontext for node "%s"' % self.node_id))

    def create_networkelement(self):
        """
        Creates the networkelement on ENM

        :raises ScriptEngineResponseValidationError: if there is no instance verification
        """

        self.create_networkelement_cmd()
        response = self.user.enm_execute(
            self.CREATE_NETWORK_ELEMENT_CMD.format(**self.create_networkelement_kwargs))
        if not any(ONE_INSTANCE_VERIFICATION in line for line in response.get_output()):
            raise ScriptEngineResponseValidationError(
                'Cannot create network element for node "%s". Response was "%s"' % (
                    self.node_id, ', '.join(response.get_output())), response=response)
        log.logger.debug(str('Successfully created network element for node "%s"' % self.node_id))
        # Update or restore once issue with node names is resolved
        # if self.controlling_rnc:
        #     self.set_controlling_rnc()

    def _disable_supervision_delete_network_element(self):
        """
        Deletes network element and disables supervision

        :raises ScriptEngineResponseValidationError: if there is no instance verification
        """

        response = self.user.enm_execute(
            self.DELETE_NETWORKELEMENT_VERIFY_SUPERVISION_DISABLED_CMD.format(node_id=self.node_id))
        if not any(ONE_INSTANCE_VERIFICATION in line for line in response.get_output()):
            raise ScriptEngineResponseValidationError(
                'Cannot disable supervision for node "%s". Response was "%s"' % (
                    self.node_id, ', '.join(response.get_output())), response=response)
        log.logger.debug(str('Successfully disabled supervision on node "%s"' % self.node_id))

    def _delete_network_element_tree(self):
        """
        Creates the network element tree from ENM

        :raises ScriptEngineResponseValidationError: if there is no multiple instances delete verifications
        """

        response = self.user.enm_execute(
            self.DELETE_NETWORKELEMENT_TREE_CMD.format(node_id=self.node_id))
        if not any(re.search(MULTIPLE_INSTANCES_DELETE_VERIFICATION, line) for line in response.get_output()):
            raise ScriptEngineResponseValidationError(
                'Cannot delete network element tree for node "%s". Response was "%s"' % (
                    self.node_id, ', '.join(response.get_output())), response=response)
        log.logger.debug(str('Successfully deleted network element tree for node "%s"' % self.node_id))

    def delete_mecontext(self):
        """
        Deletes the mecontext MO from ENM

        :raises ScriptEngineResponseValidationError: if there is no multiple instances delete verifications
        """

        response = self.user.enm_execute(
            self.DELETE_MECONTEXT_CMD.format(node_id=self.node_id, subnetwork=self.subnetwork_str))
        if not any(re.search(MULTIPLE_INSTANCES_DELETE_VERIFICATION, line) for line in response.get_output()):
            raise ScriptEngineResponseValidationError(
                'Cannot delete MeContext for node "%s". Response was "%s"' % (
                    self.node_id, ', '.join(response.get_output())), response=response)
        log.logger.debug(str('Successfully deleted MeContext for node "%s"' % self.node_id))

    def delete_network_element(self, verify_supervision_disabled=True):
        """
        Deletes the network element with mecontext as well
        """

        if verify_supervision_disabled:
            self._disable_supervision_delete_network_element()
        self._delete_network_element_tree()

    def create_connectivity(self):
        """
        Creates the node connectivity on ENM

        :raises ScriptEngineResponseValidationError: if there is no instance verification
        """

        self.create_connectivity_cmd()
        response = self.user.enm_execute(
            self.CREATE_CONNECTIVITY_INFO_CMD.format(**self.create_connectivity_info_kwargs))
        if not any(ONE_INSTANCE_VERIFICATION in line for line in response.get_output()):
            raise ScriptEngineResponseValidationError(
                'Cannot create cpp connectivity for node "%s". Response was "%s"' % (
                    self.node_id, ', '.join(response.get_output())), response=response)
        log.logger.debug(str('Successfully created cpp connectivity for node "%s"' % self.node_id))

    def set_node_security(self):
        """
        Sets the node security in ENM

        :raises: ScriptEngineResponseValidationError
        """

        self._set_node_security_cmd()
        response = self.user.enm_execute(
            self.SET_NODE_SECURITY_CMD.format(**self.set_node_security_cmd_kwargs))
        success_response_token = "All credentials were created successfully"
        if not any(success_response_token in line for line in response.get_output()):
            raise ScriptEngineResponseValidationError(
                'Cannot set node security for node "%s". Response was "%s"' % (
                    self.node_id, ', '.join(response.get_output())), response=response)
        log.logger.debug(str('Node security set on node "%s" successful' % self.node_id))

    def set_snmp_version(self):
        """
        Secures snmp version 3 in ENM

        :raises ScriptEngineResponseValidationError: if there is no success response ticket
        """

        if self.snmp_version == SnmpVersion.SNMP_V3 or config.has_prop("use_snmp_v3") or \
                self.snmp_security_level in [SnmpSecurityLevel.AUTH_NO_PRIV or SnmpSecurityLevel.AUTH_PRIV]:
            response = self.user.enm_execute(
                self.SET_SNMP_CMD.format(**self.set_snmp_cmd_kwargs))
            success_response_token = "Snmp Authpriv Command OK"
            if not any(success_response_token in line for line in response.get_output()):
                raise ScriptEngineResponseValidationError(
                    'Cannot set snmp version for node "%s". Response was "%s"' % (
                        self.node_id, ', '.join(response.get_output())), response=response)
            log.logger.debug(str('snmp version set on node "%s" successful' % self.node_id))

    def set_controlling_rnc(self):
        """

        :raises ScriptEngineResponseValidationError: if there is no instance update verification
        """

        response = self.user.enm_execute('cmedit set NetworkElement={} controllingRnc="NetworkElement={}"'
                                         .format(self.node_id, self.controlling_rnc))
        if not any(ONE_INSTANCE_UPDATED_VERIFICATION in line for line in response.get_output()):
            raise ScriptEngineResponseValidationError('Cannot set controlling RNC (%s) for node "%s". Response was "%s"' % (
                self.controlling_rnc, self.node_id, ', '.join(response.get_output())), response=response)
        log.logger.debug(str('Controlling RNC set on node "%s" successful' % self.node_id))

    def enable_cm_management(self):
        """
        Enables CM management in ENM
        """

        CmManagement.get_management_obj(nodes=[self], user=self.user).supervise()

    def enable_fm_management(self):
        """
        Enables FM Management in ENM
        """

        FmManagement.get_management_obj(nodes=[self], user=self.user).supervise()

    def enable_pm_management(self):
        """
        Enabled PM Management in ENM
        """

        PmManagement.get_management_obj(nodes=[self], user=self.user).supervise()

    def enable_shm_management(self):
        """
        Enables Shm Management in ENM
        """

        ShmManagement.get_management_obj(nodes=[self], user=self.user).supervise()

    def check_cm_management(self, status="SYNCHRONIZED"):
        """
        Checks if cm management status matches with given one
        """

        status_dict = CmManagement.get_status(self.user, node_ids=[self.node_id])
        self._verify_status(status_dict, self.node_id, status, "Cm")

    def check_fm_management(self, status="IN_SERVICE"):
        """
        Checks if fm management status matches with given one
        """

        status_dict = FmManagement.get_status(self.user, node_ids=[self.node_id])
        self._verify_status(status_dict, self.node_id, status, "Fm")

    def check_pm_management(self, status="true"):
        """
        Checks if Pm management status matches with given one
        """

        status_dict = PmManagement.get_status(self.user, node_ids=[self.node_id])
        self._verify_status(status_dict, self.node_id, status, "Pm")

    def check_shm_management(self, status="true"):
        """
        Checks if Shm management status matches with given one
        """

        status_dict = ShmManagement.get_status(self.user, node_ids=[self.node_id])
        self._verify_status(status_dict, self.node_id, status, "Shm")

    def _verify_status(self, status_dict, node_id, status, app):
        if not status_dict.get(node_id, 'No available data') == status:
            raise ScriptEngineResponseValidationError('{0} management "{1}" not found on the node {2}. '
                                                      'Current status: {3}.'.
                                                      format(app, status, node_id, status_dict.get(node_id, "Unknown")),
                                                      response=status_dict)
        else:
            log.logger.debug(str('{0} management "{1}" found on the node {2}'.format(app, status, node_id)))

    def disable_cm_management(self):
        """
        Disables CM management in ENM
        """

        CmManagement.get_management_obj(nodes=[self], user=self.user).unsupervise()

    def disable_fm_management(self):
        """
        Disables FM management in ENM
        """

        FmManagement.get_management_obj(nodes=[self], user=self.user).unsupervise()

    def disable_pm_management(self):
        """
        Disables the PM management function
        """

        PmManagement.get_management_obj(nodes=[self], user=self.user).unsupervise()

    def disable_shm_management(self):
        """
        Disables Shm management in ENM
        """

        ShmManagement.get_management_obj(nodes=[self], user=self.user).unsupervise()

    def manage(self):
        """
        Manages the ERBS node, Enables CM, FM  and PM Management and checks CM, FM and PM management
        """

        self.enable_cm_management()
        self.enable_fm_management()
        self.enable_pm_management()
        self.check_cm_management()
        self.check_fm_management()
        self.check_pm_management()

    def unmanage(self):
        """
        Unmanages the node (disabled cm, fm and pm management)
        """

        self.disable_cm_management()
        self.disable_fm_management()
        self.disable_pm_management()
        self.disable_shm_management()
        self.check_cm_management(status='UNSYNCHRONIZED')

    def sync(self):
        """
        Sync the node
        """

        CmManagement.get_management_obj(nodes=[self], user=self.user).synchronize()

    def populate(self):
        """
        Populates the node (Create and manages in ENM)
        """

        self.create()
        self.manage()

    def create(self):
        """
        Creates the Node MO (NetworkElement), Connectivity and sets node security
        """

        self.create_networkelement()
        self.create_connectivity()
        self.set_node_security()

    def delete(self):
        """
        Deltes the MeContext and NetworkElement Mos
        """

        self.delete_network_element()

    def _set_node_security_cmd(self):
        pass

    def set_heartbeat_timeout(self):
        """
        Sets the fm heartbeat timeout

        :raises ScriptEngineResponseValidationError: if there is instance verification
        """

        cmd = ('cmedit set NetworkElement={node_id}, FmAlarmSupervision=1 heartbeatinterval=120, '
               'heartbeatTimeout=360'.format(node_id=self.node_id))
        response = self.user.enm_execute(cmd)
        if not any(ONE_INSTANCE_VERIFICATION in line for line in response.get_output()):
            raise ScriptEngineResponseValidationError(
                'Failed to set FM heartbeat for node "%s". Response was "%s"' % (
                    self.node_id, ', '.join(response.get_output())), response=response)
        log.logger.debug(str('Successfully set FM heartbeat timeout for node "%s"' % self.node_id))


class NodeWithMos(Node):
    # Not being used, but deleting this fails upgrade job as of 04/07/2016
    pass


class CppNode(Node):
    PLATFORM_TYPE = 'CPP'
    CONNECTIVITY_INFO_NAMESPACE = "CPP_MED"
    CONNECTIVITY_INFO_VERSION = "1.0.0"
    CONNECTIVITY_INFO_PORT = 80

    # Create Commands
    CREATE_MECONTEXT_CMD = ("cmedit create {subnetwork}MeContext={node_id} MeContextId={node_id}, neType={netype}, "
                            "platformType={platformtype} -namespace={namespace} -version={version}")
    CREATE_NETWORK_ELEMENT_CMD = ""
    CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},CppConnectivityInformation=1 CppConnectivityInformationId=1, ipAddress="{ip_address}", port={port} -ns={namespace} -version={version}'
    SET_NODE_SECURITY_CMD = 'secadm credentials create --rootusername root --rootuserpassword dummy --secureusername "{secure_user}" --secureuserpassword "{secure_password}" --normalusername "{normal_user}" --normaluserpassword "{normal_password}" -n "{node_id}"'
    UPDATE_NODE_SECURITY_CMD = 'secadm credentials update --rootusername root --rootuserpassword dummy --secureusername "{secure_user}" --secureuserpassword "{secure_password}" --normalusername "{normal_user}" --normaluserpassword "{normal_password}" -n "{node_id}"'

    ROOT_ELEMENT = 'MeContext'

    @property
    def create_mecontext_kwargs(self):
        return {'netype': self.NE_TYPE, 'platformtype': self.PLATFORM_TYPE, 'namespace': self.MECONTEXT_NAMESPACE, 'version': self.MECONTEXT_VERSION, 'node_id': self.node_id, 'subnetwork': self.subnetwork_str + "," if self.subnetwork else ""}

    @property
    def create_networkelement_kwargs(self):
        if config.has_prop("add_model_identity"):
            return {'netype': self.NE_TYPE, 'platformtype': self.PLATFORM_TYPE, 'model_identity': self.model_identity, 'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'oss_prefix': self.oss_prefix, 'time_zone': self.time_zone}
        else:
            return {'netype': self.NE_TYPE, 'platformtype': self.PLATFORM_TYPE, 'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'oss_prefix': self.oss_prefix, 'time_zone': self.time_zone}

    @property
    def create_connectivity_info_kwargs(self):
        return {'ip_address': self.node_ip, 'port': self.CONNECTIVITY_INFO_PORT, 'namespace': self.CONNECTIVITY_INFO_NAMESPACE, 'version': self.CONNECTIVITY_INFO_VERSION, 'node_id': self.node_id}

    @property
    def set_node_security_cmd_kwargs(self):
        return {'secure_user': self.secure_user, 'secure_password': self.secure_password, 'normal_user': self.normal_user, 'normal_password': self.normal_password, 'node_id': self.node_id}

    def create_networkelement_cmd(self):
        cmd_stub = 'cmedit create NetworkElement={node_id} networkElementId={node_id}, neType={netype}, platformType={platformtype}, ossPrefix="{oss_prefix}"'
        if config.has_prop("add_model_identity") and config.get_prop("add_model_identity") and self.model_identity:
            cmd_stub += ', ossModelIdentity="{model_identity}"'

        if self.time_zone:
            cmd_stub += ", timeZone={time_zone}"
        self.CREATE_NETWORK_ELEMENT_CMD = cmd_stub + " -ns={namespace} -version={version}"

    def check_generation_counter(self):
        """
        Checks if generation counter is set in ENM
        """

        CmManagement.check_generation_counter(self.node_id, self.user)

    def manage(self):
        super(CppNode, self).manage()
        self.check_generation_counter()

    def create_connectivity_cmd(self):
        pass


class MGWNode(CppNode):
    NE_TYPE = 'MGW'
    NETWORK_TYPE = 'CORE'


class ERBSNode(CppNode):
    NE_TYPE = 'ERBS'
    NETWORK_TYPE = 'LRAN'


class RNCNode(CppNode):
    NE_TYPE = 'RNC'
    NETWORK_TYPE = 'WRAN'


class RBSNode(CppNode):
    NE_TYPE = 'RBS'
    NETWORK_TYPE = 'WRAN'


class ComEcimNode(Node):

    CONNECTIVITY_INFO_NAMESPACE = "COM_MED"
    CONNECTIVITY_INFO_VERSION = "1.1.0"
    CONNECTIVITY_INFO_PORT = 0
    SNMP_AGENT_PORT = 0

    # Create Commands
    CREATE_MECONTEXT_CMD = "cmedit create {subnetwork}MeContext={node_id} MeContextId={node_id}, neType={netype} -namespace={namespace} -version={version}"
    CREATE_NETWORK_ELEMENT_CMD = ''
    CREATE_CONNECTIVITY_INFO_CMD = ''
    SET_NODE_SECURITY_CMD = 'secadm credentials create --secureusername "{secure_user}" --secureuserpassword "{secure_password}" -n "{node_id}"'
    UPDATE_NODE_SECURITY_CMD = 'secadm credentials update --secureusername "{secure_user}" --secureuserpassword "{secure_password}" -n "{node_id}"'
    SET_SNMP_CMD = 'secadm snmp authpriv --auth_algo {auth_algo} --auth_password "{auth_password}" --priv_algo {priv_algo} --priv_password "{priv_password}" -n "{node_id}"'

    ROOT_ELEMENT = 'NetworkElement'

    def __init__(self, *args, **kwargs):
        super(ComEcimNode, self).__init__(*args, **kwargs)
        self.netconf_port = self.netconf_port or "830"
        if not self.transport_protocol:
            if self.netconf_port == "6513" and not config.has_prop("use_ssh"):
                self.transport_protocol = TLS
                self.tls_mode = "LDAPS"
            else:
                self.transport_protocol = SSH
                self.tls_mode = ""

        self.CERTM_MO = 'ManagedElement={node_id},SystemFunctions=1,SecM=1,CertM=1'.format(node_id=self.node_id)
        self.LDAP_MO = 'ManagedElement={node_id},SystemFunctions=1,SecM=1,UserManagement=1,LdapAuthenticationMethod=1,Ldap=1'.format(node_id=self.node_id)
        self.SYSM_MO = 'ManagedElement={node_id},SystemFunctions=1,SysM=1'.format(node_id=self.node_id)
        self.CLITLS_MO = self.SYSM_MO + ',CliTls=1'
        self.HTTPS_MO = self.SYSM_MO + ',HttpM=1,Https=1'
        self.NETCONFTLS_MO = self.SYSM_MO + ',NetconfTls=1'

        self.enrollment_authority_mo_name = 'EnrollmentAuthority'
        self.enrollment_server_group_mo_name = 'EnrollmentServerGroup'
        self.enrollment_server_mo_name = 'EnrollmentServer'
        self.node_credential_mo_name = 'NodeCredential'
        self.chain_certificate_mo_name = 'ChainCertificate'
        self.trust_category_mo_name = 'TrustCategory'

    @property
    def create_mecontext_kwargs(self):
        return {'netype': self.NE_TYPE, 'namespace': self.MECONTEXT_NAMESPACE, 'version': self.MECONTEXT_VERSION, 'node_id': self.node_id, 'subnetwork': self.subnetwork_str + "," if self.subnetwork else ""}

    @property
    def create_networkelement_kwargs(self):
        if config.has_prop("add_model_identity"):
            return {'netype': self.NE_TYPE, 'model_identity': self.model_identity, 'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'revision': self.revision, 'identity': self.identity, 'oss_prefix': self.oss_prefix, 'time_zone': self.time_zone}
        else:
            return {'netype': self.NE_TYPE, 'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'oss_prefix': self.oss_prefix, 'time_zone': self.time_zone}

    def create_networkelement_cmd(self):
        cmd_stub = 'cmedit create NetworkElement={node_id} networkElementId={node_id}, neType={netype}, ossPrefix="{oss_prefix}"'
        if config.has_prop("add_model_identity") and config.get_prop("add_model_identity") and self.model_identity:
            cmd_stub += ', ossModelIdentity="{model_identity}", neProductVersion=[(revision="{revision}",identity="{identity}")]'

        if self.time_zone:
            cmd_stub += ", timeZone={time_zone}"
        self.CREATE_NETWORK_ELEMENT_CMD = cmd_stub + " -ns={namespace} -version={version}"

    @property
    def set_snmp_cmd_kwargs(self):
        return {'auth_algo': self.snmp_authentication_method or "NONE", 'auth_password': self.snmp_auth_password, 'priv_algo': self.snmp_encryption_method or "NONE", 'priv_password': self.snmp_priv_password, 'node_id': self.node_id}

    @property
    def set_node_security_cmd_kwargs(self):
        return {'secure_user': self.secure_user, 'secure_password': self.secure_password, 'node_id': self.node_id}

    def create_connectivity_cmd(self):
        if self.snmp_version == SnmpVersion.SNMP_V3:
            if self.snmp_community:
                self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},ComConnectivityInformation=1 ComConnectivityInformationId=1, ipAddress="{ip_address}", port={port}, transportProtocol="{transport_protocol}", snmpAgentPort={snmp_agent_port}, snmpSecurityLevel={snmp_security_level}, snmpSecurityName={snmp_security_name}, snmpVersion={snmp_version}, snmpReadCommunity={snmp_community}, snmpWriteCommunity={snmp_community}  -ns={namespace} -version={version}'
            else:
                self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},ComConnectivityInformation=1 ComConnectivityInformationId=1, ipAddress="{ip_address}", port={port}, transportProtocol="{transport_protocol}", snmpAgentPort={snmp_agent_port}, snmpSecurityLevel={snmp_security_level}, snmpSecurityName={snmp_security_name}, snmpVersion={snmp_version} -ns={namespace} -version={version}'
        else:
            if self.snmp_community:
                self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},ComConnectivityInformation=1 ComConnectivityInformationId=1, ipAddress="{ip_address}", port={port}, transportProtocol="{transport_protocol}", snmpAgentPort={snmp_agent_port}, snmpSecurityLevel={snmp_security_level}, snmpVersion={snmp_version}, snmpReadCommunity={snmp_community}, snmpWriteCommunity={snmp_community}  -ns={namespace} -version={version}'
            else:
                self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},ComConnectivityInformation=1 ComConnectivityInformationId=1, ipAddress="{ip_address}", port={port}, transportProtocol="{transport_protocol}", snmpAgentPort={snmp_agent_port}, snmpSecurityLevel={snmp_security_level}, snmpVersion={snmp_version} -ns={namespace} -version={version}'

    @property
    def create_connectivity_info_kwargs(self):
        return {'node_id': self.node_id, 'ip_address': self.node_ip, 'port': self.netconf_port, 'snmp_agent_port': self.snmp_port, 'snmp_security_level': self.snmp_security_level, 'snmp_security_name': self.snmp_security_name or "NONE", 'snmp_version': self.snmp_version, 'namespace': self.CONNECTIVITY_INFO_NAMESPACE, 'version': self.CONNECTIVITY_INFO_VERSION, 'transport_protocol': self.transport_protocol, 'snmp_community': self.snmp_community}

    def _set_node_security_cmd(self):
        if config.has_prop('disable_ldap_user') and config.get_prop('disable_ldap_user').lower() == "true":
            self.SET_NODE_SECURITY_CMD = 'secadm credentials create --secureusername "{secure_user}" --secureuserpassword "{secure_password}" --ldapuser disable -n "{node_id}"'


class IsNode(Node):
    CONNECTIVITY_INFO_NAMESPACE = "IS_MED"
    CONNECTIVITY_INFO_VERSION = "1.0.0"

    CREATE_MECONTEXT_CMD = "cmedit create {subnetwork}MeContext={node_id} MeContextId={node_id}, neType={netype} -namespace={namespace} -version={version}"
    CREATE_NETWORK_ELEMENT_CMD = ''
    CREATE_CONNECTIVITY_INFO_CMD = ''
    SET_NODE_SECURITY_CMD = 'secadm credentials create --secureusername "{secure_user}" --secureuserpassword "{secure_password}" -n "{node_id}"'
    UPDATE_NODE_SECURITY_CMD = 'secadm credentials update --secureusername "{secure_user}" --secureuserpassword "{secure_password}" -n "{node_id}"'
    SET_SNMP_CMD = 'secadm snmp authpriv --auth_algo {auth_algo} --auth_password "{auth_password}" --priv_algo {priv_algo} --priv_password "{priv_password}" -n "{node_id}"'
    ROOT_ELEMENT = 'NetworkElement'

    @property
    def create_mecontext_kwargs(self):
        return {'netype': self.NE_TYPE, 'namespace': self.MECONTEXT_NAMESPACE, 'version': self.MECONTEXT_VERSION, 'node_id': self.node_id, 'subnetwork': self.subnetwork_str + "," if self.subnetwork else ""}

    @property
    def create_networkelement_kwargs(self):
        if config.has_prop("add_model_identity"):
            return {'netype': self.NE_TYPE, 'model_identity': self.model_identity, 'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'revision': self.revision, 'identity': self.identity, 'subnetwork': self.subnetwork_str}
        else:
            return {'netype': self.NE_TYPE, 'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'subnetwork': self.subnetwork_str}

    def create_networkelement_cmd(self):
        if config.has_prop("add_model_identity"):
            self.CREATE_NETWORK_ELEMENT_CMD = 'cmedit create NetworkElement={node_id} networkElementId={node_id}, neType={netype}, ossModelIdentity="{model_identity}", ossPrefix="{subnetwork}", neProductVersion=[(revision="{revision}",identity="{identity}")] -ns={namespace} -version={version}'
        else:
            self.CREATE_NETWORK_ELEMENT_CMD = 'cmedit create NetworkElement={node_id} networkElementId={node_id}, neType={netype}, ossPrefix="{subnetwork}" -ns={namespace} -version={version}'

    @property
    def snmp_security_level(self):
        """

        :return: Snmp Security Level
        :rtype: str
        """

        return SnmpSecurityLevel.AUTH_PRIV if self.snmp_encryption_method else SnmpSecurityLevel.AUTH_NO_PRIV

    @property
    def set_snmp_cmd_kwargs(self):
        return {'auth_algo': self.snmp_authentication_method or "NONE", 'auth_password': self.snmp_auth_password, 'priv_algo': self.snmp_encryption_method or "NONE", 'priv_password': self.snmp_priv_password, 'node_id': self.node_id}

    @property
    def set_node_security_cmd_kwargs(self):
        return {'secure_user': self.secure_user, 'secure_password': self.secure_password, 'node_id': self.node_id}

    def create_connectivity_cmd(self):
        if self.snmp_version == SnmpVersion.SNMP_V3:
            if self.snmp_community:
                self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},IsConnectivityInformation=1 IsConnectivityInformationId=1, ipAddress="{ip_address}",  snmpAgentPort={snmp_agent_port}, snmpSecurityLevel={snmp_security_level}, snmpSecurityName={snmp_security_name}, snmpVersion={snmp_version}, snmpReadCommunity={snmp_community}, snmpWriteCommunity={snmp_community}  -ns={namespace} -version={version}'
            else:
                self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},IsConnectivityInformation=1 IsConnectivityInformationId=1, ipAddress="{ip_address}", snmpAgentPort={snmp_agent_port}, snmpSecurityLevel={snmp_security_level}, snmpSecurityName={snmp_security_name}, snmpVersion={snmp_version} -ns={namespace} -version={version}'
        else:
            if self.snmp_community:
                self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},IsConnectivityInformation=1 IsConnectivityInformationId=1, ipAddress="{ip_address}", snmpAgentPort={snmp_agent_port},snmpSecurityLevel={snmp_security_level}, snmpSecurityName={snmp_security_name}, snmpVersion={snmp_version}, snmpReadCommunity={snmp_community}, snmpWriteCommunity={snmp_community}  -ns={namespace} -version={version}'
            else:
                self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},IsConnectivityInformation=1 IsConnectivityInformationId=1, ipAddress="{ip_address}", snmpAgentPort={snmp_agent_port}, snmpSecurityLevel={snmp_security_level}, snmpSecurityName={snmp_security_name}, snmpVersion={snmp_version} -ns={namespace} -version={version}'

    @property
    def create_connectivity_info_kwargs(self):
        return {'node_id': self.node_id, 'ip_address': self.node_ip, 'snmp_agent_port': self.snmp_port, 'snmp_security_level': self.snmp_security_level, 'snmp_security_name': self.snmp_security_name or "NONE", 'snmp_version': self.snmp_version, 'namespace': self.CONNECTIVITY_INFO_NAMESPACE, 'version': self.CONNECTIVITY_INFO_VERSION, 'snmp_community': self.snmp_community}

    def _set_node_security_cmd(self):
        if config.has_prop('disable_ldap_user') and config.get_prop('disable_ldap_user').lower() == "true":
            self.SET_NODE_SECURITY_CMD = 'secadm credentials create --secureusername "{secure_user}" --secureuserpassword "{secure_password}" --ldapuser disable -n "{node_id}"'


class SbgIsNode(IsNode):
    NE_TYPE = 'SBG-IS'
    PLATFORM_TYPE = 'IS'


class SGSNNode(ComEcimNode):
    NE_TYPE = 'SGSN-MME'
    PLATFORM_TYPE = 'SGSN_MME'
    NETWORK_TYPE = 'CORE'


class WCGNode(ComEcimNode):
    NE_TYPE = 'vWCG'
    PLATFORM_TYPE = 'CBA'
    NETWORK_TYPE = 'CORE'


class EMENode(ComEcimNode):
    NE_TYPE = 'vEME'
    PLATFORM_TYPE = 'CBA'
    NETWORK_TYPE = 'CORE'


class RadioNode(ComEcimNode):
    NE_TYPE = 'RadioNode'
    PLATFORM_TYPE = 'CBA'
    ROOT_ELEMENT = 'ManagedElement'
    NETWORK_TYPE = 'LRAN,WRAN'

    def __init__(self, *args, **kwargs):
        super(RadioNode, self).__init__(*args, **kwargs)


class PICONode(ComEcimNode):
    NE_TYPE = 'MSRBS_V1'
    PLATFORM_TYPE = 'CBA'
    NETWORK_TYPE = 'LRAN'


class EPGNode(ComEcimNode):
    NE_TYPE = 'EPG'
    PLATFORM_TYPE = 'CBA'
    NETWORK_TYPE = 'CORE'


class VEPGNode(ComEcimNode):
    NE_TYPE = 'VEPG'
    PLATFORM_TYPE = 'CBA'
    NETWORK_TYPE = 'CORE'


class SAPCNode(ComEcimNode):
    NE_TYPE = 'SAPC'
    PLATFORM_TYPE = 'CBA'
    NETWORK_TYPE = 'LRAN'


class SBGNode(ComEcimNode):
    NE_TYPE = 'SBG'
    PLATFORM_TYPE = 'CBA'


class RadioTNode(ComEcimNode):
    NE_TYPE = 'RadioTNode'
    PLATFORM_TYPE = ''

    def __init__(self, *args, **kwargs):
        super(RadioTNode, self).__init__(*args, **kwargs)
        self.transport_protocol = self.transport_protocol or TLS

    @property
    def create_networkelement_kwargs(self):
        if config.has_prop("add_model_identity"):
            return {'netype': self.NE_TYPE, 'model_identity': self.model_identity,
                    'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION,
                    'node_id': self.node_id, 'oss_prefix': self.oss_prefix,
                    'time_zone': self.time_zone}
        else:
            return {'netype': self.NE_TYPE, 'namespace': self.NETWORK_ELEMENT_NAMESPACE,
                    'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'oss_prefix': self.oss_prefix,
                    'time_zone': self.time_zone}

    @property
    def set_node_security_cmd_kwargs(self):
        return {'secure_user': self.secure_user or 'netsim', 'secure_password': self.secure_password or 'netsim',
                'node_id': self.node_id}

    @property
    def create_connectivity_info_kwargs(self):
        return {'node_id': self.node_id, 'ip_address': self.node_ip, 'port': self.netconf_port,
                'namespace': self.CONNECTIVITY_INFO_NAMESPACE, 'version': self.CONNECTIVITY_INFO_VERSION,
                'transport_protocol': self.transport_protocol}

    def create_connectivity_cmd(self):
        self.CREATE_CONNECTIVITY_INFO_CMD = ('cmedit create NetworkElement={node_id},ComConnectivityInformation=1 '
                                             'ComConnectivityInformationId="1",port="{port}",'
                                             'transportProtocol="{transport_protocol}",ipAddress="{ip_address}" '
                                             '-ns={namespace} -v={version}')

    def create_networkelement_cmd(self):
        cmd_stub = 'cmedit create NetworkElement={node_id} networkElementId={node_id}, neType={netype}, ossPrefix="{oss_prefix}"'
        if config.has_prop("add_model_identity") and config.get_prop("add_model_identity") and self.model_identity:
            cmd_stub += ', ossModelIdentity="{model_identity}"'

        if self.time_zone:
            cmd_stub += ", timeZone={time_zone}"
        self.CREATE_NETWORK_ELEMENT_CMD = cmd_stub + " -ns={namespace} -version={version}"


class TCU04Node(RadioTNode):
    NE_TYPE = 'RadioTNode'
    PLATFORM_TYPE = ''


class C608Node(RadioTNode):
    NE_TYPE = 'RadioTNode'
    PLATFORM_TYPE = ''


class MTASNode(ComEcimNode):
    NE_TYPE = 'MTAS'
    PLATFORM_TYPE = ''

    def __init__(self, *args, **kwargs):
        kwargs["snmp_port"] = 161
        super(MTASNode, self).__init__(*args, **kwargs)


class CSCFNode(ComEcimNode):
    NE_TYPE = 'CSCF'
    PLATFORM_TYPE = ''


class WMGNode(ComEcimNode):
    NE_TYPE = 'WMG'
    PLATFORM_TYPE = ''


class VWMGNode(ComEcimNode):
    NE_TYPE = 'vWMG'
    PLATFORM_TYPE = ''


class DSCNode(ComEcimNode):
    NE_TYPE = 'DSC'
    PLATFORM_TYPE = ''


class BSCNode(ComEcimNode):
    NE_TYPE = 'BSC'
    PLATFORM_TYPE = 'ECIM'
    CONNECTIVITY_INFO_NAMESPACE = "BSC_MED"
    CONNECTIVITY_INFO_PORT = 830
    APNODEAIPADDRESS = "172.168.16.46"
    APNODEBIPADDRESS = "172.168.16.35"
    CREATE_CONNECTIVITY_INFO_CMD = ""
    CONNECTIVITY_INFO_VERSION = "1.0.0"
    SET_NODE_SECURITY_CMD = ('secadm credentials create '
                             '--secureusername netsim --secureuserpassword "{secure_password}" '
                             '--nwieasecureusername netsim --nwieasecureuserpassword {secure_password} '
                             '--nwiebsecureusername netsim --nwiebsecureuserpassword {secure_password} -n {node_id}')

    @property
    def create_connectivity_info_kwargs(self):
        return {'node_id': self.node_id, 'ip_address': self.node_ip, 'port': self.CONNECTIVITY_INFO_PORT,
                'aIpaddress': self.apnodeAIpAddress or self.APNODEAIPADDRESS,
                'bIpaddress': self.apnodeBIpAddress or self.APNODEBIPADDRESS,
                'namespace': self.CONNECTIVITY_INFO_NAMESPACE, 'version': self.CONNECTIVITY_INFO_VERSION,
                'transport_protocol': self.transport_protocol}

    def create_connectivity_cmd(self):
        self.CREATE_CONNECTIVITY_INFO_CMD = ('cmedit create NetworkElement={node_id},BscConnectivityInformation=1 '
                                             'BscConnectivityInformationId="1",ipAddress="{ip_address}",port="{port}",'
                                             'transportProtocol={transport_protocol},apnodeBIpAddress="{bIpaddress}",'
                                             'apnodeAIpAddress="{aIpaddress}" -namespace={namespace} '
                                             '-version={version}')


class ER6000Node(Node):

    CONNECTIVITY_INFO_NAMESPACE = "ER6000_MED"
    CONNECTIVITY_INFO_VERSION = "1.2.0"
    CONNECTIVITY_INFO_PORT = 830
    SNMP_AGENT_PORT = 161

    # Create Commands
    CREATE_MECONTEXT_CMD = "cmedit create {subnetwork}MeContext={node_id} MeContextId={node_id}, neType={netype}, platformType={platformtype} -namespace={namespace} -version={version}"
    CREATE_NETWORK_ELEMENT_CMD = ''
    CREATE_CONNECTIVITY_INFO_CMD = ''
    SET_NODE_SECURITY_CMD = 'secadm credentials create --secureusername "{secure_user}" --secureuserpassword "{secure_password}" -n "{node_id}"'
    UPDATE_NODE_SECURITY_CMD = 'secadm credentials update --secureusername "{secure_user}" --secureuserpassword "{secure_password}" -n "{node_id}"'
    SET_SNMP_CMD = 'secadm snmp authpriv --auth_algo {auth_algo} --auth_password "{auth_password}" --priv_algo {priv_algo} --priv_password "{priv_password}" -n "{node_id}"'

    ROOT_ELEMENT = 'MeContext'

    def __init__(self, *args, **kwargs):
        super(ER6000Node, self).__init__(*args, **kwargs)
        self.transport_protocol = self.transport_protocol or TLS

    @property
    def create_mecontext_kwargs(self):
        return {'netype': self.NE_TYPE, 'namespace': self.MECONTEXT_NAMESPACE, 'version': self.MECONTEXT_VERSION, 'node_id': self.node_id, 'platformtype': self.PLATFORM_TYPE, 'subnetwork': self.subnetwork_str + "," if self.subnetwork else ""}

    @property
    def create_networkelement_kwargs(self):
        if config.has_prop("add_model_identity"):
            return {'netype': self.NE_TYPE, 'platformtype': self.PLATFORM_TYPE, 'model_identity': self.model_identity, 'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'oss_prefix': self.oss_prefix, 'time_zone': self.time_zone}
        else:
            return {'netype': self.NE_TYPE, 'platformtype': self.PLATFORM_TYPE, 'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'oss_prefix': self.oss_prefix, 'time_zone': self.time_zone}

    @property
    def create_connectivity_info_kwargs(self):
        return {'node_id': self.node_id, 'ip_address': self.node_ip, 'port': self.CONNECTIVITY_INFO_PORT,
                'snmp_agent_port': self.snmp_port, 'snmp_security_level': self.snmp_security_level,
                'snmp_security_name': self.snmp_security_name or "public", 'snmp_version': self.snmp_version,
                'namespace': self.CONNECTIVITY_INFO_NAMESPACE, 'version': self.CONNECTIVITY_INFO_VERSION,
                'snmp_community': self.snmp_community or "public", 'transport_protocol': self.transport_protocol}

    @property
    def set_node_security_cmd_kwargs(self):
        return {'secure_user': self.secure_user, 'secure_password': self.secure_password, 'node_id': self.node_id}

    @property
    def set_snmp_cmd_kwargs(self):
        return {'auth_algo': self.snmp_authentication_method or "NONE", 'auth_password': self.snmp_auth_password, 'priv_algo': self.snmp_encryption_method or "NONE", 'priv_password': self.snmp_priv_password, 'node_id': self.node_id}

    def create_networkelement_cmd(self):
        cmd_stub = 'cmedit create NetworkElement={node_id} networkElementId={node_id}, neType={netype}, platformType={platformtype}, ossPrefix="{oss_prefix}"'
        if config.has_prop("add_model_identity") and config.get_prop("add_model_identity") and self.model_identity:
            cmd_stub += ', ossModelIdentity="{model_identity}"'

        if self.time_zone:
            cmd_stub += ", timeZone={time_zone}"
        self.CREATE_NETWORK_ELEMENT_CMD = cmd_stub + " -ns={namespace} -version={version}"

    def create_connectivity_cmd(self):
        if self.snmp_version == SnmpVersion.SNMP_V3:
            self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},Er6000ConnectivityInformation=1 ComConnectivityInformationId=1,transportProtocol="{transport_protocol}", ipAddress="{ip_address}", port={port}, snmpAgentPort={snmp_agent_port}, snmpSecurityLevel={snmp_security_level}, snmpSecurityName={snmp_security_name}, snmpVersion={snmp_version}, snmpReadCommunity={snmp_community}, snmpWriteCommunity={snmp_community} -ns={namespace} -version={version}'
        else:
            self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},Er6000ConnectivityInformation=1 ComConnectivityInformationId=1,transportProtocol="{transport_protocol}", ipAddress="{ip_address}", port={port}, snmpAgentPort={snmp_agent_port}, snmpVersion={snmp_version}, snmpReadCommunity={snmp_community}, snmpWriteCommunity={snmp_community} -ns={namespace} -version={version}'


class Router6672Node(ER6000Node):
    NE_TYPE = 'Router6672'
    PLATFORM_TYPE = 'ER6000'


class MiniLinkNode(Node):

    CONNECTIVITY_INFO_NAMESPACE = ""
    CONNECTIVITY_INFO_VERSION = "1.0.0"
    SNMP_AGENT_PORT = 161
    CONNECTIVITY_LOCATION_VALUE = ''

    # Create Commands
    CREATE_MECONTEXT_CMD = "cmedit create {subnetwork}MeContext={node_id} MeContextId={node_id}, neType={netype}, platformType={platformtype} -namespace={namespace} -version={version}"
    CREATE_NETWORK_ELEMENT_CMD = ''
    CREATE_CONNECTIVITY_INFO_CMD = ''
    SET_NODE_SECURITY_CMD = ('secadm credentials create --rootusername "{secure_user}" --rootuserpassword '
                             '"{secure_password}" --secureusername "{secure_user}" --secureuserpassword '
                             '"{secure_password}" --normalusername "{normal_user}" --normaluserpassword '
                             '"{normal_password}" -n "{node_id}"')
    UPDATE_NODE_SECURITY_CMD = 'secadm credentials update --rootusername ericsson --rootuserpassword ericsson --secureusername "{secure_user}" --secureuserpassword "{secure_password}" --normalusername "{normal_user}" --normaluserpassword "{normal_password}" -n "{node_id}"'
    SET_SNMP_CMD = 'secadm snmp authpriv --auth_algo "{auth_algo}" --auth_password "{auth_password}" --priv_algo "{priv_algo}" --priv_password "{priv_password}" -n "{node_id}"'

    @property
    def snmp_security_level(self):
        """

        :return: Snmp Security Level
        :rtype: str
        """

        if self.snmp_encryption_method:
            return SnmpSecurityLevel.AUTH_PRIV
        else:
            return SnmpSecurityLevel.AUTH_NO_PRIV

    @property
    def create_mecontext_kwargs(self):
        return {'netype': self.NE_TYPE, 'namespace': self.MECONTEXT_NAMESPACE, 'version': self.MECONTEXT_VERSION, 'node_id': self.node_id, 'platformtype': self.PLATFORM_TYPE, 'subnetwork': self.subnetwork_str + "," if self.subnetwork else ""}

    @property
    def create_networkelement_kwargs(self):
        if config.has_prop("add_model_identity"):
            return {'netype': self.NE_TYPE, 'platformtype': self.PLATFORM_TYPE, 'model_identity': self.model_identity, 'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'oss_prefix': self.oss_prefix, 'time_zone': self.time_zone}
        else:
            return {'netype': self.NE_TYPE, 'platformtype': self.PLATFORM_TYPE, 'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'oss_prefix': self.oss_prefix, 'time_zone': self.time_zone}

    @property
    def create_connectivity_info_kwargs(self):
        return {'node_id': self.node_id, 'ip_address': self.node_ip, 'snmp_security_level': self.snmp_security_level,
                'snmp_security_name': self.snmp_security_name or "ericsson",
                'namespace': self.CONNECTIVITY_INFO_NAMESPACE,
                'version': self.CONNECTIVITY_INFO_VERSION, 'located': self.CONNECTIVITY_LOCATION_VALUE,
                'snmp_version': self.snmp_version}

    @property
    def set_node_security_cmd_kwargs(self):
        if self.snmp_version == SnmpVersion.SNMP_V2C:
            self.secure_user = "admin"
        return {'secure_user': self.secure_user or 'control_user', 'node_id': self.node_id,
                'secure_password': self.secure_password or 'ericsson',
                'normal_user': self.normal_user or 'view_user', 'normal_password': self.normal_password or 'ericsson'}

    @property
    def set_snmp_cmd_kwargs(self):
        return {'auth_algo': self.snmp_authentication_method or 'MD5',
                'auth_password': self.snmp_auth_password or 'ericsson',
                'priv_algo': self.snmp_encryption_method or 'DES',
                'priv_password': self.snmp_priv_password or 'ericsson',
                'node_id': self.node_id}

    def create_networkelement_cmd(self):
        cmd_stub = 'cmedit create NetworkElement={node_id} networkElementId={node_id}, neType={netype}, platformType={platformtype}, ossPrefix="{oss_prefix}"'
        if config.has_prop("add_model_identity") and config.get_prop("add_model_identity") and self.model_identity:
            cmd_stub += ', ossModelIdentity="{model_identity}"'

        if self.time_zone:
            cmd_stub += ", timeZone={time_zone}"
        self.CREATE_NETWORK_ELEMENT_CMD = cmd_stub + " -ns={namespace} -version={version}"

    def create_connectivity_cmd(self):
        self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},MINILINK{located}ConnectivityInformation=1 MINILINK{located}ConnectivityInformationId=1, ipAddress="{ip_address}", snmpSecurityLevel={snmp_security_level}, snmpSecurityName={snmp_security_name} -ns={namespace} -version={version}'


class MiniLinkIndoorNode(MiniLinkNode):
    NE_TYPE = 'MINI-LINK-Indoor'
    PLATFORM_TYPE = 'MINI-LINK-Indoor'
    CONNECTIVITY_INFO_NAMESPACE = "MINI-LINK-Indoor_MED"
    CONNECTIVITY_LOCATION_VALUE = 'Indoor'


class MiniLinkOutdoorNode(MiniLinkNode):
    NE_TYPE = 'MINI-LINK-Outdoor'
    PLATFORM_TYPE = 'MINI-LINK-Outdoor'
    CONNECTIVITY_INFO_NAMESPACE = "MINI-LINK-Outdoor_MED"
    CONNECTIVITY_LOCATION_VALUE = 'Outdoor'


class MiniLink6352Node(MiniLinkOutdoorNode):
    NE_TYPE = 'MINI-LINK-6352'
    CONNECTIVITY_INFO_VERSION = "1.1.0"
    SET_SNMP_CMD = ('secadm snmp authpriv --auth_algo {auth_algo} --auth_password authpassword --priv_algo {priv_algo} '
                    '--priv_password privpassword -n {node_id}')

    @property
    def create_connectivity_info_kwargs(self):
        return {'node_id': self.node_id, 'ip_address': self.node_ip, 'snmp_security_level': self.snmp_security_level,
                'snmp_security_name': self.snmp_security_name or "ericsson",
                'namespace': self.CONNECTIVITY_INFO_NAMESPACE, 'snmp_version': self.snmp_version,
                'version': self.CONNECTIVITY_INFO_VERSION, 'located': self.CONNECTIVITY_LOCATION_VALUE}

    def create_connectivity_cmd(self):
        if self.snmp_version == SnmpVersion.SNMP_V2C:
            self.CREATE_CONNECTIVITY_INFO_CMD = ('cmedit create NetworkElement={node_id},MINILINK{located}'
                                                 'ConnectivityInformation=1 '
                                                 'MINILINK{located}ConnectivityInformationId=1, '
                                                 'ipAddress="{ip_address}", snmpVersion={snmp_version},'
                                                 'snmpReadCommunity="public" -ns={namespace} -version={version}')
        else:
            self.CREATE_CONNECTIVITY_INFO_CMD = ('cmedit create NetworkElement={node_id},MINILINK{located}'
                                                 'ConnectivityInformation=1 '
                                                 'MINILINK{located}ConnectivityInformationId=1, '
                                                 'ipAddress="{ip_address}", snmpVersion={snmp_version},'
                                                 'snmpSecurityLevel="{snmp_security_level}", '
                                                 'snmpSecurityName="{snmp_security_name}" -ns={namespace} '
                                                 '-version={version}')


class TspNode(Node):
    CONNECTIVITY_INFO_NAMESPACE = "TSP_MED"
    CONNECTIVITY_INFO_VERSION = "1.0.0"
    SNMP_AGENT_PORT = 161

    # Create Commands
    CREATE_MECONTEXT_CMD = "cmedit create {subnetwork}MeContext={node_id} MeContextId={node_id}, neType={netype} -namespace={namespace} -version={version}"
    CREATE_NETWORK_ELEMENT_CMD = ''
    CREATE_CONNECTIVITY_INFO_CMD = ''
    SET_NODE_SECURITY_CMD = 'secadm credentials create --secureusername "{secure_user}" --secureuserpassword "{secure_password}" -n "{node_id}"'
    UPDATE_NODE_SECURITY_CMD = 'secadm credentials update --secureusername "{secure_user}" --secureuserpassword "{secure_password}" -n "{node_id}"'
    SET_SNMP_CMD = 'secadm snmp authpriv --auth_algo {auth_algo} --auth_password "{auth_password}" --priv_algo {priv_algo} --priv_password "{priv_password}" -n "{node_id}"'

    ROOT_ELEMENT = 'NetworkElement'

    def __init__(self, *args, **kwargs):
        super(TspNode, self).__init__(*args, **kwargs)
        self.transport_protocol = self.transport_protocol or SSH

    @property
    def create_mecontext_kwargs(self):
        return {'netype': self.NE_TYPE, 'namespace': self.MECONTEXT_NAMESPACE, 'version': self.MECONTEXT_VERSION, 'node_id': self.node_id, 'subnetwork': self.subnetwork_str + "," if self.subnetwork else ""}

    @property
    def create_networkelement_kwargs(self):
        """

        :return: NetworkElement depending on configuration property
        :rtype: dict
        """

        if config.has_prop("add_model_identity"):
            return {'netype': self.NE_TYPE, 'model_identity': self.model_identity, 'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'revision': self.revision, 'identity': self.identity, 'oss_prefix': self.oss_prefix, 'time_zone': self.time_zone}
        else:
            return {'netype': self.NE_TYPE, 'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION, 'node_id': self.node_id, 'oss_prefix': self.oss_prefix, 'time_zone': self.time_zone}

    @property
    def snmp_security_level(self):
        """
        :return: Snmp Security Level
        :rtype: str
        """

        return SnmpSecurityLevel.AUTH_PRIV if self.snmp_encryption_method else SnmpSecurityLevel.AUTH_NO_PRIV

    def create_networkelement_cmd(self):
        cmd_stub = 'cmedit create NetworkElement={node_id} networkElementId={node_id}, neType={netype}, ossPrefix="{oss_prefix}"'
        if config.has_prop("add_model_identity") and config.get_prop("add_model_identity") and self.model_identity:
            cmd_stub += ', ossModelIdentity="{model_identity}", neProductVersion=[(revision="{revision}",identity="{identity}")]'

        if self.time_zone:
            cmd_stub += ", timeZone={time_zone}"
        self.CREATE_NETWORK_ELEMENT_CMD = cmd_stub + " -ns={namespace} -version={version}"

    @property
    def set_snmp_cmd_kwargs(self):
        return {'auth_algo': self.snmp_authentication_method or "NONE", 'auth_password': self.snmp_auth_password, 'priv_algo': self.snmp_encryption_method or "NONE", 'priv_password': self.snmp_priv_password, 'node_id': self.node_id}

    @property
    def set_node_security_cmd_kwargs(self):
        return {'secure_user': self.secure_user, 'secure_password': self.secure_password, 'node_id': self.node_id}

    def create_connectivity_cmd(self):
        if self.snmp_version == SnmpVersion.SNMP_V3:
            if self.snmp_community:
                self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},TspConnectivityInformation=1 TspConnectivityInformationId=1, ipAddress="{ip_address}", snmpAgentPort={snmp_agent_port}, snmpSecurityLevel={snmp_security_level}, snmpSecurityName={snmp_security_name}, snmpVersion={snmp_version}, snmpReadCommunity={snmp_community}, snmpWriteCommunity={snmp_community}  -ns={namespace} -version={version}'
            else:
                self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},TspConnectivityInformation=1 TspConnectivityInformationId=1, ipAddress="{ip_address}", snmpAgentPort={snmp_agent_port}, snmpSecurityLevel={snmp_security_level}, snmpSecurityName={snmp_security_name}, snmpVersion={snmp_version} -ns={namespace} -version={version}'
        else:
            if self.snmp_community:
                self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},TspConnectivityInformation=1 TspConnectivityInformationId=1, ipAddress="{ip_address}", snmpAgentPort={snmp_agent_port}, snmpSecurityLevel={snmp_security_level}, snmpVersion={snmp_version}, snmpReadCommunity={snmp_community}, snmpWriteCommunity={snmp_community}  -ns={namespace} -version={version}'
            else:
                self.CREATE_CONNECTIVITY_INFO_CMD = 'cmedit create NetworkElement={node_id},TspConnectivityInformation=1 TspConnectivityInformationId=1, ipAddress="{ip_address}", snmpAgentPort={snmp_agent_port}, snmpSecurityLevel={snmp_security_level}, snmpVersion={snmp_version} -ns={namespace} -version={version}'

    @property
    def create_connectivity_info_kwargs(self):
        return {'node_id': self.node_id, 'ip_address': self.node_ip, 'snmp_agent_port': self.snmp_port, 'snmp_security_level': self.snmp_security_level, 'snmp_security_name': self.snmp_security_name or "NONE", 'snmp_version': self.snmp_version, 'namespace': self.CONNECTIVITY_INFO_NAMESPACE, 'version': self.CONNECTIVITY_INFO_VERSION, 'snmp_community': self.snmp_community}

    def _set_node_security_cmd(self):
        if config.has_prop('disable_ldap_user') and config.get_prop('disable_ldap_user').lower() == "true":
            self.SET_NODE_SECURITY_CMD = 'secadm credentials create --secureusername "{secure_user}" --secureuserpassword "{secure_password}" --ldapuser disable -n "{node_id}"'


class CSCFTspNode(TspNode):
    NE_TYPE = 'CSCF-TSP'
    PLATFORM_TYPE = 'TSP'


class MTASTspNode(TspNode):
    NE_TYPE = 'MTAS-TSP'
    PLATFORM_TYPE = 'TSP'


class HSSFETspNode(TspNode):
    NE_TYPE = 'HSS-FE-TSP'
    PLATFORM_TYPE = 'TSP'


class CSAPCTspNode(TspNode):
    NE_TYPE = 'cSAPC-TSP'
    PLATFORM_TYPE = 'TSP'


class CCNTspNode(TspNode):
    NE_TYPE = 'CCN-TSP'
    PLATFORM_TYPE = 'TSP'


class VPNTspNode(TspNode):
    NE_TYPE = 'VPN-TSP'
    PLATFORM_TYPE = 'TSP'


class TransportNode(Node):

    CONNECTIVITY_INFO_NAMESPACE = "GEN_FM_MED"
    CONNECTIVITY_INFO_VERSION = "1.0.0"
    PLATFORM_TYPE = ''
    NE_TYPE = ''

    # Create Commands
    CREATE_NETWORK_ELEMENT_CMD = ''
    CREATE_CONNECTIVITY_INFO_CMD = ''
    SET_NODE_SECURITY_CMD = ('secadm credentials create --secureusername {secure_user} --secureuserpassword '
                             '{secure_password}  --nodelist "{node_id}"')
    UPDATE_NODE_SECURITY_CMD = ('secadm credentials update --secureusername {secure_user} --secureuserpassword '
                                '{secure_password} --nodelist "{node_id}"')

    def __init__(self, *args, **kwargs):
        self.NE_TYPE = "{0}-{1}".format(kwargs.get('primary_type'), kwargs.get('node_version'))
        super(TransportNode, self).__init__(*args, **kwargs)

    @property
    def create_networkelement_kwargs(self):
        if config.has_prop("add_model_identity"):
            return {'node_id': self.node_id, 'netype': self.NE_TYPE, 'model_identity': self.model_identity,
                    'time_zone': self.time_zone, 'namespace': self.NETWORK_ELEMENT_NAMESPACE,
                    'version': self.NETWORK_ELEMENT_VERSION}
        else:
            return {'netype': self.NE_TYPE, 'node_id': self.node_id, 'time_zone': self.time_zone,
                    'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION}

    @property
    def create_connectivity_info_kwargs(self):
        return {'node_id': self.node_id, 'ip_address': self.node_ip, 'namespace': self.CONNECTIVITY_INFO_NAMESPACE,
                'version': self.CONNECTIVITY_INFO_VERSION, 'snmp_version': "SNMP_V2C"}

    @property
    def set_node_security_cmd_kwargs(self):
        return {'secure_user': 'netsim', 'secure_password': 'netsim', 'node_id': self.node_id}

    def create_connectivity_cmd(self):
        self.CREATE_CONNECTIVITY_INFO_CMD = ('cmedit create NetworkElement={node_id},'
                                             'GenericFmNodeConnectivityInformation=1 '
                                             'GenericFmNodeConnectivityInformationId="1", ipAddress="{ip_address}", '
                                             'snmpVersion={snmp_version}, snmpWriteCommunity="public" -ns={namespace} '
                                             '-version={version}')

    def create_networkelement_cmd(self):
        cmd_stub = 'cmedit create NetworkElement={node_id} networkElementId={node_id}, neType={netype}'
        if config.has_prop("add_model_identity") and config.get_prop("add_model_identity") and self.model_identity:
            cmd_stub += ', ossModelIdentity="{model_identity}"'

        if self.time_zone:
            cmd_stub += ", timeZone={time_zone}"
        self.CREATE_NETWORK_ELEMENT_CMD = cmd_stub + " -ns={namespace} -version={version}"


class JuniperNode(TransportNode):
    pass


class CiscoNode(TransportNode):
    pass


class StnNode(Node):

    PLATFORM_TYPE = 'STN'
    NE_TYPE = 'STN'
    CONNECTIVITY_INFO_NAMESPACE = "STN_MED"
    CONNECTIVITY_INFO_VERSION = "1.0.0"
    CONNECTIVITY_INFO_PORT = 161

    # Create Commands
    CREATE_MECONTEXT_CMD = ("cmedit create {subnetwork}MeContext={node_id} MeContextId={node_id}, neType={netype}, "
                            "platformType={platformtype} -namespace={namespace} -version={version}")
    CREATE_NETWORK_ELEMENT_CMD = ''
    CREATE_CONNECTIVITY_INFO_CMD = ''
    SET_NODE_SECURITY_CMD = ('secadm credentials create --secureusername {secure_user} --secureuserpassword '
                             '{secure_password}  --nodelist "{node_id}"')
    UPDATE_NODE_SECURITY_CMD = ('secadm credentials update --secureusername {secure_user} --secureuserpassword '
                                '{secure_password} --nodelist "{node_id}"')
    ROOT_ELEMENT = 'MeContext'

    def __init__(self, *args, **kwargs):
        if self.NE_TYPE == 'STN':
            self.NE_TYPE = kwargs.get('simulation').split('-')[1]
        super(StnNode, self).__init__(*args, **kwargs)
        self.transport_protocol = self.transport_protocol or SSH

    @property
    def create_mecontext_kwargs(self):
        return {'netype': self.NE_TYPE, 'platformtype': self.PLATFORM_TYPE, 'namespace': self.MECONTEXT_NAMESPACE,
                'version': self.MECONTEXT_VERSION, 'node_id': self.node_id,
                'subnetwork': self.subnetwork_str + "," if self.subnetwork else ""}

    @property
    def create_networkelement_kwargs(self):
        return {'netype': self.NE_TYPE, 'platformtype': self.PLATFORM_TYPE, 'model_identity': self.model_identity,
                'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION,
                'node_id': self.node_id, 'oss_prefix': self.oss_prefix,
                'time_zone': self.time_zone}

    @property
    def create_connectivity_info_kwargs(self):
        return {'ip_address': self.node_ip, 'port': self.CONNECTIVITY_INFO_PORT,
                'version': self.CONNECTIVITY_INFO_VERSION, 'transport_protocol': self.transport_protocol,
                'node_id': self.node_id, 'namespace': self.CONNECTIVITY_INFO_NAMESPACE}

    @property
    def set_node_security_cmd_kwargs(self):
        return {'secure_user': self.secure_user or 'admin', 'secure_password': self.secure_password or 'hidden',
                'node_id': self.node_id}

    def create_networkelement_cmd(self):
        cmd_stub = ('cmedit create NetworkElement={node_id} networkElementId={node_id}, neType={netype}, '
                    'platformType={platformtype}, ossModelIdentity="{model_identity}"')
        if self.time_zone:
            cmd_stub += ", timeZone={time_zone}"
        self.CREATE_NETWORK_ELEMENT_CMD = cmd_stub + " -ns={namespace} -version={version}"

    def create_connectivity_cmd(self):
        self.CREATE_CONNECTIVITY_INFO_CMD = ('cmedit create NetworkElement={node_id},STNConnectivityInformation=1 '
                                             'StnConnectivityInformationId="1",'
                                             'transportProtocol="{transport_protocol}",snmpAgentPort="{port}",'
                                             'ipAddress="{ip_address}" -ns={namespace} -v={version}')


class SIU02Node(StnNode):
    NE_TYPE = 'SIU02'
    PLATFORM_TYPE = 'STN'


class TCU02Node(StnNode):
    NE_TYPE = 'TCU02'
    PLATFORM_TYPE = 'STN'


class Fronthaul6080Node(Node):

    NE_TYPE = 'FRONTHAUL-6080'
    CONNECTIVITY_INFO_NAMESPACE = "FRONT-HAUL-6080_MED"
    CONNECTIVITY_INFO_VERSION = "1.0.0"
    PLATFORM_TYPE = ''
    SNMP_PORT = '161'

    CREATE_NETWORK_ELEMENT_CMD = ''
    CREATE_CONNECTIVITY_INFO_CMD = ''
    SET_NODE_SECURITY_CMD = ('secadm credentials create --rootusername "admin"--rootuserpassword '
                             '"admin"  --secureusername "{secure_user}" --secureuserpassword '
                             '"{secure_password}" --normalusername "{normal_user}" --normaluserpassword '
                             '"{normal_password}" -n "{node_id}"')
    UPDATE_NODE_SECURITY_CMD = ('secadm credentials update --rootusername "{root_user}" --rootuserpassword '
                                '"{root_password}" --secureusername "{secure_user}" --secureuserpassword '
                                '"{secure_password}" --normalusername "{normal_user}" --normaluserpassword "'
                                '{normal_password}" -n "{node_id}"')

    @property
    def set_node_security_cmd_kwargs(self):
        return {
            'secure_user': self.secure_user or 'user', 'secure_password': self.secure_password or 'user',
            'normal_user': self.normal_user or 'guest', 'normal_password': self.normal_password or 'guest',
            'node_id': self.node_id}

    @property
    def create_connectivity_info_kwargs(self):
        return {'node_id': self.node_id, 'ip_address': self.node_ip, 'snmp_port': self.SNMP_PORT,
                'namespace': self.CONNECTIVITY_INFO_NAMESPACE, 'version': self.CONNECTIVITY_INFO_VERSION}

    @property
    def create_networkelement_kwargs(self):
        if config.has_prop("add_model_identity"):
            return {'node_id': self.node_id, 'netype': self.NE_TYPE, 'model_identity': self.model_identity,
                    'oss_prefix': self.oss_prefix, 'time_zone': self.time_zone,
                    'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION}
        else:
            return {'netype': self.NE_TYPE, 'node_id': self.node_id,
                    'oss_prefix': self.oss_prefix, 'time_zone': self.time_zone,
                    'namespace': self.NETWORK_ELEMENT_NAMESPACE, 'version': self.NETWORK_ELEMENT_VERSION}

    def create_networkelement_cmd(self):
        cmd_stub = 'cmedit create NetworkElement={node_id} networkElementId={node_id}, neType={netype}, ossPrefix="{oss_prefix}"'
        if config.has_prop("add_model_identity") and config.get_prop("add_model_identity") and self.model_identity:
            cmd_stub += ', ossModelIdentity="{model_identity}"'

        if self.time_zone:
            cmd_stub += ", timeZone={time_zone}"
        self.CREATE_NETWORK_ELEMENT_CMD = cmd_stub + " -ns={namespace} -version={version}"

    def create_connectivity_cmd(self):
        self.CREATE_CONNECTIVITY_INFO_CMD = ('cmedit create NetworkElement={node_id},'
                                             'FrontHaul6080ConnectivityInformation=1 '
                                             'FrontHaul6080ConnectivityInformationId="1",ipAddress="{ip_address}",'
                                             'snmpAgentPort="{snmp_port}" -ns={namespace} -v={version}')


class APGNode(CppNode):
    NE_TYPE = ''
    PLATFORM_TYPE = 'ECIM'
    CONNECTIVITY_INFO_NAMESPACE = "MSC_MED"
    CREATE_CONNECTIVITY_INFO_CMD = ""
    SET_NODE_SECURITY_CMD = ('secadm credentials create --secureusername "{secure_user}" --secureuserpassword '
                             '"{secure_password}" -n "{node_id}"')

    @property
    def create_connectivity_info_kwargs(self):
        return {'node_id': self.node_id, 'ip_address': self.node_ip, 'port': self.netconf_port,
                'aIpaddress': self.apnodeAIpAddress or "0.0.0.0", 'bIpaddress': self.apnodeBIpAddress or "0.0.0.0",
                'namespace': self.CONNECTIVITY_INFO_NAMESPACE, 'version': self.CONNECTIVITY_INFO_VERSION,
                'transport_protocol': self.transport_protocol}

    def create_connectivity_cmd(self):
        self.CREATE_CONNECTIVITY_INFO_CMD = ('cmedit create NetworkElement={node_id},MscConnectivityInformation=1 '
                                             'MscConnectivityInformationId="1",ipAddress="{ip_address}",'
                                             'apnodeAIpAddress={aIpaddress},apnodeBIpAddress={bIpaddress} '
                                             '-namespace={namespace} -version={version}')


class VMSCNode(APGNode):
    NE_TYPE = 'vMSC'


class MSCDBNode(APGNode):
    NE_TYPE = 'MSC-DB'


class IPSTPNode(APGNode):
    NE_TYPE = 'IP-STP'


class VIPSTPNode(APGNode):
    NE_TYPE = 'vIP-STP'


NODE_CLASS_MAP = {
    'ERBS': ERBSNode,
    'SGSN': SGSNNode,
    'RadioNode': RadioNode,
    'MSRBS_V1': PICONode,
    'MGW': MGWNode,
    'SpitFire': Router6672Node,
    'Router_6672': Router6672Node,
    'MLTN': MiniLinkIndoorNode,
    'EPG': EPGNode,
    'EPDG': WMGNode,
    'EPG-SSR': EPGNode,
    'VEPG': VEPGNode,
    'RNC': RNCNode,
    'SAPC': SAPCNode,
    'MTAS': MTASNode,
    'SBG': SBGNode,
    'SBG-IS': SbgIsNode,
    'CSCF': CSCFNode,
    'WMG': WMGNode,
    'vWMG': VWMGNode,
    'DSC': DSCNode,
    'RBS': RBSNode,
    'RadioTNode': RadioTNode,
    'CSCF-TSP': CSCFTspNode,
    'MTAS-TSP': MTASTspNode,
    'HSS-FE-TSP': HSSFETspNode,
    'cSAPC-TSP': CSAPCTspNode,
    'CCN-TSP': CCNTspNode,
    'VPN-TSP': VPNTspNode,
    'JUNIPER': JuniperNode,
    'CISCO': CiscoNode,
    'STN': StnNode,
    'SIU02': SIU02Node,
    'TCU02': TCU02Node,
    'TCU04': TCU04Node,
    'C608': C608Node,
    'Fronthaul-6080': Fronthaul6080Node,
    'LH': MiniLinkIndoorNode,
    'MINI-LINK-6352': MiniLink6352Node,
    'BSC': BSCNode,
    'MSC-DB': MSCDBNode,
    'vMSC': VMSCNode,
    'vIP-STP': VIPSTPNode,
    'IP-STP': IPSTPNode,
    'STP': IPSTPNode,
    'ECM': VMSCNode,
    'MSC-BC-BSP': MSCDBNode,
    'MINI-LINK-6351': MiniLink6352Node,
    'PT2020': MiniLink6352Node,
    'PT': MiniLink6352Node,
    'switch-6391': MiniLink6352Node,
    'Fronthaul-6392': MiniLink6352Node,
    'WCG': WCGNode,
    'vWCG': WCGNode,
    'EME': EMENode,
    'vEME': EMENode
}

# MOST OF BELOW, COULD BE MOVED TO THE load_node.py in the internal package


def get_all_enm_network_element_objects(user):
    """
    Get all NetworkElement objects from ENM

    :param user: object to be used to make http requests
    :type user: enm_user_2.User
    :return: response
    :rtype: `Response` object
    :raises HTTPError: if the response is not ok
    """

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    response = user.get(NETEX_ENDPOINT, headers=headers)
    if not response.ok:
        raise HTTPError("Unable to get data from Network Explorer", response=response)

    return response


def verify_nodes_against_enm(nodes, user):
    """
    This should verify that (passed in) nodes still exist on ENM. Log it otherwise.

    :param nodes: list of Node objects to be populated
    :type nodes: enm_node.Node
    :param user:object to be used to make http requests
    :type user: enm_user_2.User
    :return: common nodes object, nodes object not on enm, enm nodes partial data
    :rtype: list, list, dict
    """

    all_enm_network_elements_data_json = get_all_enm_network_element_objects(user).json()

    nodes_ids = {node.node_id for node in nodes}
    # build data structure to hold nodes information received from ENM
    enm_nodes_partial_data = {
        node['moName']: (node['moType'], node['poId']) for node in all_enm_network_elements_data_json}

    # from within supplied nodes, only work with nodes that are also found on ENM
    common_nodes_ids = set(enm_nodes_partial_data).intersection(nodes_ids)
    common_nodes_obj = [node for node in nodes if node.node_id in common_nodes_ids]

    nodes_obj_not_on_enm = list(set(nodes).difference(common_nodes_obj))

    if nodes_obj_not_on_enm:
        log.logger.debug("Warning: These nodes don't appear to be on ENM: {0}".format(
            ', '.join([node.node_id for node in nodes_obj_not_on_enm])))

    return common_nodes_obj, nodes_obj_not_on_enm, enm_nodes_partial_data


def annotate_fdn_poid_return_node_objects(nodes, user):
    """
    Annotate the fdn and poid on the given node objects, based on information available from ENM
    and return amended common Node objects

    :param nodes: list of `LoadNodeMixin` objects
    :type nodes: list
    :param user: object to be used to make http requests
    :type user: enm_user_2.User
    :return: list of Node objects
    :rtype: list
    """

    common_nodes_obj, _, enm_nodes_partial_data = verify_nodes_against_enm(nodes, user)
    #  Add fdn and poid to specified nodes in the workload pool
    for node in common_nodes_obj:
        moType = enm_nodes_partial_data[node.node_id][0]
        fdn = '%s=%s' % (moType, node.node_id)
        poid = enm_nodes_partial_data[node.node_id][1]

        node.set_fdn_poid(fdn, poid)

    return common_nodes_obj


def annotate_fdn_poid(nodes, user):
    """
    Annotate the fdn and poid from ENM to the given nodes. Return nodes ids only

    :param nodes: list of `nssutils.lib.enm_node.Node` objects to be populated
    :type nodes: list
    :param user: User object to be used to make http requests
    :type user: enm_user_2.User
    :return: set of common nodes id
    :rtype: list
    """

    common_nodes_ids = [node.node_id for node in annotate_fdn_poid_return_node_objects(nodes, user)]
    return set(common_nodes_ids)


def verify_poids_on_nodes(nodes_to_verify):
    """

    :param nodes_to_verify: list of `nssutils.lib.enm_node.Node` objects to be populated
    :type nodes_to_verify: list
    :return: nodes with poids, nods without poids
    :rtype: list, list
    """

    nodes_to_verify = set(nodes_to_verify)

    nodes_with_no_poids = [n for n in nodes_to_verify if not n.poid]
    nodes_with_poids = list(nodes_to_verify.difference(set(nodes_with_no_poids)))

    if nodes_with_no_poids:
        log.logger.debug('These nodes have no poids: {0}'.format(', '.join([n.node_id for n in nodes_with_no_poids])))

    assert len(nodes_to_verify) == len(nodes_with_poids + nodes_with_no_poids)

    return nodes_with_poids, nodes_with_no_poids


def get_nodes_by_cell_size(cells, user):
    """
    Returns a list of nodes of with the specified number of cells

    :param cells: Create a list of nodes with the corresponding number of cells
    :type cells: list
    :param user: User object to be used to make http requests
    :type user: enm_user_2.User
    :return: list of nodes name
    :rtype: list
    """

    node_cells_cmd = "cmedit get * EUtranCellFDD.EUtranCellFDDId -t"
    cell_regex = r"\s+\d+\s+([a-zA-Z0-9_-]+)"
    cell_size_regex = r"([a-zA-Z0-9_]+)-{0}"

    response = user.enm_execute(node_cells_cmd)

    matches = re.findall(cell_regex, ','.join(line for line in response.get_output()))
    matching_cells = re.findall(cell_size_regex.format(cells), ','.join(match for match in matches))
    matching_cells_plus_one = re.findall(cell_size_regex.format(cells + 1), ','.join(match for match in matches))

    return list(set(matching_cells) - (set(matching_cells_plus_one)))


def get_enm_network_element_sync_states(enm_user):
    """
    B{To get the synchronization status of network elements in ENM}

    :type enm_user: enm_user_2.User
    :param enm_user: User to run ENM CLI commands
    :rtype: dict[str, str]
    :return: The sync status of all network elements in ENM
    :raises RuntimeError: if there is error in response
    """

    response = enm_user.enm_execute("cmedit get * CmFunction.syncStatus -t")
    if "Error" in "\n".join(response.get_output()):
        raise RuntimeError("Could not read synchronization status of network elements in ENM: {output}".format(output=response.get_output()))

    enm_network_element_sync_states = {}
    for line in response.get_output()[2:-2]:
        node_id, _, _, sync_status = line.split("\t")
        enm_network_element_sync_states[node_id.strip()] = sync_status.strip()

    log.logger.debug(str("Sync States of Network Elements already in ENM: {}".format(str(enm_network_element_sync_states))))
    return enm_network_element_sync_states


class DeleteNetwork(object):

    DELETE_NETWORKELEMENT_CMD = "cmedit delete {node_ids} NetworkElement -ALL"
    DELETE_SUBNETWORK_CMD = "cmedit delete {subnetwork} SubNetwork -ALL"
    DELETE_MECONTREXT_CMD = "cmedit delete {node_ids} MeContext -ALL"
    DELETENRMDATAFROMENM_CMD = "cmedit action {node_ids} CmFunction deleteNrmDataFromEnm"

    def __init__(self, node_ids="*", subnetworks="*", user=None):
        self.node_ids = node_ids
        self.subnetworks = subnetworks
        self.user = user or get_admin_user()

    def delete_network_element(self):
        """
        Deletes NetworkElements on ENM
        """

        response = self.user.enm_execute(self.DELETE_NETWORKELEMENT_CMD.format(node_ids=";".join(self.node_ids)))
        output = response.get_output()
        if "ERROR" in " ".join(output) or \
                ("instance(s) deleted" not in output[-1] and "found" not in output[-1]):
            raise ScriptEngineResponseValidationError("Failed to delete NetworkElement of nodes {0}"
                                                      "".format(";".join(self.node_ids)), response=response)

    def delete_mecontext(self):
        """
        Deletes MeContexts on ENM
        """

        response = self.user.enm_execute(self.DELETE_MECONTREXT_CMD.format(node_ids=";".join(self.node_ids)))
        output = response.get_output()
        if "ERROR" in " ".join(output) or \
                ("instance(s) deleted" not in output[-1] and "found" not in output[-1]):
            raise ScriptEngineResponseValidationError("Failed to delete MeContext of nodes {0}"
                                                      "".format(";".join(self.node_ids)), response=response)

    def delete_nrm_data_from_enm(self):
        """
        Performs CmFunction deleteNrmDataFromEnm action on ENM
        """

        response = self.user.enm_execute(self.DELETENRMDATAFROMENM_CMD.format(node_ids=";".join(self.node_ids)))
        output = response.get_output()
        if "ERROR" in " ".join(output) or "instance(s)" not in output[-1]:
            raise ScriptEngineResponseValidationError("Failed action CmFunction for deleteNrmDataFromEnm of nodes {0}"
                                                      "".format(";".join(self.node_ids)), response=response)

    def delete_subnetwork(self):
        """
        Deletes Subnetworks from ENM
        """

        response = self.user.enm_execute(self.DELETE_SUBNETWORK_CMD.format(subnetwork=";".join(self.subnetworks)))
        output = response.get_output()
        if "ERROR" in " ".join(output) or \
                ("instance(s) deleted" not in output[-1] and "found" not in output[-1]):
            raise ScriptEngineResponseValidationError("Failed delete Subnetwork for Subnetworks {0}"
                                                      "".format(";".join(self.subnetworks)), response=response)


class SnmpVersion(Enum):
    SNMP_V1 = ("SNMP_V1", ["v1"])
    SNMP_V2C = ("SNMP_V2C", ["v2c", "v2"])
    SNMP_V3 = ("SNMP_V3", ["v3"])

    def __str__(self):
        return self.enm_representation

    def __lt__(self, other):
        return self.enm_representation < other.enm_representation

    @property
    def enm_representation(self):
        return self.value[0]

    @property
    def arne_representations(self):
        return self.value[1]

    @classmethod
    def from_arne_value(cls, value):
        """
        Returns the SNMP version enum that the value refers to. If the value contains more than one version (e.g. 'v1+v2+v3'), the highest version is returned

        :type value: str
        :param value: The string representation used by ARNE to refer to a version of SNMP. Can refer to multiple version (e.g. v1+v2)
        :return: Snmp Version
        :rtype: dict[str]
        """

        return sorted(cls._from_arne_value(version) for version in value.split("+"))[-1]

    @classmethod
    def _from_arne_value(cls, value):
        """
        Returns the SNMP version enum that the value refers to

        :type value: str
        :param value: The string representation used by ARNE to refer to a version of SNMP (e.g. v3). Can only refer to a single version
        :return: Snmp Version
        :rtype: str
        :raises ValueError: if there is StopIteration exception
        """

        try:
            return next(snmp_version for snmp_version in SnmpVersion if value.lower() in snmp_version.arne_representations)
        except StopIteration:
            raise ValueError("'{}' is not a valid SNMP version".format(value))

    @classmethod
    def from_enm_value(cls, value):
        """
        Returns the SNMP version enum that the value refers to

        :type value: str
        :param value: The string representation used by ENM to refer to a version of SNMP (e.g. SNMP_V3)
        :return: Snmp Version
        :rtype: str
        :raises ValueError: if there is StopIteration exception
        """

        try:
            return next(snmp_version for snmp_version in SnmpVersion if value in snmp_version.enm_representation)
        except StopIteration:
            raise ValueError("'{}' is not a valid SNMP version".format(value))


class SnmpEncryptionMethod(Enum):
    AES_128 = ("AES128", "AES-128")
    CBC_DES = ("DES", "CBC-DES")

    def __str__(self):
        return self.value[0]

    @property
    def enm_representation(self):
        return self.value[0]

    @property
    def arne_representation(self):
        return self.value[1]

    @classmethod
    def from_enm_value(cls, value):
        """
        Returns the appropriate SNMP encryption algorithm based on a value from an ARNE XML

        :type value: str
        :param value: The value of SNMP encryptionMethod retrieved from ARNE
        :return: Snmp Encryption Method
        :rtype: str
        :raises ValueError: if there is StopIteration exception
        """

        try:
            return next(method for method in cls if method.enm_representation == value)
        except StopIteration:
            raise ValueError("'{}' is not a valid SNMP encryption method".format(value))

    @classmethod
    def from_arne_value(cls, value):
        """
        Returns the appropriate SNMP encryption algorithm based on a value from ENM

        :type value: str
        :param value: The value of SNMP encryptionMethod retrieved from ENM
        :return: Snmp Encryption Method
        :rtype: str
        :raises ValueError: if there is StopIteration exception
        """

        try:
            return next(method for method in cls if method.arne_representation == value)
        except StopIteration:
            raise ValueError("'{}' is not a valid SNMP encryption method".format(value))


class SnmpAuthenticationMethod(Enum):
    MD5 = ["MD5", "MD5"]
    SHA = ["SHA1", "SHA"]

    def __str__(self):
        return self.value[0]

    @property
    def enm_representation(self):
        return self.value[0]

    @property
    def arne_representation(self):
        return self.value[1]

    @classmethod
    def from_arne_value(cls, value):
        """
        Returns the appropriate SNMP authentication algorithm based on a value from an ARNE XML

        :type value: str
        :param value: The value of SNMP authenticationMethod retrieved from ARNE
        :return: Snmp Authentication Method
        :rtype: str
        :raises ValueError: if there is StopIteration exception
        """

        try:
            return next(method for method in cls if method.arne_representation == value)
        except StopIteration:
            raise ValueError("'{}' is not a valid SNMP authentication method".format(value))

    @classmethod
    def from_enm_value(cls, value):
        """
        Returns the appropriate SNMP authentication algorithm based on a value from ENM

        :type value: str
        :param value: The value of SNMP authenticationMethod retrieved from ENM
        :return: Snmp Authentication Method
        :rtype: str
        :raises ValueError: if there is StopIteration exception
        """

        try:
            return next(method for method in cls if method.enm_representation == value)
        except StopIteration:
            raise ValueError("'{}' is not a valid SNMP authentication method".format(value))


class SnmpSecurityLevel(Enum):
    NO_AUTH_NO_PRIV = "NO_AUTH_NO_PRIV"
    AUTH_NO_PRIV = "AUTH_NO_PRIV"
    AUTH_PRIV = "AUTH_PRIV"

    def __str__(self):
        return self.value
