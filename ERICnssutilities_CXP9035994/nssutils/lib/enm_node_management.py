import re

from nssutils.lib import log
from nssutils.lib.enm_user_2 import get_admin_user
from nssutils.lib.exceptions import ScriptEngineResponseValidationError


class Management(object):
    EXTRACT_INSTANCES_VALUE = r"\d+(?=\sinstance\(s\))"
    FAILED_GROUP_REGEX = r"\d+(?=\sout\sof\s\d+\sobjects)"
    EXTRACT_NODE_ID = r"(?<=NetworkElement=)(.*?)(?=,)"

    def __init__(self, node_ids="*", user=None, regex=None, ne_type=None, collections=None):
        """
        Management constructor

        :type node_ids: list
        :param node_ids: A list of node_ids
        :type user: string or None
        :param user: The user that will be used for accessing ENM and issuing the commands.
        :type ne_type: string or None
        :param ne_type: network element type ed. RadioNode
        :type collections: netex.Collection object
        :param collections: an enm collection of nodes
        """
        if not collections:
            self.node_ids = node_ids
            self.node_id = node_ids[0] if len(node_ids) == 1 and node_ids[0] != "*" else None
        if collections:
            self.node_ids = []
        self.collections = collections
        self.regex = regex
        self.user = user or get_admin_user()
        self.ne_type = ne_type

    @property
    def network_elements(self):
        node_ids = self.regex if self.regex else "*" if self.node_ids == "*" else ';'.join("NetworkElement={0}".format(node_id) for node_id in self.node_ids)
        return node_ids

    @classmethod
    def get_management_obj(cls, nodes=None, user=None, collections=None):
        """
        Returns the enm node management object

        :type nodes: list
        :param nodes: List of nodes to perform the operation(s) upon
        :type user: `enm_user_2.User`
        :param user: Enm user user who will perform the operation(s)
        :type collections: list
        :param collections: List of `netex.Collections` objects, to perform the operation(s) upon

        :rtype: `enm_node_management.Management`
        :return: Management object that will perform the operation
        """
        if collections:
            return cls(user=user, collections=collections)
        if not nodes:
            return cls(user=user)
        return cls.get_management_obj_from_string([node.node_id for node in nodes], user=user)

    @classmethod
    def get_management_obj_from_string(cls, node_ids, user=None):
        return cls(node_ids=node_ids, user=user)

    @classmethod
    def get_status(cls, user, node_ids="*", regex=None):
        """
        Get status of responses

        :param user: user to execute command as
        :param node_ids: node_ids to get status of
        :param regex: regex to find node status with
        :rtype: dictionary (node_id: status)

        """
        status_dict = {}
        node_ids = regex if regex else node_ids if node_ids == "*" else ';'.join("NetworkElement={0}".format(node_id) for node_id in node_ids)

        response = user.enm_execute(cls.SUPERVISION_STATUS_CMD.format(node_ids=node_ids))

        nodes_info = ",".join(response.get_output()).split("FDN")

        for node_info in nodes_info:
            match = re.search(cls.EXTRACT_SYNC_STATUS, node_info)
            node = re.search(cls.EXTRACT_NODE_ID, node_info)
            if node and match:
                status_dict[node.group(0)] = match.group(0)

        return status_dict

    def supervise(self, timeout_seconds=600):
        """
        Enables management in ENM on self.nodes

        :raises: ScriptEngineResponseValidationError
        :rtype: None

        """
        if self.node_id:
            response = self.user.enm_execute(self.SINGLE_SUPERVISION_CMD.format(node_ids="NetworkElement={0}".format(self.node_id), active="true"), timeout_seconds=timeout_seconds)
        elif self.ne_type:
            response = self.user.enm_execute(self.NETYPE_SUPERVISION_CMD.format(active="true", ne_type=self.ne_type), timeout_seconds=timeout_seconds)
        else:
            response = self.user.enm_execute(self.MULTIPLE_SUPERVISION_CMD.format(node_ids=self.network_elements, active="true"), timeout_seconds=timeout_seconds)

        self._verify_supervise_operation(response, "supervise")

    def unsupervise(self, timeout_seconds=600):
        """
        Disables management in ENM on self.nodes

        :raises: ScriptEngineResponseValidationError
        :rtype: None
        """
        if self.node_id:
            response = self.user.enm_execute(self.SINGLE_SUPERVISION_CMD.format(node_ids="NetworkElement={0}".format(self.node_id), active="false"), timeout_seconds=timeout_seconds)
        elif self.ne_type:
            response = self.user.enm_execute(self.NETYPE_SUPERVISION_CMD.format(active="false", ne_type=self.ne_type), timeout_seconds=timeout_seconds)
        else:
            response = self.user.enm_execute(self.MULTIPLE_SUPERVISION_CMD.format(node_ids=self.network_elements, active="false"), timeout_seconds=timeout_seconds)

        self._verify_supervise_operation(response, "unsupervise")

    def synchronize(self, netype=None):
        """
        Synchronizes all nodes in ENM on self.nodes

        :type ne_type: string or None
        :param ne_type: network element type ed. RadioNode
        :raises: ScriptEngineResponseValidationError
        :rtype: None

        """
        msg = 'Unable to synchronize {0} as this functionality is not implemented in ENM.'.format(self.APPLICATION)
        if not netype and not self.collections:
            assert self.SYNCHRONIZE_CMD, msg
            response = self.user.enm_execute(self.SYNCHRONIZE_CMD.format(node_ids=self.network_elements))
        elif self.collections:
            assert self.SYNCHRONIZE_COLLECTION_CMD, msg
            response = self.user.enm_execute(self.SYNCHRONIZE_COLLECTION_CMD
                                             .format(collections=";"
                                                     .join([collection.name for collection in self.collections])))
        else:
            assert self.SYNCHRONIZE_CMD_WITH_NE_TYPE, msg
            response = self.user.enm_execute(self.SYNCHRONIZE_CMD_WITH_NE_TYPE.format(ne_type=netype))

        self._verify_sync_operation(response, collections=self.collections)

    def _verify_supervise_operation(self, response, action):
        """
        Verify results of supervision commands

        :raises: ScriptEngineResponseValidationError
        :rtype: None

        """
        num_nodes = len(self.node_ids)
        cmd_output = ','.join(line for line in response.get_output())
        match = re.search(self.INSTANCE_VERIFICATION.format(num_nodes), cmd_output)
        instances_match = re.search(self.EXTRACT_INSTANCES_VALUE, cmd_output)

        if match:
            log.logger.debug('Successfully executed {0} {1} for {2} nodes.'
                             .format(self.APPLICATION, action,
                                     ",".join(str(self.node_ids)) if num_nodes < 20 else
                                     re.search(r"\d+", match.group(0)).group(0)))
        elif instances_match:
            instances_returned = int(instances_match.group(0))
            if self.network_elements == "*" or self.regex:
                search_value = self.regex if self.regex else "*"
                # Assuming there is an error in the regex passed in since no nodes have been supervised
                if instances_returned > 0:
                    log.logger.debug('Successfully executed {0} {1} for {2} nodes with {3}.'
                                     .format(self.APPLICATION, action, instances_returned, search_value))
                else:
                    raise ScriptEngineResponseValidationError('Failed {0} {1} on all nodes with regex {2}. '
                                                              'Output = {3}'
                                                              .format(action, self.APPLICATION, search_value,
                                                                      cmd_output), response)
            else:
                raise ScriptEngineResponseValidationError('Failed {0} {1} on {2}/{3}. Output = {4}'
                                                          .format(action, self.APPLICATION,
                                                                  num_nodes - instances_returned,
                                                                  num_nodes, response.get_output()), response)
        else:
            raise ScriptEngineResponseValidationError('Failed {0} {1} on specified nodes. Output = {2}'
                                                      .format(action, self.APPLICATION, cmd_output), response)

    def _verify_sync_operation(self, response, collections=None):
        """
        Verify results of synchronization commands
        :type collections: netex.Collection object
        :param collections: an enm collection of nodes
        :raises: ScriptEngineResponseValidationError
        :rtype: None

        """
        if collections:
            for collection in collections:
                self.node_ids.extend([node.node_id for node in collection.nodes])
        num_nodes = len(self.node_ids)
        cmd_output = ','.join(line for line in response.get_output())
        instances_match = re.search(self.EXTRACT_INSTANCES_VALUE, cmd_output)
        error_match = re.search(self.FAILED_GROUP_REGEX, cmd_output)

        if instances_match:
            instances_returned = int(instances_match.group(0))
            if self.network_elements == "*" or self.regex:
                search_value = self.regex if self.regex else "*"
                # Assuming there is an error in the regex passed in since no nodes have been synchronized
                if instances_returned == 0:
                    raise ScriptEngineResponseValidationError('Failed {0} synchronization on all nodes with regex {1}. '
                                                              'Output = {2}'.format(self.APPLICATION, search_value,
                                                                                    response.get_output()), response)
                else:
                    log.logger.debug('Successfully executed {0} synchronize for {1} nodes using {2}.'.
                                     format(self.APPLICATION, instances_returned, search_value))
            elif num_nodes == int(instances_match.group(0)):
                log.logger.debug('Successfully executed {0} synchronize for {1} nodes.'.
                                 format(self.APPLICATION,
                                        ",".join(str(self.node_ids)) if len(self.node_ids) < 20 else instances_returned))
            else:
                raise ScriptEngineResponseValidationError('Failed {0} synchronize on {1}/{2} nodes. Output = {3}'
                                                          .format(self.APPLICATION, num_nodes - instances_returned,
                                                                  num_nodes, response.get_output()), response)
        elif error_match:
            raise ScriptEngineResponseValidationError('Failed {0} synchronization on {1}/{2} nodes. Output = {3}'
                                                      .format(self.APPLICATION, num_nodes - int(error_match.group(0)),
                                                              num_nodes, response.get_output()),
                                                      response)
        else:
            raise ScriptEngineResponseValidationError('Failed {0} synchronization. Output = {1}'
                                                      .format(self.APPLICATION, response.get_output()),
                                                      response)


class CmManagement(Management):
    APPLICATION = "Cm"
    SINGLE_SUPERVISION_CMD = "cmedit set {node_ids},CmNodeHeartbeatSupervision=1 active={active}"
    MULTIPLE_SUPERVISION_CMD = "cmedit set {node_ids} CmNodeHeartbeatSupervision active={active}"
    NETYPE_SUPERVISION_CMD = "cmedit set * CmNodeHeartbeatSupervision active={active} -ne={ne_type}"
    SUPERVISION_STATUS_CMD = "cmedit get {node_ids} CmFunction.syncStatus"
    GENERATION_COUNTER_STATUS_CMD = "cmedit get {node_ids} CppConnectivityInformation.generationCounter"
    SYNCHRONIZE_CMD = "cmedit action {node_ids} CmFunction sync"
    SYNCHRONIZE_CMD_WITH_NE_TYPE = "cmedit action * CmFunction sync --force --neType={ne_type}"
    SYNCHRONIZE_COLLECTION_CMD = "cmedit action {collections} CmFunction=1 sync"
    INSTANCE_VERIFICATION = r"{0} instance\(s\) updated"
    EXTRACT_SYNC_STATUS = r"(?<=syncStatus\s:\s)(\w+)"
    CHECK_GENERATION_COUNTER = r"generationCounter : 0"

    def __init__(self, *args, **kwargs):
        """
        CmManagement constructor

        """
        super(CmManagement, self).__init__(*args, **kwargs)

    @classmethod
    def check_generation_counter(cls, node_id, user):
        response = user.enm_execute(cls.GENERATION_COUNTER_STATUS_CMD.format(node_ids="NetworkElement={0}".format(node_id)))

        if any(cls.CHECK_GENERATION_COUNTER in line for line in response.get_output()):
            raise ScriptEngineResponseValidationError(
                'Generation counter zero on node "%s". Response was "%s"' % (
                    node_id, ', '.join(response.get_output())), response=response)


class FmManagement(Management):
    APPLICATION = "Fm"
    SINGLE_SUPERVISION_CMD = "cmedit set {node_ids},FmAlarmSupervision=1 active={active}"
    MULTIPLE_SUPERVISION_CMD = "cmedit set {node_ids} FmAlarmSupervision active={active}"
    NETYPE_SUPERVISION_CMD = "cmedit set * FmAlarmSupervision active={active} -ne={ne_type}"
    SUPERVISION_STATUS_CMD = "cmedit get {node_ids} FmFunction.currentServiceState"
    SYNCHRONIZE_CMD = "alarm sync {node_ids}"
    INSTANCE_VERIFICATION = r"{0} instance\(s\)"
    EXTRACT_SYNC_STATUS = r"(?<=currentServiceState\s:\s)(\w+)"

    def __init__(self, *args, **kwargs):
        """
        FmManagement constructor

        """
        super(FmManagement, self).__init__(*args, **kwargs)


class ShmManagement(Management):
    APPLICATION = "Shm"
    SINGLE_SUPERVISION_CMD = "cmedit set {node_ids},InventorySupervision=1 active={active}"
    MULTIPLE_SUPERVISION_CMD = "cmedit set {node_ids} InventorySupervision active={active}"
    NETYPE_SUPERVISION_CMD = "cmedit set * InventorySupervision active={active} -ne={ne_type}"
    SUPERVISION_STATUS_CMD = "cmedit get {node_ids} InventoryFunction.syncStatus"
    SYNCHRONIZE_CMD = "cmedit action {node_ids},SHMFunction=1,InventoryFunction=1 synchronize.(invType=ALL)"
    INSTANCE_VERIFICATION = r"{0} instance\(s\) updated"
    EXTRACT_SYNC_STATUS = r"(?<=syncStatus\s:\s)(\w+)"

    def __init__(self, *args, **kwargs):
        """
        ShmManagement constructor

        """
        super(ShmManagement, self).__init__(*args, **kwargs)


class PmManagement(Management):
    APPLICATION = "Pm"
    SINGLE_SUPERVISION_CMD = "cmedit set {node_ids},PmFunction=1 pmEnabled={active}"
    MULTIPLE_SUPERVISION_CMD = "cmedit set {node_ids} PmFunction pmEnabled={active}"
    NETYPE_SUPERVISION_CMD = "cmedit set * PmFunction pmEnabled={active} -ne={ne_type}"
    SUPERVISION_STATUS_CMD = "cmedit get {node_ids} PmFunction.pmEnabled"
    INSTANCE_VERIFICATION = r"{0} instance\(s\) updated"
    EXTRACT_SYNC_STATUS = r"(?<=pmEnabled\s:\s)(\w+)"

    def __init__(self, *args, **kwargs):
        """
        PmManagement constructor

        """
        super(PmManagement, self).__init__(*args, **kwargs)
