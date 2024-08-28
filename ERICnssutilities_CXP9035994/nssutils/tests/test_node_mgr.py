#!/usr/bin/env python
import os
import pkgutil
from contextlib import contextmanager

import unipath

from nssutils.lib import filesystem, log, mutexer, node_parse, persistence
from nssutils.lib.enm_node import (EPGNode, ERBSNode, MGWNode, PICONode, RBSNode, RNCNode, RadioNode, Router6672Node,
                                   SAPCNode, SGSNNode, VEPGNode)

NSSUTILS_PATH = unipath.Path(pkgutil.get_loader('nssutils').filename)


def persist_after(func):
    # A decorator function which will persist pool after running the calling function
    # For decorator pattern please read
    # http://simeonfranklin.com/blog/2012/jul/1/python-decorators-in-12-steps/

    def wrapper(pool, *args, **kwargs):
        # Invoke decorated function
        return_value = func(pool, *args, **kwargs)

        # Persist updated node pool
        pool.persist()

        # Return output from decorated function
        return return_value

    return wrapper


class TestNodeMixin(object):

    def __init__(self, *args, **kwargs):
        super(TestNodeMixin, self).__init__(*args, **kwargs)
        self.test_cls = None
        self.profiles = kwargs.pop('profiles', [])
        self.error_info = kwargs.pop('error_info', [])
        self.errored_by_applications = kwargs.pop('errored_by_applications', {})
        self.available_to_profiles = kwargs.pop('available_to_profiles', set())
        self._is_exclusive = kwargs.pop('_is_exclusive', False)

    def add_test(self, test_cls):
        self.test_cls = test_cls.__name__
        self._persist()

    def remove_test(self):
        self.test_cls = None
        self._persist()

    @property
    def used(self):
        return bool(self.test_cls)

    @property
    def is_available(self):
        return not self.used

    def is_available_for(self, _):
        return not self.used

    def _persist(self):
        persistence.node_pool_db().set(self.node_id, self, -1, log_values=False)


class TestERBSNode(TestNodeMixin, ERBSNode):
    pass


class TestSGSNNode(TestNodeMixin, SGSNNode):
    pass


class TestRadioNode(TestNodeMixin, RadioNode):
    pass


class TestMGWNode(TestNodeMixin, MGWNode):
    pass


class TestSpitFireNode(TestNodeMixin, Router6672Node):
    pass


class TestPICOLoadNode(TestNodeMixin, PICONode):
    pass


class TestEPGLoadNode(TestNodeMixin, EPGNode):
    pass


class TestVEPGLoadNode(TestNodeMixin, VEPGNode):
    pass


class TestRNCLoadNode(TestNodeMixin, RNCNode):
    pass


class TestSAPCLoadNode(TestNodeMixin, SAPCNode):
    pass


class TestRBSLoadNode(TestNodeMixin, RBSNode):
    pass


NODE_CLASS_MAP = {
    'ERBS': TestERBSNode,
    'SGSN': TestSGSNNode,
    'MSRBS_V2': TestRadioNode,
    'RadioNode': TestRadioNode,
    'MGW': TestMGWNode,
    'SpitFire': TestSpitFireNode,
    'MSRBS_V1': TestPICOLoadNode,
    'EPG': TestEPGLoadNode,
    'EPG-SSR': TestEPGLoadNode,
    'VEPG': TestVEPGLoadNode,
    'RNC': TestRNCLoadNode,
    'SAPC': TestSAPCLoadNode,
    'RBS': TestRBSLoadNode

}


class Pool(object):

    def __init__(self):
        self._nodes = {key: [] for key in NODE_CLASS_MAP.keys()}
        self.key = self.PERSISTENCE_KEY

    @property
    def nodes(self):
        nodes = []
        for node_type in self._nodes.keys():
            nodes = nodes + self.db.get_keys([node for node in self._nodes[node_type] if self.db.has_key(node)])
        return nodes

    @property
    def node_dict(self):
        """
        :return: dictionary of nodes
        :rtype: dict
        """
        node_dict = {}
        for node_type in self._nodes.keys():
            node_dict[node_type] = {node: self.db.get(node) for node in self._nodes[node_type] if self.db.has_key(node)}
        return node_dict

    @staticmethod
    def _load_nodes_from_file(file_path, node_map=None):
        """
        Reads node data from the specified file and creates load_node.Node subclass instances for the nodes

        :param file_path: absolute path of the node data file to be read
        :type file_path: str
        :param node_map: keys are the different types of node names and values are the instances of that node
        :type node_map: dict
        :return: list of nodes
        :rtype: list
        """

        node_map = node_map or NODE_CLASS_MAP
        valid_nodes = []
        for node_dict in node_parse.get_node_data(file_path):
            primary_type = node_dict["primary_type"]
            if primary_type in node_map:
                valid_nodes.append(node_map[primary_type](**node_dict))
            else:
                log.logger.debug(
                    "The NODE_CLASS_MAP in load_node does not have a key for the primary_type: {0}".format(
                        primary_type))

        return valid_nodes

    @persist_after
    def add(self, path, start=None, end=None, node_map=None):
        """
        Add nodes given the path to csv and start and end ranges

        :param path: path to csv file
        :type path: str
        :param start: start range
        :type start: int
        :param end: end range
        :type end: int
        :param node_map: dictionary of node name and node
        :type node_map: dict

        :return: Tuple where first element is list of nodes added, second element is list of nodes not added
        :rtype: tuple

        """
        node_map = node_map or NODE_CLASS_MAP
        nodes_to_check = self._load_nodes_from_file(path, node_map=node_map)
        missing_nodes = {"ALREADY_IN_POOL": [], "NOT_ADDED": [], "NOT_SYNCED": [], "MISSING_PRIMARY_TYPE": []}
        added = []
        if start and end:
            nodes_to_check = nodes_to_check[start - 1: end]

        for node in nodes_to_check:
            if not self._nodes.has_key(node.primary_type):
                log.logger.debug("The primary type {0} does not exist in the nodes dictionary for node_pool_mgr".format(
                    node.primary_type))
                missing_nodes["MISSING_PRIMARY_TYPE"].append(node.node_id)
                continue
            if node.node_id in self._nodes[node.primary_type]:
                missing_nodes["ALREADY_IN_POOL"].append(node.node_id)
            else:
                node._persist()
                self._nodes[node.primary_type].append(node.node_id)
                log.logger.debug("Successfully ADDED node: '{0}' to the workload pool and persistence."
                                 .format(node.node_id))
                added.append(node.node_id)

        return added, missing_nodes

    def get_available_nodes(self, item):
        """
        Gets a list of available nodes the specified profile could be assigned to

        :param item: the item to be checked if the nodes can be assigned to it
        :type item: object
        :return: list of nodes
        :rtype: list
        :raises ValueError: raised if num_nodes is set to -1 twice and total_nodes is specified
        :raises NoNodesAvailable: raised if there are no nodes available for the profile
        """

        available_nodes = []
        if hasattr(item, 'NUM_NODES'):
            for key, value in item.NUM_NODES.iteritems():
                available_nodes.extend(self.get_random_available_nodes(item, node_type=key, num_nodes=value))
        return available_nodes

    def get_random_available_nodes(self, item, num_nodes=None, node_type=None):
        """
        Get random available nodes for the item

        :param item: item to get nodes for
        :type item: object
        :param num_nodes: number of nodes required
        :type num_nodes: int
        :param node_type: type of nodes required
        :type node_type: str
        :return: list of nodes
        :rtype: list
        :raises ValueError: raised if no nodes found in the pool when node type is None
        """
        available_nodes = self.node_dict[node_type].values() if node_type else self.nodes
        if not available_nodes:
            if node_type is None:
                raise ValueError('No nodes found in the pool for {0}'.format(str(item)))
        return available_nodes[:num_nodes]

    def clear(self):
        """
        Removes the node pool from persistence
        """
        self.db.remove(self.key)


class TestPool(Pool):

    PERSISTENCE_KEY = 'acceptance-node-pool'

    def __init__(self, pool_type="acceptance"):
        super(TestPool, self).__init__()
        self.pool_type = pool_type
        node_file = '/var/nssutils/acceptance_list'
        if pool_type == "acceptance":
            if not filesystem.does_file_exist(node_file):
                raise ValueError("Node file: {0} not found, provide supply parsed file of created nodes @ {0}."
                                 .format(node_file))
            node_file_path = os.path.join('/var/nssutils/acceptance_list')
            self.key = "acceptance-node-pool"
        else:
            raise ValueError("Unknown pool type {0} is not supported".format(pool_type))

        log.logger.info("Populating node pool with nodes from file {0}".format(node_file_path))
        self.add(node_file_path, node_map=NODE_CLASS_MAP)

    @property
    def db(self):
        return persistence.node_pool_db()

    def _node_is_used_by(self, node, _):
        return node.test_cls is not None

    def persist(self):
        with self.mutex():
            self.db.set(self.key, self, -1)

    def allocate_nodes(self, test_cls):
        """
        Given the test_cls, adds the nodes to the test_cls, raising error if it can't

        :param test_cls: test_cls to which nodes are to be allocated
        :type test_cls: object

        :return: List of available test nodes
        :rtype: list
        """
        with self.mutex():
            available_nodes = self.get_available_nodes(test_cls)
            for node in available_nodes:
                node.add_test(test_cls)
        return available_nodes

    def return_nodes(self, nodes):
        with self.mutex():
            for node in nodes:
                node.remove_test()

    @contextmanager
    def mutex(self):
        with mutexer.mutex('test-node-pool-operation', persisted=True):
            yield
