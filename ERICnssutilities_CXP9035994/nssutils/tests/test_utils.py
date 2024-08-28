#!/usr/bin/env python
import json
import random
import test_node_mgr

from nssutils.lib import enm_user_2
from nssutils.lib import cache, persistence, log, mutexer


def setup():
    """
    B{Does all pre-test cleanup to prepare for execution of next test case}

    @rtype: void
    """

    log.logger.debug("Clearing cache and persistence before each test case is run. Done in 'def setUp(self)'.")
    cache.clear()
    persistence.clear()


def tear_down():
    """
    B{Does all post-test cleanup to prepare for execution of next test case}

    @rtype: void
    """

    pass


def get_random_string(size, include_numbers=True):
    """
    B{Generates a random string of the specified size}

    @type size: int
    @param size: The length of the random string to be returned
    @type include_numbers: bool
    @param include_numbers: Toggles whether numbers are to be included in the pool of candidate characters for the random string

    @rtype: void
    """

    if include_numbers:
        characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz'
    else:
        characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

    temp_string = ''.join(random.choice(characters) for x in range(size))
    return ''.join(random.sample(temp_string, len(temp_string)))


def convert_string_to_json(string):
    """
    B{Converts a valid JSON string to a native Python primitive or collection}

    @type string: str
    @param string; JSON string to be converted

    @rtype: primitive || collection || bool
    """

    return json.loads(string)


def convert_json_to_string(json):
    """
    B{Converts a valid JSON string to a native Python primitive or collection}

    @type json: primitive || collection || bool
    @param json: JSON object to be converted to string

    @rtype: str
    """

    return json.dumps(json)


def get_pool(pool_type):
    """
    B{Returns the pool from persistence (if it exists)}

    @type pool_type: str
    @param pool_type: Type of pool to get

    @return: Pool object (singleton) || None
    """

    if pool_type == "acceptance":
        key = "acceptance-node-pool"

    return persistence.node_pool_db().get(key)


def init_pool(pool_type):
    """
    B{Checks to see if the specified pool already exists and instantiates it if not}

    @type pool_type: str
    @param pool_type: Type of pool to initialise

    @rtype: void
    """

    if get_pool(pool_type) is None:
        log.logger.debug("Instantiating new {0} test node pool...".format(pool_type))
        test_node_mgr.TestPool(pool_type=pool_type).persist()


def clear_pool(pool_type):
    """
    B{Removes the specified pool from persistence}

    @type pool_type: str
    @param pool_type: Type of pool to clear

    @rtype: void
    """

    log.logger.debug("Clearing {0} test node pool...".format(pool_type))

    pool = get_pool(pool_type)
    if pool is not None:
        pool.clear()


def clean_pool(pool_type):
    """
    B{Free nodes that weren't released during normal teardown}

    @type pool_type: str
    @param pool_type: Type of pool to clean

    @rtype: void
    """
    log.logger.debug("Cleaning {0} test node pool...".format(pool_type))
    pool = get_pool(pool_type)

    nodes = []
    methods = ['disable_cm_management', 'disable_fm_management', 'disable_pm_management', 'disable_shm_management',
               '_disable_supervision_delete_network_element', '_delete_network_element_tree']
    if pool is not None:
        for node in pool.nodes:
            skip = False
            if node.used:
                # Remove the node from ENM
                for method in methods:
                    remove(node, method)

                # Check for the NetworkElement
                try:
                    admin_user = enm_user_2.get_or_create_admin_user()
                    cli_command = "cmedit get {0} NetworkElement".format(node.node_id)
                    response = admin_user.enm_execute(cli_command)
                    if any("1 instance(s)" in line for line in response.get_output()):
                        skip = True
                except Exception as e:
                    log.logger.debug("Could not get the NetworkElement: {0}".format(str(e)))
                    skip = True
                if not skip:
                    nodes.append(node)

        if len(nodes) > 0:
            pool.return_nodes(nodes)


def remove(node, method):
    try:
        getattr(node, method)()
    except Exception as e:
        log.logger.debug("Method executed and raised exception message: {0}".format(str(e)))


# If commands with identical CM command key exist
# store the command key in the Command object and add to the dictionary
class CommandHolder(object):
    def __init__(self, key):
        self.key = key


def get_test_db_index():
    """
    B{Checks out an available DB index for a test process to use for the course of its testing}

    @rtype: int
    """

    # The first potential index is 35
    index_counter = 34
    index = None

    with mutexer.mutex("manage-test-db-indices", persisted=True):
        while index is None:
            index_counter += 1
            key = "test-db-index-{0}".format(index_counter)

            if not persistence.index_db().has_key(key):
                index = index_counter

                # NOTE: Indices are only checked out for three hours
                persistence.index_db().set(key, 1, 10800)

        log.logger.debug("Checked out test DB index {0}".format(index))
    return index


def return_test_db_index(index):
    """
    B{Checks out an available DB index for a test process to use for the course of its testing}

    @type index: int
    @param index: Index of the test DB to be cleared and returned to the pool

    @rtype: void
    """

    key = "test-db-index-{0}".format(index)

    with mutexer.mutex("manage-test-db-indices", persisted=True):
        persistence.index_db().remove(key)

        log.logger.debug("Checked in test DB index {0}".format(index))
