import signal
import re

from contextlib import contextmanager

import nose

from nssutils.lib import netsim_executor
from nssutils.tests import test_utils
from nssutils.lib import log, exception, init, mutexer, persistence, timestamp, arguments
from nssutils.lib import enm_user_2 as enm_user
from nssutils.lib.enm_node_management import (FmManagement, CmManagement, PmManagement)


class TestFixture(object):
    def __init__(self, cls):
        """
        B{Constructor for class TestFixture}

        @type cls: unittest2.Testcase
        @param cls: The test class the fixtures are being created for

        @rtype: void
        """

        self.test_class = cls
        self.admin_user = None

        # Nodes
        self.num_nodes = sum(val for val in cls.NUM_NODES.values() if val > 0) if hasattr(cls, 'NUM_NODES') else 0
        self.nodes = []

        # Users
        self.num_users = 0
        self.user_roles = []
        self.users = []

        # Setup/Teardown
        self.stop_on_setup_fail = True
        self.raise_exception_on_teardown_fail = False
        self.teardown_result = True

        # Setups completed
        self.node_setup_done = False
        self.user_setup_done = False

    @property
    def test_class_name(self):
        return self.test_class.__name__

    @property
    def identifier(self):
        return '_'.join([self.test_class_name, self.get_timestamp_str()])

    @staticmethod
    def get_timestamp_str():
        now = timestamp.get_current_time()
        return "{0}-{1}-{2}".format(now.hour, now.minute, now.second)

    def setup(self):
        """
        B{Sets up all fixtures required before the test method is invoked}

        @rtype: void
        """
        if not hasattr(nose, "allure"):
            signal.signal(signal.SIGINT, lambda signum, frame: init.signal_handler(signum, frame, self.teardown))
        else:
            signal.signal(signal.SIGTERM, lambda signum, frame: init.signal_handler(signum, frame, self.teardown))

        # Establish administrator session before starting test executions
        self.admin_user = enm_user.get_or_create_admin_user()

        try:
            if self.num_users > 0 and len(self.user_roles) > 0 and not self.user_setup_done:
                self._setup_users()
        except:
            exception.process_exception("Exception raised while setting up users in test fixture setup")
            if self.stop_on_setup_fail:
                raise
        finally:
            self.user_setup_done = True

        try:
            if self.num_nodes and not self.node_setup_done:
                self._allocate_nodes()
        except:
            exception.process_exception("Exception raised while setting up nodes in test fixture setup")
            if self.stop_on_setup_fail:
                raise
        finally:
            self.node_setup_done = True

    def teardown(self):
        """
        B{Tears down all fixtures after the test method has been executed}

        @rtype: boolean
        @return: True if the teardown was successful
        """

        try:
            if self.num_nodes:
                self._deallocate_nodes()
        except:
            self.teardown_result = False
            exception.process_exception("Exception raised while tearing down nodes in test fixture teardown")

        try:
            if self.num_users > 0:
                self._teardown_users()
        except:
            self.teardown_result = False
            exception.process_exception("Exception raised while tearing down users in test fixture teardown")

        if not self.raise_exception_on_teardown_fail:
            self.teardown_result = True

        return self.teardown_result

    def _setup_users(self):
        """
        B{Sets up all users required for test. If there is a fail a RuntimeError is raised}

        @rtype: void
        """
        import string
        for i in xrange(self.num_users):
            random_prefix = arguments.get_random_string(3, exclude=string.digits)
            user = enm_user.User("user-{0}-{1}".format(random_prefix, self.get_timestamp_str()),
                                 "Passw0rd", roles=self.user_roles, keep_password=True, email="{0}{1}@ericsson.com"
                                 .format(self.identifier.split('_')[0], i))
            try:
                user.create()
            except Exception as e:
                log.logger.warning("ERROR: {0}".format(str(e)))
            else:
                self.users.append(user)

        if len(self.users) != self.num_users:
            raise RuntimeError("{0} users failed during creation.".format(self.num_users - len(self.users)))

    def _teardown_users(self):
        """
        B{Tears down all of the users used by the test}

        @raise RunTimeError: raises an exception if users fail to be deleted
        @rtype: void
        """

        users_not_deleted = []

        for user in self.users:
            try:
                user.delete()
            except Exception as e:
                log.logger.debug("Failed to delete user: {0}. Exception: {1}".format(user.username, str(e)))
                users_not_deleted.append(user.username)

        self.users = []
        if users_not_deleted:
            raise RuntimeError("Could not delete all users during teardown."
                               " Users remaining on the system are: {0}".format(users_not_deleted))

    def _allocate_nodes(self):
        """
        B{Allocate nodes to acceptance test}

        @rtype: void
        """

        if not test_utils.get_pool(self.test_type):
            test_utils.init_pool(self.test_type)

        self.nodes = test_utils.get_pool(self.test_type).allocate_nodes(self.test_class)

    def _deallocate_nodes(self):
        """
        B{Deallocate nodes from acceptance test}

        @raise RunTimeError: raises an exception if nodes fail to be deleted
        @rtype: void
        """
        nodes = self.nodes

        nodes_not_started = netsim_executor.check_nodes_started(nodes)
        nodes_not_created = self.verify_nodes_exist(self.admin_user, nodes)
        nodes_not_synced = self.verify_nodes_are_synced(self.admin_user, nodes)

        unavailable_nodes = set(nodes_not_started).union(set(nodes_not_synced).union(nodes_not_created))

        if unavailable_nodes:
            log.logger.warn(
                "The following nodes will not be returned to acceptance pool: {0}".format
                (",".join([node.node_id for node in unavailable_nodes])))

        available_nodes = set(nodes) - set(unavailable_nodes)

        if available_nodes:
            log.logger.debug("Adding the following nodes back to the acceptance pool: {0}".format
                             (",".join([node.node_id for node in available_nodes])))
            test_utils.get_pool(self.test_type).return_nodes(available_nodes)
        else:
            log.logger.debug("No nodes were added back to the pool.")

    @staticmethod
    def verify_nodes_exist(user, nodes, get_all=False):
        """
        B{verifies that the node exists on ENM}
        @type user: User
        @param user: User object to carry out operations with
        @type nodes: list of `enm_node.Node` instances
        @param nodes: The node need of the test case that calls test_fixture
        @rtype: list of nodes not on ENM
        """
        found_nodes = []
        response = user.enm_execute("cmedit get {0} NetworkElement".format
                                    ("*" if get_all else ";".join([node.node_id for node in nodes])))

        for node in nodes:
            match = re.search(node.node_id, ",".join(response.get_output()))
            if match:
                found_nodes.append(node)

        return set(nodes) - set(found_nodes)

    @staticmethod
    def verify_nodes_are_synced(user, nodes):
        """
        B{verifies that the node is synced CM,FM,PM}
        @type user: User
        @param user: User object to carry out operations with
        @type nodes: list of `enm_node.Node` instances
        @param nodes: The node need of the test case that calls test_fixture
        @rtype: list of nodes not synced in either CM, FM, PM
        """
        found_nodes = []
        cm_management = CmManagement.get_status(user)
        fm_management = FmManagement.get_status(user)
        pm_management = PmManagement.get_status(user)
        for node in nodes:
            if all([node.node_id in cm_management, node.node_id in fm_management, node.node_id in pm_management]):
                if all([cm_management[node.node_id] == "SYNCHRONIZED", fm_management[node.node_id] == "IN_SERVICE",
                        pm_management[node.node_id] == "true"]):
                    found_nodes.append(node)
                else:
                    log.logger.debug("Sync Status {0}: CM={1}, FM={2}, PM={3}".format(node.node_id,
                                                                                      cm_management[node.node_id].lower(),
                                                                                      fm_management[node.node_id].lower(),
                                                                                      pm_management[node.node_id].lower()))
            else:
                log.logger.debug("Node is not available on the system: {0}".format(node.node_id))

        return set(nodes) - set(found_nodes)

    @contextmanager
    def mutex(self):
        test_db = persistence.node_pool_db()
        with mutexer.mutex('acceptance-test-fixture-delete-node', persisted=True, db=test_db):
            yield


class AcceptanceTestFixture(TestFixture):
    def __init__(self, *args, **kwargs):
        self.test_type = "acceptance"
        super(AcceptanceTestFixture, self).__init__(*args, **kwargs)
