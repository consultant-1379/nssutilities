import random
import time
import datetime
from abc import ABCMeta, abstractmethod

from enum import Enum

import config
import log
import timestamp
import thread_queue
import mutexer
import node_parse
import enm_node
import shell


def operation(input_file, operation, range_start=None, range_end=None, verbose=False, nodes=None):
    """
    Conducts an operation for node_populator.

    :type input_file: str
    :param input_file: The name of the parsed csv file to use in the operation
    :type operation: str
    :param operation: The operation, whether it's create, manage etc.
    :type range_start: int
    :param range_start: The row at which to start reading nodes from the parsed file
    :type range_end : int
    :param range_end: The row at which to end reading nodes from the parsed file
    :type verbose: bool
    :param verbose: Flag controlling whether additional information is printed to console during execution
    :type nodes: object
    :param nodes: The node objects created from topology_export_file to use in the operation

    :rtype: Operation
    :returns: The Operation object.
    """

    return OperationName.get_operation(operation)(input_file=input_file, range_start=range_start, range_end=range_end, verbose=verbose, nodes=nodes)


class Operation(object):
    def __init__(self, input_file, range_start=None, range_end=None, verbose=False, nodes=None):
        """
        Sets up an operation for node_populator

        :type input_file: str
        :param input_file: The name of the parsed csv file to use in the operation
        :type range_start: int
        :param range_start: The row at which to start reading nodes from the parsed file
        :type range_end : int
        :type verbose: bool
        :param verbose: Flag controlling whether additional information is printed to console during execution
        :param range_end: The row at which to end reading nodes from the parsed file
        :type nodes : objects
        :param nodes: The nodes to use in the operation
        """
        if nodes is None:
            self.nodes = self.get_nodes(input_file, range_start=range_start, range_end=range_end)
        else:
            self.nodes = nodes

        self.num_workers = len(self.nodes) if len(self.nodes) < 10 else 10
        self.verbose = verbose
        self.all_failed_assertions = list()
        self.input_file = input_file

    def get_nodes(self, input_file, range_start, range_end):
        """
        Gets a list of the nodes that will serve as input to the operation

        :type input_file: str
        :param input_file: Absolute path to the node data file to be used to populate the commands
        :type range_start: int
        :param range_start: The lower bound of the range of nodes to target in the input_file
        :type range_end: int
        :param range_end: The upper bound of the range of nodes to target in the input_file

        :rtype: list
        :returns: A list of enm_node.Node objects
        :raises RuntimeError: raises if length of nodes is 0
        """
        # nodes is a list of node objects
        nodes = node_parse.read_csv(input_file, range_start, range_end)
        if len(nodes) == 0:
            raise RuntimeError("\nThe csv file {0} does not contain any valid nodes".format(input_file))
        # Shuffle the work list so that the load is randomly spread
        random.shuffle(nodes)
        return nodes

    def subnetwork(self, operation):
        """
        Creates/ Deletes a Subnetwork for a node

        :type operation: str
        :param operation: Create or delete a Subnetwork

        :rtype: list
        :returns: Returns a list containing the results of the Subnetwork operation.
        """
        all_subnetworks = []
        results = []
        succ = True
        error_msg = ""

        # Get unique SubNetworks
        for node in self.nodes:
            # Set up the SubNetwork list
            node_subnetwork = node.subnetwork
            if node_subnetwork:
                subnet_list = node_subnetwork.split("|") if "|" in node.subnetwork else node_subnetwork.split(",")

                for i in xrange(0, len(subnet_list)):
                    sub = ",".join(subnet_list[0:i + 1])
                    if sub not in all_subnetworks:
                        all_subnetworks.append(sub)

        # The child Subnetworks need to be cleared before the parents.
        subnets = all_subnetworks if operation == "create" else reversed(all_subnetworks)
        for subnet in subnets:
            sub = enm_node.Subnetwork(subnet)

            start = timestamp.get_current_time()
            try:
                if operation == "create":
                    if not sub.exists():
                        sub.create()
                elif operation == "delete":
                    if sub.has_no_child_mos():
                        sub.delete()
            except Exception as e:
                error_msg = str(e)
                log.logger.debug("ERROR: {0}".format(error_msg))
                succ = False
            finish = timestamp.get_current_time() - start

            status = "PASS" if succ else "FAIL"
            header = "SubNetwork ID  {0}".format(sub.id)
            body = [["{0} SubNetwork MO".format(operation.upper()), status, error_msg]]
            footer = self.colour("FINAL RESULT FOR {0} OPERATION ON {1} [{2}] ({3})\n".format(operation.upper(), sub.id, status, timestamp.get_string_elapsed_time(finish)))

            results.append([header, body, footer])
        return results

    def operate(self, enm_node, operation_name):
        """
        Takes an enm_node and performs the required operation on it, we return the node id if it failed.

        :type enm_node: enm_node.Node
        :param enm_node: The node object
        :type operation_name: str
        :param operation_name: The operation to perform

        :rtype: list
        :returns: A list of enm_node.Node objects
        """

        start = timestamp.get_current_time()
        op_set_class = OperationName.get_operation_set(operation_name)

        kwargs = {"primary_type": enm_node.primary_type} if operation_name.lower() in [str(OperationName.CREATE), str(OperationName.MANAGE), str(OperationName.POPULATE)] else {}
        if operation_name.lower() == str(OperationName.CREATE):
            kwargs["has_mecontext"] = "MeContext" in enm_node.oss_prefix
        op_set = op_set_class(**kwargs)
        all_task_results = op_set.execute(enm_node)

        finish = timestamp.get_current_time() - start
        overall_res = self.operation_result(all_task_results)
        if not overall_res:
            self.all_failed_assertions.append(enm_node)

        node = None
        with mutexer.mutex("operation-result"):
            if overall_res == "FAIL":
                node = enm_node.node_id
            header = op_set.header.format(node_id=enm_node.node_id, node_ip=enm_node.node_ip, model_identity=enm_node.model_identity, mim_version=enm_node.mim_version, security_state=enm_node.security_state)
            footer = op_set.footer.format(operation=operation_name.upper(), node_id=enm_node.node_id, op_res=overall_res, timestamp=timestamp.get_string_elapsed_time(finish))
            updated_footer = self.colour(footer)
            # Print the operation result
            self.print_result(header, all_task_results, updated_footer)
        return node

    def print_result(self, header, body, footer):
        """
        Prints the result of a single operation
        """
        output = []
        header_text = self.colour(header, type="header")
        output.append(header_text)
        for entry in body:
            result_text = self.colour(entry[1])
            output.append("    {result} {action:55}".format(result=result_text, action=self.colour(entry[0], "description")))
            if entry[1] == "FAIL":
                output.append("      {error:55}".format(error=log.red_text(entry[2])))

        output.append(footer)

        for line in output:
            log.logger.info(line)

    def operation_result(self, results):
        """
        Determines the success/failure of an operation

        :return: a text whether is a pass, fail or unattempted
        :rtype: str
        """
        passes = 0
        unattempted = 0

        for result in results:
            if result[1] == "PASS" or result[1] == "WARN":
                passes += 1
            elif result[1] == "UNATTEMPTED":
                unattempted += 1

        if unattempted == len(results):
            return "UNATTEMPTED"

        if passes == len(results):
            return "PASS"
        else:
            return "FAIL"

    def colour(self, msg, type=None):  # pylint: disable=redefined-builtin
        """
        Colours a message depending what's in the message, or it's type

        :return: result_text with result
        :rtype: str
        """
        if "PASS" in msg:
            result_text = log.green_text(msg)
        elif "UNATTEMPTED" in msg or "WARN" in msg:
            result_text = log.yellow_text(msg)
        elif "FAIL" in msg:
            result_text = log.red_text(msg)
        elif type == "header":
            result_text = log.purple_text(msg)
        elif type == "description":
            result_text = log.blue_text(msg)
        else:
            result_text = msg
        return result_text

    def summary(self, tqs, elapsed_time, operation):
        """
        Prints out the summary of an operation

        :return: if nodes length is less than 0 returns False else True
        :rtype: bool
        """
        failed_nodes = []
        result = True
        # hoover up thread queue
        work_items = 0
        for tq in tqs:
            work_items += len(tq.work_items)
            for entry in tq.work_entries:
                if entry.result:
                    failed_nodes.append(entry.result)
                elif self.all_failed_assertions and entry.arg_list[0].node_name in self.all_failed_assertions:
                    failed_nodes.append(entry.arg_list[0].node_name)

        successful_nodes = work_items - len(failed_nodes)

        log.logger.info("")
        log.logger.info(log.purple_text("NODE POPULATOR SUMMARY"))
        log.logger.info(log.purple_text("----------------------"))
        log.logger.info(log.cyan_text("  NODES {0}: {1}/{2}".format(operation, successful_nodes, work_items)))
        log.logger.info(log.white_text("  EXECUTION TIME: {0}\n".format(elapsed_time)))

        if len(failed_nodes) > 0:
            log.logger.info(log.red_text("NODES THAT FAILED OR ERRORED"))
            log.logger.info(log.red_text("----------------------------"))
            log.logger.info(log.red_text(",".join(failed_nodes)))

            # If we failed
            node_parse.reparse_nodes_file(self.input_file, failed_nodes)

            result = False
        return result


class CreateOperation(Operation):
    def __init__(self, input_file, range_start=None, range_end=None, verbose=False, nodes=None):
        super(CreateOperation, self).__init__(input_file, range_start=range_start, range_end=range_end, verbose=verbose, nodes=nodes)

    def operation(self):
        """
        Performs a create operation

        :return: result from summary function in Operation class
        :rtype: bool
        """
        # Start the timer
        start = timestamp.get_current_time()
        # Create the subnetworks
        results = self.subnetwork("create")
        if len(results) > 0:
            for result in results:
                header, body, footer = result
                super(CreateOperation, self).print_result(header, body, footer)

        tq = _create_thread_queues(self.nodes, self.num_workers, func_ref=lambda node: self.operate(node, "create"))
        # Stop the clock
        elapsed_time = timestamp.get_string_elapsed_time(timestamp.get_current_time() - start)

        # Print out the summary
        return super(CreateOperation, self).summary(tq, elapsed_time, "CREATED")


class DeleteOperation(Operation):
    def __init__(self, input_file, range_start=None, range_end=None, verbose=False, nodes=None):
        super(DeleteOperation, self).__init__(input_file, range_start=range_start, range_end=range_end, verbose=verbose, nodes=nodes)

    def operation(self):
        """
        Performs a delete operation

        :return: result from summary function in Operation class
        :rtype: bool
        """

        # Start the timer
        start = timestamp.get_current_time()

        # Delete the nodes
        tq = thread_queue.ThreadQueue(self.nodes, self.num_workers, func_ref=lambda node: self.operate(node, "delete"))
        tq.execute()

        # Delete the subnetworks
        results = self.subnetwork("delete")
        if len(results) > 0:
            for result in results:
                header, body, footer = result
                super(DeleteOperation, self).print_result(header, body, footer)

        # Stop the clock
        elapsed_time = timestamp.get_string_elapsed_time(timestamp.get_current_time() - start)

        # Print out the result
        return super(DeleteOperation, self).summary([tq], elapsed_time, "DELETED")


class ManageOperation(Operation):
    def __init__(self, input_file, range_start=None, range_end=None, verbose=False, nodes=None):
        super(ManageOperation, self).__init__(input_file, range_start=range_start, range_end=range_end, verbose=verbose, nodes=nodes)

    def operation(self):
        """
        Performs a manage operation

        :return: result from summary function in Operation class
        :rtype: bool
        """

        # Start the timer
        start = timestamp.get_current_time()

        # Delete the nodes
        tq = thread_queue.ThreadQueue(self.nodes, self.num_workers, func_ref=lambda node: self.operate(node, "manage"))
        tq.execute()

        # Stop the clock
        elapsed_time = timestamp.get_string_elapsed_time(timestamp.get_current_time() - start)

        # Print out the result
        return super(ManageOperation, self).summary([tq], elapsed_time, "MANAGED")


class UnmanageOperation(Operation):
    def __init__(self, input_file, range_start=None, range_end=None, verbose=False, nodes=None):
        super(UnmanageOperation, self).__init__(input_file, range_start=range_start, range_end=range_end, verbose=verbose, nodes=nodes)

    def operation(self):
        """
        Performs an unmanage operation

        :return: result from summary function in Operation class
        :rtype: bool
        """

        # Start the timer
        start = timestamp.get_current_time()

        # Delete the nodes
        tq = thread_queue.ThreadQueue(self.nodes, self.num_workers, func_ref=lambda node: self.operate(node, "unmanage"))
        tq.execute()

        # Stop the clock
        elapsed_time = timestamp.get_string_elapsed_time(timestamp.get_current_time() - start)

        # Print out the result
        return super(UnmanageOperation, self).summary([tq], elapsed_time, "UNMANAGED")


class PopulateOperation(Operation):
    def __init__(self, input_file, range_start=None, range_end=None, verbose=False, nodes=None):
        super(PopulateOperation, self).__init__(input_file, range_start=range_start, range_end=range_end, verbose=verbose, nodes=nodes)

    def operation(self):
        """
        Performs a populate operation

        :return: result from summary function in Operation class
        :rtype: bool
        """

        # Start the timer
        start = timestamp.get_current_time()

        results = self.subnetwork("create")
        if len(results) > 0:
            for result in results:
                header, body, footer = result
                super(PopulateOperation, self).print_result(header, body, footer)

        tq = _create_thread_queues(self.nodes, self.num_workers, func_ref=lambda node: self.operate(node, "populate"))

        # Stop the clock
        elapsed_time = timestamp.get_string_elapsed_time(timestamp.get_current_time() - start)

        # Print out the result
        return super(PopulateOperation, self).summary(tq, elapsed_time, "POPULATED")


class SyncOperation(Operation):
    def __init__(self, input_file, range_start=None, range_end=None, verbose=False, nodes=None):
        super(SyncOperation, self).__init__(input_file, range_start=range_start, range_end=range_end, verbose=verbose, nodes=nodes)

    def operation(self):
        """
        Performs a sync operation

        :return: result from summary function in Operation class
        :rtype: bool
        """

        # Start the timer
        start = timestamp.get_current_time()

        # Delete the nodes
        tq = thread_queue.ThreadQueue(self.nodes, self.num_workers, func_ref=lambda node: self.operate(node, "sync"))
        tq.execute()

        # Stop the clock
        elapsed_time = timestamp.get_string_elapsed_time(timestamp.get_current_time() - start)

        # Print out the result
        return super(SyncOperation, self).summary([tq], elapsed_time, "SYNCED")


class SetItem(object):
    def __init__(self, method, description, monitor_method=False, monitor_args=None):
        """
        Creates an element of a OperationSet defining the information required to run one "enm_node.Node' method

        :param method: The method name of a method on an enm_node.Node object to run
        :type method: str
        :param description: The description to use when reporting on the success / failure of this method
        :type description: str
        :param monitor_method: Specifies if this is a monitored method, which will run the method a number of times
        until a positive response is received or a timeout period expires
        :type monitor_method: bool
        :param monitor_args: Method arguments required for a monitored method
        :type monitor_args: object
        """

        self.method = method
        self.description = description
        self.monitor_method = monitor_method
        self.monitor_args = monitor_args if monitor_args else {}
        self.result = "UNATTEMPTED"
        self.error = None

        self.pass_status = "PASS"
        self.fail_status = "FAIL"

        self.lock_functions = [enm_node.Node.create_mecontext.__name__,
                               enm_node.Node._disable_supervision_delete_network_element.__name__,
                               enm_node.Node.create_networkelement.__name__]

    def add_result(self, result, error=None):
        """
        Add the result of the operation

        :param result: True / False
        :type result: bool
        :param error: Error message (if any) associated with the result
        :type error: str
        """

        self.result = self.pass_status if result else self.fail_status
        self.error = error

    def execute(self, enm_node, monitor_time, monitor_interval):
        """
        Executes the defined method on the enm_node.Node object provided

        :param enm_node: An enm_node.Node object to call the specified method on
        :type enm_node: enm_node.Node
        :param monitor_time: The maximum time to wait for a positive response from the called method
        :type monitor_time: int
        :param monitor_interval: The number of seconds to sleep inbetween each time the method is called during the
        timeout period
        :type monitor_interval: int
        :return: A list containing the method's name, the result and any associated error
        :rtype: list
        """

        if self.monitor_method:
            self._run_monitored_command(enm_node, monitor_time, monitor_interval)
        else:
            result, error = self._execute_method(node=enm_node)
            self.add_result(result, error)

        return [self.description, self.result, self.error]

    def _run_monitored_command(self, enm_node, monitor_time, monitor_interval):
        """
        Runs a monitored method on the enm_node.Node object provided for a maximum period of time or until a positive
        response is received

        :param enm_node:  An enm_node.Node object to call the specified method on
        :type enm_node: enm_node.Node
        :param monitor_time: The maximum time to wait for a positive response from the called method
        :type monitor_time: int
        :param monitor_interval: The number of seconds to sleep inbetween each time the method is called during the
        timeout period
        :type monitor_interval: int
        """

        start_time = timestamp.get_current_time()
        log.logger.debug("Running a monitoring command")
        wait_time = datetime.timedelta(seconds=monitor_time)
        loop_time = timestamp.get_current_time() - start_time
        while loop_time < wait_time:
            result = self._execute_method(enm_node, self.monitor_args)
            if result[0]:
                self.add_result(result)
                break
            # Sleep a bit before we try again
            time.sleep(monitor_interval)
            loop_time = timestamp.get_current_time() - start_time
            if not result[0] and loop_time >= wait_time:
                self.add_result(False, "Monitored command ({method}({method_args})) timed out before returning a "
                                       "positive result.".format(method=self.method, method_args=self.monitor_args))

    def _execute_method(self, node, kwargs=None):
        """
        Executes a specified method on a enm_node.Node object

        :param node: The enm_node.Node object to run the method on
        :type node: enm_node.Node
        :param kwargs: The keyword arguments to pass to the method
        :type kwargs: dict
        :return: The boolean result from running the method and any associated error
        :rtype: bool
        :raises Exception: raises when exception is caught
        """

        result = True
        kwargs = {} if not kwargs else kwargs
        error = None

        try:
            # MeContext deletes must be serialized due to locking issues in Versant
            if self.method.__name__ in self.lock_functions and not is_dps_provider_neo4j():
                mutexer.acquire_mutex("mecontext_lock")
            getattr(node, self.method.__name__)(**kwargs)
        except Exception as e:
            error = str(e)
            log.logger.debug("ERROR: {0}".format(error))
            result = False
        finally:
            if self.method.__name__ in self.lock_functions and not is_dps_provider_neo4j():
                mutexer.release_mutex("mecontext_lock")

        return result, error


class VerifySetItem(SetItem):
    def __init__(self, method, description, verify_task, monitor_method=False, monitor_args=None):
        """
        Creates an element of a OperationSet defining the information required to run one "enm_node.Node' method, which
        also defines another SetItem object to run as verification of this methods output.

        :param method: The method name of a method on an enm_node.Node object to run
        :type method: str
        :param description: The description to use when reporting on the success / failure of this method
        :type description: str
        :param verify_task: The SetItem method to execute to verify the success of running the method defined within
        this SetItem
        :type verify_task: set
        :param monitor_method: Specifies if this is a monitored method, which will run the method a number of times
        until a positive response is received or a timeout period expires
        :type monitor_method: bool
        :param monitor_args: Method arguments required for a monitored method
        :type monitor_args: object
        """

        super(VerifySetItem, self).__init__(method, description, monitor_method=monitor_method, monitor_args=monitor_args)
        self.verify_item = verify_task


class OperationSet(object):
    __metaclass__ = ABCMeta

    monitor_time = 0

    def __init__(self):
        """
        Abstract base class to define a set of method items to call on an enm_node.Node object and the order in which
        they should be called
        """

        self.header = "Node ID {node_id} ({node_ip}) [Model Identity {model_identity}; MIM version {mim_version}; security state {security_state}]"
        self.footer = "FINAL RESULT FOR {operation} OPERATION on {node_id}: [{op_res}] ({timestamp})\n"

        self.monitor_time = 180
        self.monitor_interval = 3

        self._add_set_items()

    def execute(self, enm_node):
        """
        Executes the defined method items in a defined order on an enm_node.Node object

        :param enm_node: The enm_node.Node object to call the methods on
        :type enm_node: enm_node.Node
        :return: list of results
        :rtype: list
        """

        results = []

        for method_group in self.methods:
            for method_item in method_group:
                results.append(method_item.execute(enm_node, self.monitor_time, self.monitor_interval))

            # run the validation tasks
            for method_item in method_group:
                if hasattr(method_item, "verify_item") and method_item.result == method_item.pass_status:
                    results.append(method_item.verify_item.execute(enm_node, self.monitor_time, self.monitor_interval))

        return results

    @abstractmethod
    def _add_set_items(self):
        """
        Abstract method to add the methods required for the set

        """

        pass


class PopulationSet(OperationSet):
    def __init__(self, primary_type):
        """
        Defines the set of methods to run on an enm_node.Node object to populate (create & manage) a enm_node.Node
        object on ENM

        :param primary_type: The node's primary type
        :type primary_type: str
        """

        self.primary_type = primary_type
        super(PopulationSet, self).__init__()

    def _add_set_items(self):
        """
        Adds the specific set of methods to run on a enm_node.Node object to populate the node on ENM
        """

        methods = CreationSet(self.primary_type).methods
        methods.extend(ManageSet(self.primary_type).methods)
        self.methods = methods


class ManageSet(OperationSet):
    def __init__(self, primary_type):
        """
        Defines the set of methods to run on an enm_node.Node object to manage a node on ENM

        :param primary_type: The node's primary type
        :type primary_type: str
        """

        self.primary_type = primary_type
        super(ManageSet, self).__init__()

    def _add_set_items(self):
        check_cm = SetItem(method=enm_node.Node.check_cm_management, description="Assert that node CM sync state is SYNCHRONIZED",
                           monitor_method=True, monitor_args={"status": "SYNCHRONIZED"})
        enable_cm = VerifySetItem(method=enm_node.Node.enable_cm_management, description="Enable CM supervision",
                                  verify_task=check_cm)

        check_fm = SetItem(method=enm_node.Node.check_fm_management, description="Assert that node FM service state is IN_SERVICE",
                           monitor_method=True, monitor_args={"status": "IN_SERVICE"})
        enable_fm = VerifySetItem(method=enm_node.Node.enable_fm_management, description="Enable FM supervision",
                                  verify_task=check_fm)

        check_pm = SetItem(method=enm_node.Node.check_pm_management, description="Assert that node PM function is ENABLED",
                           monitor_method=True, monitor_args={"status": "true"})
        enable_pm = VerifySetItem(method=enm_node.Node.enable_pm_management, description="Enable PM supervision",
                                  verify_task=check_pm)

        check_gen_counter = SetItem(method=enm_node.CppNode.check_generation_counter,
                                    description="Assert that node generation counter is greater than 0")

        if self.primary_type in ["ERBS", "MGW", "RNC", "RBS"]:
            self.methods = [[enable_cm, enable_fm, enable_pm], [check_gen_counter]]
        elif self.primary_type in ["JUNIPER", "BSC"]:
            self.methods = [[enable_cm, enable_fm]]
        elif self.primary_type in ["MSC-DB", "IP-STP", "vMSC", "vIP-STP"]:
            self.methods = [[enable_pm, enable_fm]]
        else:
            self.methods = [[enable_cm, enable_fm, enable_pm]]


class UnmanageSet(OperationSet):
    def __init__(self):
        """
        Defines the set of methods to run on an enm_node.Node object to un-manage a node on ENM
        """

        super(UnmanageSet, self).__init__()

    def _add_set_items(self):
        check_cm = SetItem(method=enm_node.Node.check_cm_management, description='Assert that node CM sync state is UNSYNCHRONIZED',
                           monitor_method=True, monitor_args={"status": 'UNSYNCHRONIZED'})
        disable_cm = VerifySetItem(method=enm_node.Node.disable_cm_management, description='Disabling CM supervision of node',
                                   verify_task=check_cm)

        check_fm = SetItem(method=enm_node.Node.check_fm_management, description='Assert that node FM supervision state is IDLE',
                           monitor_method=True, monitor_args={"status": "IDLE"})
        disable_fm = VerifySetItem(method=enm_node.Node.disable_fm_management, description='Disabling FM supervision of node',
                                   verify_task=check_fm)

        check_pm = SetItem(method=enm_node.Node.check_pm_management, description="Assert that node PM enabled state is FALSE",
                           monitor_method=True, monitor_args={"status": "false"})
        disable_pm = VerifySetItem(method=enm_node.Node.disable_pm_management, description='Disabling PM supervision of node',
                                   verify_task=check_pm)

        disable_shm = SetItem(method=enm_node.Node.disable_shm_management, description='Disabling SHM supervision of node')

        self.methods = [[disable_cm, disable_fm, disable_pm, disable_shm]]


class SyncSet(OperationSet):
    """
    Defines the set of methods to run on an enm_node.Node object to explicitly call a sync of a node on ENM
    """

    def _add_set_items(self):
        cm_sync = SetItem(method=enm_node.Node.sync, description="Trigger explicit CM sync")

        self.methods = [[cm_sync]]


class CreationSet(OperationSet):
    def __init__(self, primary_type, has_mecontext=False):
        """
        Defines the set of methods to run on an enm_node.Node object to create a node on ENM

        :param primary_type: The node's primary type
        :type primary_type: str
        :param has_mecontext: checks if node has mecontext
        :type has_mecontext: bool
        """

        self.primary_type = primary_type
        self.has_mecontext = has_mecontext
        super(CreationSet, self).__init__()

    def _add_set_items(self):
        create_mecontext = SetItem(method=enm_node.Node.create_mecontext, description="Create MeContext MO")
        create_ne = SetItem(method=enm_node.Node.create_networkelement, description="Create NetworkElement MO")
        create_connectivity_info = SetItem(method=enm_node.Node.create_connectivity,
                                           description="Create ConnectivityInformation MO")
        set_security = SetItem(method=enm_node.Node.set_node_security, description="Set node security credentials")
        set_up_snmp = SetItem(method=enm_node.Node.set_snmp_version, description="Set up SNMP")
        set_heartbeat_timeout = SetItem(method=enm_node.Node.set_heartbeat_timeout,
                                        description="Set up HeartBeat Interval")

        if self.primary_type in ["ERBS", "MGW", "JUNIPER", "CISCO", "SpitFire", "Router_6672", "Fronthaul-6080"]:
            self.methods = [[create_ne, create_connectivity_info, set_security]]
            config.set_prop('add_model_identity', False)
            config.set_prop('create_mecontext', False)
        elif self.primary_type in ["STN", "SIU02", "TCU02", "TCU04", "C608", "RadioTNode", "BSC",
                                   "IP-STP", "vIP-STP", "MSC-DB", "vMSC"]:
            config.set_prop('add_model_identity', True)
            config.set_prop('create_mecontext', True)
            self.methods = [[create_ne, create_connectivity_info, set_security, set_up_snmp]]
            if self.primary_type in ["STN", "SIU02", "TCU02", "TCU04", "C608", "RadioTNode"]:
                self.methods[0].append(set_heartbeat_timeout)
        else:
            config.set_prop('add_model_identity', False)
            config.set_prop('create_mecontext', False)
            self.methods = [[create_ne, create_connectivity_info, set_security, set_up_snmp]]

        if config.has_prop("create_mecontext") and config.get_prop("create_mecontext") or self.has_mecontext:
            self.methods[0].insert(0, create_mecontext)


class DeletionSet(OperationSet):
    def __init__(self):
        """
        Defines the set of methods to run on an enm_node.Node object to delete a node from ENM
        """
        super(DeletionSet, self).__init__()
        self.monitor_time = 500
        self.monitor_interval = 3

    def _add_set_items(self):
        delete_mecontext = SetItem(method=enm_node.Node._disable_supervision_delete_network_element, description="Verify that supervision is disabled for this node. This will also delete the MeContext tree.")
        delete_ne = SetItem(method=enm_node.Node._delete_network_element_tree, description="Delete NetworkElement MO and all descendants")

        methods = UnmanageSet().methods
        methods.extend([[delete_mecontext, delete_ne]])
        self.methods = methods


class OperationName(Enum):
    POPULATE = (PopulateOperation, PopulationSet)
    MANAGE = (ManageOperation, ManageSet)
    UNMANAGE = (UnmanageOperation, UnmanageSet)
    SYNC = (SyncOperation, SyncSet)
    CREATE = (CreateOperation, CreationSet)
    DELETE = (DeleteOperation, DeletionSet)

    def __str__(self):
        return self.name.lower()

    def __repr__(self):
        return str(self)

    @property
    def operation(self):
        return self.value[0]

    @property
    def item_set(self):
        return self.value[1]

    @classmethod
    def get_operation(cls, required_operation):
        if hasattr(cls, required_operation.upper()):
            return getattr(cls, required_operation.upper()).operation

        cls._invalid_choice(required_operation)

    @classmethod
    def get_operation_set(cls, required_operation):
        if hasattr(cls, required_operation.upper()):
            return getattr(cls, required_operation.upper()).item_set

        cls._invalid_choice(required_operation)

    @classmethod
    def _invalid_choice(cls, required_operation):
        raise KeyError("Specified operation '{0}' is not recognised. Supported operations "
                       "are: {1}".format(required_operation, ", ".join([op for op in cls.__members__.keys()])))


def is_dps_provider_neo4j():
    """
    :rtype: bool
    :return: True if the Neo4j is the DPS provider in this ENM deployment, otherwise False
    """
    dps_persistence_provider = shell.run_cmd_on_ms("grep dps_persistence_provider /ericsson/tor/data/global.properties").stdout
    return "neo4j" in dps_persistence_provider


def _create_thread_queues(nodes, num_workers, func_ref):
    """
    Shared functionality between create and populate operations

    :type nodes: list
    :param nodes: List of `enm_node.Node` instances
    :type num_workers: int
    :param num_workers: Number of threads to create
    :type func_ref: func
    :param func_ref: Function to call

    :rtype: list
    :return: List of execute thread queues to evaluate
    """
    rnc_nodes = []
    tqs = []
    # Create the nodes
    if any("RNC" in node.primary_type for node in nodes):
        rnc_nodes = [node for node in nodes if node.primary_type == "RNC"]
        tq = thread_queue.ThreadQueue(rnc_nodes, num_workers, func_ref=func_ref)
        tq.execute()
        tqs.append(tq)
    nodes = list(set(nodes) - set(rnc_nodes))
    if nodes:
        tq = thread_queue.ThreadQueue(nodes, num_workers, func_ref=func_ref)
        tq.execute()
        tqs.append(tq)
    return tqs
