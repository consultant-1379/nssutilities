import os
import pkgutil
import random
import re

import netsim_executor
from nssutils.lib import cache, exception, filesystem, log, mutexer, network, shell, thread_queue

NSSUTILS_PATH = pkgutil.get_loader('nssutils').filename
SHOW_NETWORK_CMD = ".show network "
SWITCHMIM_CMD = ".switchmim {ne_system} {ne_type} {mim_version} -nowarn"
PARALLEL_START = ".start -parallel"
PARALLEL_STOP = ".stop -parallel"
RESTART_CMD = ".restart"
SHOW_NODE_ATTRIBUTES = ".show simne"
START_NETSIM_CMD = "/netsim/inst/start_netsim"
STOP_NETSIM_CMD = "/netsim/inst/stop_netsim"
GET_STARTED_NODES_CMD = ".show started"
SHOW_ALLSIMNES = ".show allsimnes"
PM_REF_FILE_NAME = "enm_workload.STATS"
PM_REF_FILE_PATH = "/netsim/netsimdir/{simulation}/data_files/pm_filesets/{pm_ref_file_name}.lte"

GET_ALL_SIMULATIONS_CMD = "echo .show simulations | /netsim/inst/netsim_pipe | grep -v '.zip'"
CREATE_SIMULATION_XML_FILE_CMD = "bash -c \"echo .open {sim}; echo .select network; echo .createarne R12.2 {sim}_fetcher NETSim %nename {password} IP secure sites no_external_associations defaultgroups\" | /netsim/inst/netsim_pipe -stop_on_error"
ADD_NETSIM_AND_SIMULATION_TO_ARNE_XML_CMD = "sed -i -e 's|</Model>|<Simulation string=\"{target_simulation}\"/> <Netsim string=\"{netsim}\"/> </Model>|; s/string=\"IST\"/string=\"GB-Eire\"/g' {local_file_path}"

NETSIM_ARNE_CREATE_PATH = "/netsim/netsimdir/exported_items/{sim}_fetcher_create.xml"
NETSIM_ARNE_DELETE_PATH = "/netsim/netsimdir/exported_items/{sim}_fetcher_delete.xml"
NETSIM_ARNE_DNS_PATH = "/netsim/netsimdir/exported_items/{sim}_fetcher_dns.xml"

SCTP_MO_PATH = "ManagedElement=1,TransportNetwork=1,Sctp=1"
SCTP_MO_ATTRIBUTE = "userLabel"
SCTP_MO_VALUES = ["abc.def.ghi", "jkl.mno.prq", "stv.wxy.z"]
AVC_BURST_CMD = "avcburst:id={id}, duration={duration}, freq={freq}, mode=temp, idle_time=0, avcdata = '[{MO_Updates}]', loop=true;"
AVC_BURST_MO_UPDATE_SUB_CMD = "{{\"{MO_path}\",[{{\"{MO_attribute}\",\"{MO_value}\"}}]}}"
BURST_ID = 500
BURST_DURATION = 15
SCTP_MO_PATH_AVC_OPTIONS_ATTRIBUTES = [SCTP_MO_PATH, SCTP_MO_ATTRIBUTE, SCTP_MO_VALUES]

FETCH_TIMEOUT = 60 * 50
NETSIM_USERNAME = "netsim"
NETSIM_PASSWORD = "netsim"


def fetch_arne_xmls_from_netsim(netsim_host, target_simulations, xml_dir, verbose=True, num_workers=20,
                                force_create=False, delete_created_files=False):
    """
    Fetch ARNE XML files for each simulation of a given netsim host and copies them to the specified directory
    [multi-threaded]

    :param netsim_host: Netsim to target
    :type netsim_host: string
    :param target_simulations: Simulations to fetch
    :type target_simulations: list of strings
    :param xml_dir: Absolute path to the directory where the ARNE XML files will be copied
    :type xml_dir: string
    :param verbose: Flag controlling whether information should be printed to console
    :type verbose: bool
    :param num_workers: Number of worker threads to be created
    :type num_workers: int
    :param force_create: Flag to indicate if the arne creation should be performed regardless
    :type force_create: bool
    :param delete_created_files: Flag to indicate if the generated files should be deleted
    :type delete_created_files: bool

    :returns: True of False whether the fetch operation succeeded or not
    :rtype: boolean
    """

    result = True
    work_items_thread_pool = []

    if "default" in target_simulations:
        target_simulations.remove("default")

    # Add each simulation to the work items thread pool
    for target_simulation in target_simulations:
        work_items_thread_pool.append([netsim_host, target_simulation])

    # Modify the number of workers if the number of work items is less than what is configured in props
    if len(work_items_thread_pool) < num_workers:
        num_workers = len(work_items_thread_pool)

    # Spawn threads to gather XML files
    tq = thread_queue.ThreadQueue(
        work_items_thread_pool, num_workers, get_xml_file_from_netsim,
        args=[xml_dir, verbose, force_create, delete_created_files], task_wait_timeout=FETCH_TIMEOUT)

    tq.execute()
    if tq.exceptions_raised > 0:
        result = False
        for entry in tq.work_entries:
            if entry.exception_raised:
                log.logger.error("    ERROR completing all tasks related to fetching ARNE XML file for: {0} - {1}. Exception: {2}"
                                 .format(entry.arg_list[0][0], entry.arg_list[0][1], entry.exception))
    else:
        for s in target_simulations:
            if not os.path.exists(os.path.join(xml_dir, s) + '.xml'):
                result = False

    return result


def get_password_for_simulation(host, simulation):
    """
    Attempt to retrieve the password for a simulation

    :type host: str
    :param host: The hostname of the netsim box
    :type simulation:  str
    :param simulation: Name of the simulation to get password details of

    :raises Exception: raised if started nodes command fails

    :rtype: str
    :return: Password for admin user if exists
    """
    password = 'netsim'
    key = "================================================================="
    try:
        response = _get_started_nodes(host, simulation).split(key)
    except Exception as e:
        raise e
    for sim in response:
        if simulation in sim:
            if "admin_user" in sim:
                password = sim.split("admin_user ")[1].split(' ')[0].strip()
    return password


def get_xml_file_from_netsim(work_item, xml_dir, verbose=True, force_create=False, delete_created_files=False):
    """
    Generates and copies the ARNE XML file for specified simulation on the specified netsim to the specified XML
    directory on the MS

    :param work_item: IP address or hostname of netsim target [0], and the simulation to target [1]
    :type work_item: list
    :param xml_dir: Absolute path to the directory on the MS where the ARNE XML file is to be copied
    :type xml_dir: str
    :param verbose: Flag to indicate if the logging output should be details
    :type verbose: bool
    :param force_create: Flag to indicate if the arne creation should be performed regardless
    :type force_create: bool
    :param delete_created_files: Flag to indicate if the generated files should be deleted
    :type delete_created_files: bool

    :raises RuntimeError: raised if shell command fails
    """

    netsim_hostname = work_item[0]
    target_simulation = work_item[1]

    log.logger.debug(
        "Attempting to create ARNE XML file for simulation {0}".format(target_simulation))

    password = get_password_for_simulation(netsim_hostname, target_simulation)
    create_xml_cmd = CREATE_SIMULATION_XML_FILE_CMD.format(sim=target_simulation, password=password)

    # Build the file paths that we expect the create arne command to create on
    # the netsim
    netsim_create_file_path = NETSIM_ARNE_CREATE_PATH.format(sim=target_simulation)
    netsim_delete_file_path = NETSIM_ARNE_DELETE_PATH.format(sim=target_simulation)
    netsim_dns_file_path = NETSIM_ARNE_DNS_PATH.format(sim=target_simulation)

    def _does_arne_exist():
        return filesystem.does_remote_file_exist(netsim_create_file_path, netsim_hostname, NETSIM_USERNAME,
                                                 NETSIM_PASSWORD)

    class TempResponse(object):
        rc = 0
        stdout = None

    # Generate the XML file
    # Note: Some RNC sims with DG2 Nodes take over 20 mins to generate ARNE xmls hence the command needs a long
    # timeout value
    response = TempResponse()
    cmd = shell.Command(create_xml_cmd, timeout=FETCH_TIMEOUT)
    action = "fetched"
    if not _does_arne_exist() or force_create:
        response = shell.run_remote_cmd(cmd, netsim_hostname, NETSIM_USERNAME, NETSIM_PASSWORD)
        action = "created"
    if response.rc == 0 and _does_arne_exist():
        log.logger.info("Successfully {1} ARNE XML file {0} on the netsim".format(netsim_create_file_path, action))
        if not xml_dir.endswith("/"):
            local_file_path = "{0}{1}{2}.xml".format(
                xml_dir, os.sep, target_simulation)
        else:
            local_file_path = "{0}{1}.xml".format(xml_dir, target_simulation)

        # Now copy the file to our target directory on the MS
        log.logger.debug(
            "Downloading remote files from {0} to {1}".format(netsim_hostname, local_file_path))
        shell.download_file(
            netsim_create_file_path, local_file_path, netsim_hostname, NETSIM_USERNAME, NETSIM_PASSWORD)

        if filesystem.does_file_exist(local_file_path):
            if verbose:
                log.logger.info(log.green_text("    Successfully copied ARNE XML file from netsim {0} to local path {1}".format(netsim_hostname, local_file_path)))
            else:
                log.logger.debug("    Successfully copied ARNE XML file from netsim {0} to local path {1}".format(netsim_hostname, local_file_path))

        cmd = ADD_NETSIM_AND_SIMULATION_TO_ARNE_XML_CMD.format(
            target_simulation=target_simulation, netsim=netsim_hostname, local_file_path=local_file_path)

        command = shell.Command(cmd)
        response = shell.run_local_cmd(command)

        if response.rc != 0:
            raise RuntimeError(
                "Could not add information about the simulation and netsim to ARNE XML file : {0}".format(local_file_path))

        # Delete the create, delete and dns XML files on the netsim
        log.logger.debug(
            "Deleting remote files on {0}".format(netsim_hostname))
        if delete_created_files:
            filesystem.delete_remote_file(netsim_create_file_path, netsim_hostname, NETSIM_USERNAME, NETSIM_PASSWORD)

        if filesystem.does_remote_file_exist(netsim_delete_file_path, netsim_hostname, NETSIM_USERNAME, NETSIM_PASSWORD):
            filesystem.delete_remote_file(netsim_delete_file_path, netsim_hostname, NETSIM_USERNAME, NETSIM_PASSWORD)

        if filesystem.does_remote_file_exist(netsim_dns_file_path, netsim_hostname, NETSIM_USERNAME, NETSIM_PASSWORD):
            filesystem.delete_remote_file(netsim_dns_file_path, netsim_hostname, NETSIM_USERNAME, NETSIM_PASSWORD)

        log.logger.debug("Successfully deleted {} delete and dns XML files on the netsim"
                         .format("created" if delete_created_files else ""))
    else:
        error_summary = ""
        if response.stdout:
            error_summary = extract_error_summary_from_output_of_failed_create_arne_operation(response.stdout)

        raise RuntimeError("    Failed to create ARNE XML file: {0}. {1}".format(
            netsim_create_file_path, error_summary))


def extract_error_summary_from_output_of_failed_create_arne_operation(printout_data):
    """
    Extracts 2 lines from the output from the netsim commands run during a failed create arne operation

    :param printout_data: data returned by the execution of netsim commands
    :type printout_data: string

    :returns: summary of the error encountered
    :rtype: string
    """

    netsim_create_arne_command = netsim_create_arne_command_response_one_line_only = ""
    check_logs_message = "Check nssutils debug.log for further details."

    match_successful = False
    match_pattern = re.compile(r'createarne')

    for line in printout_data.split("\n"):
        if match_pattern.search(line) is not None:
            match_successful = True
            netsim_create_arne_command = "Netsim Command: '{0}'.".format(line)
            continue

        if match_successful:
            netsim_create_arne_command_response_one_line_only = "Netsim Response: '{0}'.".format(line)
            break

    return "{0} {1} {2}"\
        .format(netsim_create_arne_command, netsim_create_arne_command_response_one_line_only, check_logs_message)


def validate_netsim_connectivity(netsim, verbose_mode=False):
    """
    Checks that the specified netsim is contactable

    :param netsim: IP address or hostname of netsim target
    :type netsim: string
    :param verbose_mode: Flag controlling whether extra log messages are printed or not
    :type verbose_mode: boolean

    :raises RuntimeError: raised if host is not reachable or ssh fails
    """

    key = "{0}-validated".format(netsim)

    with mutexer.mutex("check_netsim_connectivity"):
        netsim_validated = cache.get(key)

        if netsim_validated is None:
            # Check that we can ping the netsim
            if not network.is_host_pingable(netsim):
                raise RuntimeError("Netsim {0} is not pingable".format(netsim))

            # First check to see if we already have public key access to the
            # netsim host
            if not shell.are_ssh_credentials_valid(netsim, "netsim"):
                # Since we don't have public key access to the netsim, verify
                # that we can connect as netsim/netsim
                if not shell.are_ssh_credentials_valid(netsim, "netsim", "netsim"):
                    raise RuntimeError(
                        "Could not establish SSH connection to netsim {0} as user 'netsim' with password 'netsim'".format(netsim))

            if verbose_mode:
                log.logger.info(
                    "  Verified that netsim {0} is pingable and that we can connect to it as user netsim".format(netsim))

            cache.set(key, True)


def get_all_simulations_on_netsim(netsim, verbose_mode=False):
    """
    Returns a list of all of the simulations found on the specified netsim

    :param netsim: IP address or hostname of netsim target
    :type netsim: string
    :param verbose_mode: Flag controlling whether extra log messages are printed or not
    :type verbose_mode: boolean

    :returns: Simulation list
    :rtype: list
    """

    all_netsim_simulations = []

    cmd = shell.Command(GET_ALL_SIMULATIONS_CMD)
    response = shell.run_remote_cmd(cmd, netsim, "netsim", 'netsim')

    if response.rc == 0:
        if response.stdout is not None and len(response.stdout) > 0:
            for simulation in response.stdout.split("\n")[1:]:
                if simulation not in [None, "default"] and len(simulation.strip()) > 0:
                    all_netsim_simulations.append(simulation.strip())

    if verbose_mode:
        log.logger.info("  Found {0} simulations on netsim {1}".format(
            len(all_netsim_simulations), netsim))

    return all_netsim_simulations


def _execute_netsim_restart_cmd(operation, netsim):
    """
    Runs a command related to a netsim start, stop or restart

    :param operation: Operation to be performed (currently either 'start' or 'stop')
    :type operation: str
    :param netsim: IP address or hostname of netsim target
    :type netsim: string

    :returns: True or False whether the operation succeeded or not
    :rtype: boolean
    """

    result = False

    if "start" in operation:
        cmd = START_NETSIM_CMD
    elif "stop" in operation:
        cmd = STOP_NETSIM_CMD

    response = shell.run_remote_cmd(shell.Command(cmd, timeout=600), netsim, "netsim", 'netsim')

    if response.rc == 0:
        log.logger.debug("Netsim {0} operation executed successfully for netsim host {1}".format(operation, netsim))
        result = True
    else:
        log.logger.debug("Unable to execute {0} operation on netsim host {1}; rc returned was {2}".format(operation, netsim, response.rc))
        if response.stdout is not None and len(response.stdout) > 0:
            log.logger.debug("Output of {0} operation for netsim host {1}: {2}".format(operation, netsim, response.stdout))

    return result


def restart_netsim(netsim):
    """
    Tries to restart the given netsim

    :param netsim: IP address or hostname of netsim target
    :type netsim: string

    :returns: True or False whether the restart operation succeeded or not
    :rtype: boolean
    """

    log.logger.info(log.yellow_text('NOTE: This will stop all nodes in all simulations on the target netsim host'))
    restarted = True

    operations = ["stop", "start"]

    for operation in operations:
        attempts_remaining = 2
        operation_succeeded = False

        while attempts_remaining > 0 and not operation_succeeded:
            if _execute_netsim_restart_cmd(operation, netsim):
                operation_succeeded = True
            else:
                attempts_remaining = attempts_remaining - 1
                log.logger.debug("Attempt to execute {0} operation on netsim host {1} failed; {2} attempt(s) remaining...".format(operation, netsim, attempts_remaining))

        # If we've exceeded our set number of attempts, mark this as a fail
        if not operation_succeeded:
            log.logger.error("Unable to execute {0} operation on netsim host {1} during netsim restart".format(operation, netsim))
            restarted = False
            break

    if restarted:
        log.logger.info("Restart of netsim host {0} successful".format(netsim))
    else:
        log.logger.error("Restart of netsim host {0} failed".format(netsim))

    return restarted


def check_if_ref_file_exists(netsim, simulation):
    """
    Checks that the reference file set on a simulation within a netsim exists

    :param netsim: IP address or hostname of netsim target
    :type netsim: string
    :param simulation: The simulation within the netsim
    :type simulation: string

    :returns: True or False whether the reference file exists or not
    :rtype: boolean
    """

    result = False

    key = "{0}-{1}-ref-file-created".format(netsim, simulation)
    ref_file_created = cache.get(key)

    if ref_file_created is None or not ref_file_created:
        ref_file_path = PM_REF_FILE_PATH.format(pm_ref_file_name=PM_REF_FILE_NAME, simulation=simulation)

        if filesystem.does_remote_file_exist(ref_file_path, netsim, "netsim", 'netsim'):
            cache.set(key, True)
            result = True
    elif ref_file_created:
        result = True

    return result


def check_node_status_for_nodes_list(nodes):
    """
    Checks the nodes if they have been started and updates the attributes accordingly

    :param nodes: The list of enm_node.Node <objects>
    :type nodes: list

    :raises ValueError: raised if nodes list is empty

    :returns: The list of nodes
    :rtype: list
    """

    if nodes is None or len(nodes) < 1:
        raise ValueError("No nodes specified to check status of on netsim!")

    # Get a list of started nodes from netsim
    netsim_name = nodes[0].netsim
    simulation_name = nodes[0].simulation
    started_nodes = _get_started_nodes(netsim_name, simulation_name)

    # Check if nodes passed are in the started list and set node_started
    # property appropriately
    for node in nodes:
        if node.node_id in started_nodes:
            node.node_started = True
        else:
            node.node_started = False

    return nodes


def _get_started_nodes(netsim_name, simulation_name):
    """
    Gets the list of the started nodes in a simulation

    :param netsim_name: The name of the netsim
    :type netsim_name: string
    :param simulation_name: The name of the simulation
    :type simulation_name: string

    :returns: List of the started nodes
    :rtype: string
    """

    response = netsim_executor.run_cmd(GET_STARTED_NODES_CMD, netsim_name, sim=simulation_name)
    return response.stdout


def build_avc_burst_command(mo_path_name=None, notification_frequency=None):
    """
    Builds the avc burst command required to successfully start an avc burst on a node

    :param mo_path_name: The name of the MO patch to create the avc burst on
    :type mo_path_name: string
    :param notification_frequency: The frequency at which notifications should be sent
    :type notification_frequency: floating/integer

    :returns: The avc command required to successfully start an avc burst
    :rtype: string
    """

    # Get the skeleton command used to build the overall avc burst command
    avc_burst_command = AVC_BURST_CMD
    avc_burst_mo_sub_cmd = AVC_BURST_MO_UPDATE_SUB_CMD
    avc_burst_duration = BURST_DURATION

    # If the duration is constant, then se it so we reissue the burst command every half hour (although really this could be any time)
    avc_burst_duration = int(avc_burst_duration) if avc_burst_duration != "constant" else 1800

    # Get the attributes required to complete the skeleton avc burst command
    avc_cmd_attributes = SCTP_MO_PATH_AVC_OPTIONS_ATTRIBUTES

    mo_path = mo_path_name if mo_path_name else SCTP_MO_PATH
    mo_attribute = avc_cmd_attributes[1]
    mo_values = avc_cmd_attributes[2]

    update_cmds = []
    if isinstance(mo_values, list):
        for value in mo_values:
            update_cmds.append(avc_burst_mo_sub_cmd.format(
                MO_path=mo_path, MO_attribute=mo_attribute, MO_value=value))
    else:
        update_cmds.append(avc_burst_mo_sub_cmd.format(
            MO_path=mo_path, MO_attribute=mo_attribute, MO_value=mo_values))

    avc_burst_command = avc_burst_command.format(
        id=BURST_ID, duration=avc_burst_duration, freq=notification_frequency, MO_Updates=",".join(update_cmds))

    return avc_burst_command


def get_network_elements(simulation, netsim_host):
    """
    Get the network elements in a simulation

    :param simulation: The name of the node simulation within the netsim
    :type simulation: string
    :param netsim_host: The netsim host
    :type netsim_host: string

    :returns: List of the node in the simulation
    :rtype: list
    """

    simulation_nodes = None

    # Get the list of nodes in the simulation
    response = netsim_executor.run_cmd(SHOW_NETWORK_CMD, netsim_host, sim=simulation)

    try:
        # Parse stdout and extract a list of node names
        stdout_list = re.findall(r'([a-zA-Z0-9-]+)', response.stdout)

        # There is a sim_nes substring which has format sim_nes = ['LTE01ERBS0001'....
        # Truncate the list after sim_nes to pick up the node names
        truncation_key = "nes"

        truncation_position = stdout_list.index(truncation_key) + 1

        simulation_nodes = stdout_list[truncation_position:]
    except:
        exception.process_exception(
            msg="Could not get a list of nodes for this simulation", fatal=True)

    return simulation_nodes


def execute(operation, netsim, simulation_list, nodes=None):
    """
    Executes an operation on the netsim

    :param operation: Operation is one of start, stop, restart etc.
    :type operation: string
    :param netsim: The netsim host
    :type netsim: string
    :param simulation_list: List of simulations
    :type simulation_list: list
    :param nodes: List of nodes to operate on
    :type nodes: list

    :returns: True or False whether the operation succeeded or not
    :rtype: boolean
    """

    result = False

    if operation == "start":
        op_command = PARALLEL_START
    elif operation == "stop":
        op_command = PARALLEL_STOP
    elif operation == "restart":
        op_command = RESTART_CMD

    if operation in ["start", "stop", "restart"]:
        if nodes:
            cmd = op_command
            stdout = update_simulation(simulation_list[0], sim_host=netsim, cmd=cmd, nodes=nodes, operation=operation)
            if (operation == "restart" and stdout.count("OK") == 3) or stdout.count("OK") == 1:
                result = True
        else:
            nodes = ['network']
            cmd = op_command
            sim_host = netsim

            tq = thread_queue.ThreadQueue(simulation_list, len(simulation_list), update_simulation, [sim_host, cmd, nodes, operation])
            tq.execute()

            num_successes = 0
            for work_entry in tq.work_entries:
                if work_entry.result is not None and work_entry.result.count("OK") == 1:
                    num_successes += 1

            if num_successes == len(simulation_list):
                result = True

    elif operation == "list_simulations":
        _print_simulations(netsim, simulation_list)
        result = True

    elif operation == "list_nodes":
        tq = thread_queue.ThreadQueue(
            simulation_list, len(simulation_list), get_network_elements, [netsim])
        tq.execute()

        _print_nodes(tq.work_entries)

        result = tq.process_results(tq.work_entries)

    elif operation in ["activities", "info"]:
        sim_dict = {}
        for simulation in simulation_list:
            sim_dict[simulation] = {}

        # This dictionary sims_dict will now be passed down through the methods to add information on each node in each simulation
        if operation == "activities":
            result_1 = _core_info_added(netsim, sim_dict)
            result_2 = _subscription_info_added(netsim, sim_dict)
            result_3 = _activity_info_added(netsim, sim_dict)
            _print_info(sim_dict, activities=True)

            if all([result_1, result_2, result_3]):
                result = True

        else:
            result = _core_info_added(netsim, sim_dict)
            _print_info(sim_dict)

    elif operation == 'restart_netsim':
        # Try to restart the netsim
        result = restart_netsim(netsim)

        if result:
            # If restarted try to start all the nodes in all simulations
            tq = thread_queue.ThreadQueue(simulation_list, len(simulation_list), update_simulation, [netsim, PARALLEL_START, ['network'], 'start'])
            tq.execute()

            result = tq.process_results(tq.work_entries)

    return result


def switch_mim(netsim_host, simulation, node_name, mim_version):
    """
    Updates the MIM version on nodes on a given simulation

    :param netsim_host: hostname of netsim target
    :type netsim_host: string
    :param simulation: The name of the simulation within the netsim
    :type simulation: string
    :param node_name: The name of the node within the simulation
    :type node_name: string
    :param mim_version: The MIM version we want to set on the nodes
    :type mim_version: string

    :raises RuntimeError: raised if nodes fail to start

    :returns: True or False whether the MIM update succeeded or not
    :rtype: boolean
    """

    if not execute("start", netsim_host, [simulation]):
        raise RuntimeError("Unable to start all nodes on netsim")
    else:
        log.logger.info(log.green_text("\nSuccessfully started all nodes on simulation {0}".format(simulation)))

    result = False
    log.logger.info(log.green_text("\nAttempting to update MIM version on simulation {0}".format(simulation)))
    ne_system, ne_type, current_mim_version = _get_ne_type(simulation, node_name, netsim_host).split()

    if mim_version == current_mim_version:
        log.logger.info("\n{0} is already the MIM version for nodes on this simulation\n".format(mim_version))
    else:
        num_nodes = len(get_network_elements(simulation, netsim_host))
        cmd = SWITCHMIM_CMD.format(ne_system=ne_system, ne_type=ne_type, mim_version=mim_version)
        response = netsim_executor.run_cmd(cmd, netsim_host, sim=simulation, node_names="network")
        if "Mim change done for NE" in response.stdout:
            num_changed_nodes = response.stdout.count("Mim change done for NE")
            log.logger.info(log.green_text("\nMIM version changed for {0}/{1} nodes on simulation {2}"
                                           .format(num_changed_nodes, num_nodes, simulation)))
            if num_changed_nodes == num_nodes:
                result = True
            else:
                log.logger.warn("Please run '/opt/ericsson/nssutils/bin/netsim info {0} {1}' to see what nodes failed "
                                "to have their MIM version changed".format(netsim_host, simulation))
        elif "given NE type doesn't use" in response.stdout:
            log.logger.error("\nERROR: {0} is not a valid MIM version".format(mim_version))
        else:
            log.logger.error("\nERROR: Something went wrong when trying to update MIM version for nodes on simulation "
                             "{0}. Please see nssutils logs for more information ....".format(simulation))

    return result


def update_simulation(sim, sim_host=None, cmd=None, nodes=None, operation=None):
    """
    Executes netsim commands on a simulation

    :param sim: The name of the simulation within the netsim
    :type sim: string
    :param sim_host: hostname of netsim target
    :type sim_host: string
    :param cmd: The list of netsim shell commands
    :type cmd: list
    :param nodes: The list of nodes to update
    :type nodes: list
    :param operation: The operation to execute i.e. start, stop etc.
    :type operation: string

    :returns: list where index 0 is boolean and index 1 is stderr merged into stdout
    :rtype: list
    """

    if nodes and len(nodes) > 0:
        nodes_length = str(len(nodes))
        node_names = ' '.join(nodes)

        if "network" in node_names:
            num = "all"
        else:
            num = nodes_length
    else:
        node_names = None
        num = "all"

    log.logger.info(log.green_text("Attempting to %s %s nodes on simulation %s" % (operation, num, sim)))

    return netsim_executor.run_cmd(cmd, sim_host, sim=sim, node_names=node_names).stdout


def _core_info_added(netsim, update_dict_with_core_info):
    """
    Retrieves information i.e. IP, MIM version, node status, on all nodes from each simulation passed down

    :param netsim: The netsim host
    :type netsim: string
    :param update_dict_with_core_info: A dictionary containing simulations that is used to retrieve information
                                       on all the associated nodes in each simulation. The retrieved information
                                       will then be appended to this dictionary on a per node per simulation basis.
    :type update_dict_with_core_info: dictionary

    :returns: True or False whether the operation succeeded or not
    :rtype: boolean
    """

    log.logger.info("Collecting core information from %s\n" % netsim)
    node_data_cmd = SHOW_ALLSIMNES
    response = netsim_executor.run_cmd(node_data_cmd, netsim)
    node_data_list = response.stdout
    core_info = {}

    # At this stage we have a dictionary mapping each simulation to its position in the node_data_list
    # and a index_list from which we can get the position of the next simulation
    tq = thread_queue.ThreadQueue(update_dict_with_core_info.keys(), len(update_dict_with_core_info.keys()), _build_core_info, args=[node_data_list, netsim])
    tq.execute()
    for work_entry in tq.work_entries:
        core_info[work_entry.arg_list[0]] = work_entry.result

    merge_dict(update_dict_with_core_info, core_info)

    return response.ok


def _build_core_info(simulation, node_data_list, netsim):
    """
    Algorithm to get core information.

    :param simulation: The simulation that the node data was obtained from
    :type simulation: string
    :param node_data_list: A list of node data that we parse
    :type node_data_list: string
    :param netsim: The netsim host
    :type netsim: string

    :returns: Dictionary
    :rtype: dictionary
    """

    sim_dict = dict()
    sim_info = []
    try:
        node_data_list = node_data_list[node_data_list.index(simulation):].split("\n\n", 1)[0]

        if "default" in node_data_list:
            node_data_list = node_data_list.split("default")[0]

        node_data_list = node_data_list.split("\n")
        sim_info = node_data_list[node_data_list.index(simulation):]
        sim_info = node_data_list[3:]
    except:
        exception.process_exception(
            msg="Could not parse core node information in simulation %s" % simulation)

    for sim in sim_info:
        sim = sim.split()

        if len(sim) < 3:
            continue

        node_name = sim[0]
        ip = sim[1]
        server = sim[-1]
        sim_dict[node_name] = {}
        sim_dict[node_name]["ip"] = ip

        if "server_" in server:
            sim_dict[node_name]["status"] = "started"
        else:
            sim_dict[node_name]["status"] = "stopped"

    try:
        random_ch = random.choice(sim_dict.keys())
        mim = get_mim_version_for_node(simulation, random_ch, netsim)
        sim_dict["mim"] = mim
    except:
        exception.process_exception(
            msg="Could not determine MIM version of nodes in simulation %s" % simulation)
        sim_dict["mim"] = "unknown"

    return sim_dict


def get_mim_version_for_node(simulation, node_name, netsim):
    """
    Checks for MIM versions in simulation name and returns a parsed MIM

    :param simulation: A simulation
    :type simulation: string
    :param node_name: The name of a node in the simulation
    :type node_name: string
    :param netsim: The netsim host
    :type netsim: string

    :returns: Parsed MIM version
    :rtype: string
    """

    # Checking for { as new MIM versions aren't decided yet and { appears in place of new MIM versions in the new nodes
    ne_type = _get_ne_type(simulation, node_name, netsim)
    if "{" in ne_type:
        mim_version = ne_type.strip()
    else:
        mim_version = ne_type.split()[-1]
    return mim_version


def _get_ne_type(simulation, node_name, netsim):
    """
    Gets NE type information from node

    :param simulation: A simulation
    :type simulation: string
    :param node_name: The name of a node in the simulation
    :type node_name: string
    :param netsim: The netsim host
    :type netsim: string

    :returns: NE type of the node
    :rtype: string
    """

    cmd = "{0} {1}".format(SHOW_NODE_ATTRIBUTES, node_name)
    response = netsim_executor.run_cmd(cmd, netsim, simulation)
    regex_for_ne_type = r"ne_type.*\n"
    ne_type = re.search(regex_for_ne_type, response.stdout).group(0).split(":")[1].replace("\n", "")

    return ne_type


def _subscription_info_added(netsim, sims_dict):
    """
    Retrieves subscription information on all nodes from each simulation passed down

    :param netsim: The netsim host
    :type netsim: string
    :param sims_dict: A dict containing simulations and node info which the subscription info will be added to appropriately
    :type sims_dict: dictionary

    :returns: True or False whether the operation succeeded or not
    :rtype: boolean
    """

    log.logger.info("Collecting subscription information from %s\n" % netsim)
    subscription_dict = {}

    tq = thread_queue.ThreadQueue(sims_dict.keys(), len(
        sims_dict.keys()), _get_subscription_info, args=[netsim, "network", sims_dict])
    tq.execute()

    for work_entry in tq.work_entries:
        subscription_dict[work_entry.arg_list[0]] = work_entry.result

    merge_dict(sims_dict, subscription_dict)

    return tq.process_results(tq.work_entries)


def _get_subscription_info(simulation, netsim, network, sims_dict):
    """
    Algorithm to search for subscription information

    :param simulation: The simulation to get subscription data for
    :type simulation: string
    :param netsim: The netsim host
    :type netsim: string
    :param network: A string which represents the network
    :type network: string
    :param sims_dict: A dictionary of simulation information
    :type sims_dict: dict

    :returns: A dictionary containing all subscriptions and the subscription status for each node in the simulation
    :rtype: dictionary
    """

    nodes = sims_dict[simulation].keys()
    node_indices = {}
    sim_dict = dict()
    status_cmd = "status;"
    response = netsim_executor.run_cmd(status_cmd, netsim, sim=simulation, node_names=network)

    # Load the string patterns to use in the subscription search
    fm_header_pattern = "Alarm Service information:"
    cm_header_pattern = "Configuration Service information:"
    pm_header_pattern = "Performance Management information:"
    fm_no_subscription_pattern = "No active alarm subscriptions"
    cm_no_subscription_pattern = "No CS subscriptions"
    pm_no_subscription_pattern = "There are no scanners"
    not_started_pattern = "Not started!"
    cm_subscription_pattern = "Subscriptions:"
    fm_subscription_pattern = "Alarm subscriptions:"
    pm_subscription_pattern = "Scanners:"
    ne_status_crash_pattern = "Streamsession"

    # We just want the nodes and not the mim key
    try:
        nodes.remove("mim")
    except:
        log.logger.debug("No mim key to remove in the keys")

    # The simulation is Not started!
    if response.stdout.count(not_started_pattern) == 1 or "Command not found: status" in response.stdout:
        for node in nodes:
            sim_dict[node] = {'fm_sub': 'inactive', 'pm_sub': 'inactive', 'cm_sub': 'inactive'}
        return sim_dict

    # Map the indices of the nodes in the response.stdout
    for node in nodes:
        node_indices[response.stdout.index(node)] = node

    # Sort the indices so we know where to start and stop when picking up a node's subscription data
    indices = node_indices.keys()
    indices.append(len(response.stdout))
    indices.sort()

    # Perform the checks for subscription data
    for i in xrange(0, len(indices) - 1):
        node_subscription_info = response.stdout[indices[i]:indices[i + 1]]

        # Network Element Not started! or Streamsession crashed
        if not_started_pattern in node_subscription_info or ne_status_crash_pattern in node_subscription_info:
            sim_dict[node_indices[indices[i]]] = {'fm_sub': 'inactive', 'pm_sub': 'inactive', 'cm_sub': 'inactive'}
            continue
        else:
            sim_dict[node_indices[indices[i]]] = {'fm_sub': '', 'pm_sub': '', 'cm_sub': ''}

        # FM check
        if fm_header_pattern in node_subscription_info:
            if fm_no_subscription_pattern in node_subscription_info:
                sim_dict[node_indices[indices[i]]]["fm_sub"] = "inactive"
            elif fm_subscription_pattern in node_subscription_info:
                sim_dict[node_indices[indices[i]]]["fm_sub"] = "active"
            else:
                sim_dict[node_indices[indices[i]]]["fm_sub"] = "inactive"
        else:
            sim_dict[node_indices[indices[i]]]["fm_sub"] = "inactive"

        # CM check
        if cm_header_pattern in node_subscription_info:
            if cm_no_subscription_pattern in node_subscription_info:
                sim_dict[node_indices[indices[i]]]["cm_sub"] = "inactive"
            elif cm_subscription_pattern in node_subscription_info:
                sim_dict[node_indices[indices[i]]]["cm_sub"] = "active"
            else:
                sim_dict[node_indices[indices[i]]]["cm_sub"] = "inactive"
        else:
            sim_dict[node_indices[indices[i]]]["cm_sub"] = "inactive"

        # PM check
        if pm_header_pattern in node_subscription_info:
            if pm_no_subscription_pattern in node_subscription_info:
                sim_dict[node_indices[indices[i]]]["pm_sub"] = "inactive"
            elif pm_subscription_pattern in node_subscription_info:
                sim_dict[node_indices[indices[i]]]["pm_sub"] = "active"
            else:
                sim_dict[node_indices[indices[i]]]["pm_sub"] = "inactive"
        else:
            sim_dict[node_indices[indices[i]]]["pm_sub"] = "inactive"

    return sim_dict


def _is_node(node_entry, nodes):
    """
    Checks for a node

    :param node_entry: A node id
    :type node_entry: string
    :param nodes: A list of nodes in a simulation.
    :type nodes: list

    :returns: True or False whether the entry is a node id
    :rtype: boolean
    """

    node = False

    # regex: include all letters a-z & A-Z. include all numbers 0-9 and include -. '\' escapes the '-' so regex explicitly takes the '-'
    is_node = re.match(r'([a-zA-Z0-9\-]+:)', node_entry)

    if is_node and 'crashed' not in node_entry and is_node.groups()[0].strip(':') in nodes:
        node = True

    return node


def _activity_info_added(netsim, sims_dict):
    """
    Top level function to get the activity information for a simulation

    :param netsim: The netsim host
    :type netsim: string
    :param sims_dict: A dict containing simulations and node info which the activity info will be added to appropriately
    :type sims_dict: dictionary

    :returns: True
    :rtype: boolean
    """

    log.logger.info("Collecting activity information from %s\n" % netsim)
    activity_dict = {}
    tq = thread_queue.ThreadQueue(
        sims_dict.keys(), len(sims_dict), _get_activity_info, [netsim])
    tq.execute()

    for work_entry in tq.work_entries:
        if work_entry.result is not None:
            activity_dict[work_entry.arg_list[0]] = work_entry.result

    merge_dict(sims_dict, activity_dict)

    return True


def _get_activity_info(simulation, netsim):
    """
    Gets the activity information for a simulation

    :param simulation: A simulation
    :type simulation: string
    :param netsim: The netsim host
    :type netsim: string

    :returns: Dictionary
    :rtype: dictionary
    """

    components_cmd = ".show components"
    activity_nodes = {}
    activity_status = {}

    response = netsim_executor.run_cmd(components_cmd, netsim, sim=simulation)
    components = response.stdout

    component_list = _parse_components(components, simulation)

    if len(component_list) > 0:
        # If we have components get the activities
        tq = thread_queue.ThreadQueue(component_list, len(component_list), _parse_component_nodes, args=[netsim, simulation, activity_nodes])
        tq.execute()

        show_activities_cmd = ".show activities"

        response = netsim_executor.run_cmd(show_activities_cmd, netsim, sim=simulation)
        activity_data = response.stdout

        _parse_activity_status(activity_data, activity_status)
        return _build_simulation_dictionary(activity_nodes, activity_status)


def _parse_components(components_data, simulation):
    """
    Gets the component IDs

    :param components_data: Stdout from show components command
    :type components_data: string
    :param simulation: A simulation on the netsim
    :type simulation: string

    :returns: List of the component IDs
    :rtype: list
    """

    if "no components" in components_data:
        cache.set("%s_activity_info" % simulation, {})
        return []

    return re.findall(r'([A-Z0-9]+)', components_data)


def _parse_component_nodes(component, netsim, simulation, activity_nodes):
    """
    Parse the nodes from the component data

    :param component: Component ID
    :type component: string
    :param netsim: Netsim host
    :type netsim: string
    :param simulation: A simulation on the netsim
    :type simulation: string
    :param activity_nodes: Stores an activity's nodes
    :type activity_nodes: dictionary
    """

    component_cmd = ".show component {cmp}".format(cmp=component)
    response = netsim_executor.run_cmd(component_cmd, netsim, sim=simulation)
    component_data = response.stdout
    _parse_nodes(component_data, activity_nodes)


def _parse_nodes(component_data, activity_nodes):
    """
    Gets the activity's nodes

    :param component_data: Stdout from show component command
    :type component_data: string
    :param activity_nodes: Data structure to hold an activity's nodes
    :type activity_nodes: dictionary

    :returns: Dictionary
    :rtype: dictionary
    """

    component_data = re.sub(r',\n\s+', ',', component_data.strip())
    data_list = component_data.split('\n')[1:]
    # Creating a dict of key value pairs splitting on ':'. For example: activities : ['+alarm']
    # splits into a dict {'activities': '+alarm'}
    activity_data = dict([re.sub(r'[\s\[\]"]+', '', item).split(':') for item in data_list])
    if activity_data['activities'].startswith('+'):
        activity_nodes[activity_data['activities']] = activity_data['sim_nes'].split(',')
    return activity_nodes


def _parse_activity_status(activity_data, activity_status):
    """
    Gets the activity status for a group of activities

    :param activity_data: Stdout from netsim show activities command
    :type activity_data: string
    :param activity_status: Data structure to hold activities status
    :type activity_status: dictionary

    :returns: Dictionary
    :rtype: dictionary
    """

    data_list = activity_data.split()

    i = 0
    while i < len(data_list):
        if "+" in data_list[i]:
            if "-" in data_list[i + 1]:
                activity_status[data_list[i]] = "stopped"

            else:
                activity_status[data_list[i]] = data_list[i + 1]
        i += 1

    return activity_status


def _build_simulation_dictionary(activity_nodes, activity_status):
    """
    Builds a dictionary of activity data for a simulation

    :param activity_nodes: Contains activities running on nodes
    :type activity_nodes: dictionary
    :param activity_status: Contains activity's status
    :type activity_status: dictionary

    :returns: Dictionary
    :rtype: dictionary
    """

    simulation_dictionary = {}

    for activity_name, nodes in activity_nodes.iteritems():
        status_of_activity = activity_status[activity_name]

        for node in nodes:
            if node not in simulation_dictionary.keys():
                simulation_dictionary[node] = {}
                simulation_dictionary[node]["activities"] = {}

            simulation_dictionary[node]["activities"][activity_name] = status_of_activity

    return simulation_dictionary


def _print_info(sims_dict, activities=False):
    """
    Prints information on the nodes in the simulations

    :param sims_dict: A list of simulations
    :type sims_dict: dictionary
    :param activities: Flag to include activities
    :type activities: boolean

    """

    for simulation in sims_dict.keys():

        log.logger.info(log.purple_text("%s" % simulation))
        log.logger.info("")

        mim_version = sims_dict[simulation]["mim"]
        del sims_dict[simulation]["mim"]
        for node_name, node_info in sorted(sims_dict[simulation].items()):
            try:
                node_keys = node_info.keys()
                node_status = node_info["status"]

                log.logger.info(log.cyan_text("  %s" % node_name))

                if "{" in mim_version:
                    mim_version = log.red_text(mim_version)

                node_status_colour = log.green_text if node_status == "started" else log.red_text

                log.logger.info("    IP: %-18s MIM version: %s    Node Status: %s " % (
                    node_info["ip"], mim_version, node_status_colour(node_status)))

                if activities:
                    if "fm_sub" in node_keys and "cm_sub" in node_keys and "pm_sub" in node_keys:
                        log.logger.info("    FM Subscription: %s    CM Subscription: %s    PM Subscription: %s" % (node_info["fm_sub"], node_info["cm_sub"], node_info["pm_sub"]))
                    else:
                        log.logger.info("    FM Subscription: %s    CM Subscription: %s    PM Subscription: %s" % ("No data", "No data", "No data"))

                    log.logger.info("    Activities:")

                    if "activities" in node_keys:
                        for activity_name, activity_status in node_info["activities"].items():
                            log.logger.info("        %s    %s" %
                                            (activity_name, activity_status))
                    else:
                        log.logger.info("        No activities")

                log.logger.info("")
            except KeyError:
                log.logger.debug('Invalid node information structure encountered, probably due to an unsupported node type: {0}, {1}'.format(node_name, node_info))


def _print_simulations(netsim, simulations):
    """
    Prints a list of simulations to the user

    :param netsim: NetSim host name
    :type netsim: str
    :param simulations: List of simulations
    :type simulations: list
    """

    if len(simulations) == 0:
        log.logger.warn("There are no simulations on %s" % netsim)
        return

    log.logger.info(log.purple_text("Simulations:"))

    for sim in simulations:
        if sim != "default":
            log.logger.info(log.green_text("    %s" % sim))

    log.logger.info("")


def _print_nodes(thread_queue_entries):
    """
    Prints a list of nodes in each simulation

    :param thread_queue_entries:List of thread_queue entries
    :type thread_queue_entries: list
    """

    for q_entry in thread_queue_entries:
        log.logger.info("")
        log.logger.info(
            log.purple_text("Simulation: %s" % q_entry.arg_list[0]))
        log.logger.info(log.green_text("     Node Number   |   Node Name"))
        log.logger.info(
            log.green_text("    ---------------------------------"))

        for index, value in enumerate(q_entry.result):
            log.logger.info("        %-*s %s" % (12, index + 1, value))


def check_nodes_for_predefined_scanners(netsim, simulation, nodes, scanner_id):
    """
    Checks for the existence of pre-defined scanners with a particular ID on nodes in simulation

    :param netsim: The host of the netsim nodes
    :type netsim: string
    :param simulation: The simulation in which the nodes are contained
    :type simulation: string
    :param nodes : List of node names we are querying for scanner information
    :type nodes : list
    :param scanner_id: The scanner Id we are checking for on the nodes
    :type scanner_id: string

    :returns: Dict with True/False value for each node depending on whether it has the scanner or not
    :rtype: dictionary
    """

    response_dict = {node: False for node in nodes}
    node_string = " ".join(nodes)
    response = netsim_executor.run_cmd("showscanners2;", netsim, simulation, node_string)
    # If there is an equals sign in the response that means there is at least one scanner on the nodes
    if response.ok and "===\n" in response.stdout:
        # If there are only four new lines in the whole output that means all nodes have same scanners
        if ":" not in response.stdout:
            if "\n{0} ".format(scanner_id) in response.stdout:
                response_dict = {node: True for node in nodes}
        else:
            # Split on the two new lines to get a list if node info
            scanner_info_on_nodes = response.stdout.split("\n\n")
            for node in nodes:
                for scanner_info_on_node in scanner_info_on_nodes:
                    if node in scanner_info_on_node:
                        node_info = scanner_info_on_node.split(":")[1]
                        # Scanner id is always at the start of a new line followed by a space
                        if "\n{0} ".format(scanner_id) in node_info:
                            response_dict[node] = True
                        break

    return response_dict


def get_version(netsim):
    """
    Returns netsim version, installed patches, license info

    :param netsim: IP address or hostname of netsim target
    :type netsim: string

    :returns: A dictionary containing: netsim version, a list of installed patches and a dictionary with license information
    :rtype: dictionary
    """

    version_marker = "Directory: /netsim/"
    patch_marker = "Installed patches:"
    version_marker_found = False
    patch_marker_found = False
    version = None
    output = {}
    response = netsim_executor.run_cmd(".show installation", netsim)
    response_line_list = response.stdout.splitlines()
    if len(response_line_list) > 0:
        for line in response_line_list:
            if version_marker_found:
                if not version:
                    match = re.match(r' \* NETSim UMTS (R\d\d\w+)\s+installed', line)
                    if match:
                        version = match.group(1)
                        output['version'] = version
                        output['patches'] = []
                        output['license'] = {}
                if patch_marker_found:
                    match = re.match(r'(P\d{5}.+)', line)
                    if match:
                        output['patches'].append(match.group(1))
                else:
                    patch_marker_found = patch_marker in line
            else:
                version_marker_found = version_marker in line
    if version:
        response_output = netsim_executor.run_cmd(".show license", netsim).stdout
        if response_output:
            match = re.search(r'NETSim license number (\d+), revision (\d+), for generation (\d+.\d+), expires (\d{4}.\d\d.\d\d).+\nIt allows (\d+) .+\n(.+)', response_output)
            if match:
                output['license']['number'] = match.group(1)
                output['license']['revision'] = match.group(2)
                output['license']['generation'] = match.group(3)
                output['license']['expiration'] = match.group(4)
                output['license']['nodes'] = match.group(5)
                output['license']['hosts'] = match.group(6)

    return output


def merge_dict(base_dict, built_dict):
    """
    B{Merges the built up dictionary to the base dictionary containing all the sorted information}

    @type base_dict: dict
    @param base_dict: The base dictionary which you want to merge into
    @type built_dict: dict
    @param built_dict: A dictionary containing information you've gathered which is to be merged to base
    @rtype: void
    """

    for key, value in built_dict.items():
        if key in base_dict.keys():
            for inner_key, inner_value in value.items():
                if isinstance(inner_value, dict) and inner_key in base_dict[key].keys():
                    for k, v in inner_value.items():
                        base_dict[key][inner_key][k] = v
                else:
                    if inner_key in base_dict[key] and isinstance(base_dict[key][inner_key], list):
                        base_dict[key][inner_key].extend(inner_value)
                    else:
                        base_dict[key][inner_key] = inner_value
        else:
            base_dict[key] = value
