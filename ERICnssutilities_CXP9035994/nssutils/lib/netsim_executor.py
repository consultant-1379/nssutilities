import os
import re
import pkgutil
from unipath import Path
from nssutils.lib import persistence, shell, cache, filesystem, mutexer, log


NSSUTILS_PATH = Path(pkgutil.get_loader('nssutils').filename)


def run_sim_cmd(cmd, host, sim, password=None):
    """
    B{Runs a command on a given simulation on a specified Netsim box}

    @type cmd: string
    @param cmd: The command to be run on Netsim
    @type host: string
    @param host: The Netsim box you want to access
    @type sim: string
    @param sim: The simulation you wish to use on the Netsim box
    @type password: string
    @param password: The password to the netsim host

    @rtype: dict
    """

    response = run_cmd(cmd, host, sim, password)
    response_dict = _parse_sim_response(response, sim)

    return response_dict


def _parse_sim_response(response, sim_name):
    """
    B{Parses the response after running the command on a simulation remotely and returns a dict}

    @type response: shell.response object
    @param response: Response object retrieved from running the remote simulation command
    @type sim_name: string
    @param sim_name: The simulation you wish to use on the Netsim box
    @rtype: dict
    """

    response_desc = _prepare_response(response)

    if response.ok and response_desc.startswith("createarne", 4):
        node_status = _check_create_arne_response(response)
        result_dict = {sim_name: node_status}
    elif response.ok:
        ok_matches = re.findall('OK', response_desc)

        if len(ok_matches) == 1:
            result_dict = {sim_name: 'OK'}
        else:
            result_dict = {sim_name: 'FAIL'}
    else:
        result_dict = {sim_name: 'FAIL'}

    return result_dict


def _check_create_arne_response(response):
    """
    B{Checks if the document is valid and returns an Ok or Fail pending on this}

    @type response: shell.response object
    @param response: Response object retrieved from running the remote sim command
    @rtype: string
    """

    matches = re.findall('the document is valid', response.stdout)
    if len(matches) == 2:
        return "OK"
    else:
        return "FAIL"


def run_ne_cmd(cmd, host, sim, node_names, password=None):
    """
    B{Runs a command on a given list of nodes in a specified simulation on a specified Netsim box}

    @type cmd: string
    @param cmd: The command to be run on Netsim
    @type host: string
    @param host: The Netsim box you want to access
    @type sim: string
    @param sim: The simulation you wish to use on the Netsim box
    @type node_names: list
    @param node_names: A list of node_names you wish to use
    @type password: string
    @param password: The password to the netsim host

    @rtype: dict
    """

    nodes = node_names
    if isinstance(node_names, list):
        nodes = ' '.join(node_names)
    response = run_cmd(cmd, host, sim, nodes, password)
    response_dict = _parse_ne_response(response, node_names)
    if "all" in response_dict:
        if "OK" in response_dict["all"]:
            response_dict = {node: 'OK' for node in node_names}
        else:
            response_dict = {node: 'FAIL' for node in node_names}

    return response_dict


def _parse_ne_response(response, node_names):
    """
    B{Parses the response after running the command on a specific set of nodes in a simulation remotely and returns a dict}

    @type response: shell.response object
    @param response: Response object retrieved from running the remote ne command
    @type node_names: list
    @param node_names: A list of node names to run the command on
    @rtype: dict
    """

    nodes = {}
    if response.ok:
        response_desc = _prepare_response(response, node_names)
        matches = re.findall('OK', response_desc)
        node_found = any(node_name in response_desc for node_name in node_names)
        if len(matches) == 1 and not node_found:
            nodes["all"] = 'OK'
        elif node_found:
            for node_name in node_names:
                if node_name in response_desc:
                    node_status = _check_response_for_node_result(node_name, response_desc)
                else:
                    node_status = 'OK'

                nodes[node_name] = node_status
        else:
            nodes['all'] = 'FAIL'

    else:
        nodes['all'] = 'FAIL'

    return nodes


def _check_response_for_node_result(node_name, response_desc):
    """
    B{Checks a string for a particular node name to see if 'OK' is specified after the name}

    @type node_name: string
    @param node_name: The name of the node to check for in the string
    @type response_desc: dict
    @param response_desc: The string to search for the node name and determine the result of the operation for.
    @rtype: string
    @return: 'OK' if OK was found beside the node name or 'FAIL' otherwise
    """

    end_index = response_desc.index(node_name) + len(node_name)
    node_result = response_desc[end_index: end_index + 4]

    if 'OK' in node_result:
        node_status = 'OK'
    else:
        ok_line = [line for line in response_desc.split('\n') if line == 'OK']
        node_status = 'FAIL'
        if len(ok_line) > 0:
            if 'OK' in ok_line:
                node_status = 'OK'

    return node_status


def _prepare_response(response, node_names=None):
    """
    B{Strips down the response to remove node names from the command in the response and 'Id's from the response text}

    :type response: shell.response object
    :param response: Response object retrieved from running the remote command
    :type node_names: list
    :param node_names: A list of node names the command was run against
    :rtype: string
    :returns: A formatted response
    """

    cmd_in_resp = ""
    if node_names:
        cmd_in_resp = response.stdout.split("\n")[0]
        for node_name in node_names:
            cmd_in_resp = re.sub(r'{}'.format(node_name), '___', cmd_in_resp)

        # put it all back together
        cmd_in_resp = "{}\n".format(cmd_in_resp)
        response_str = "{}{}".format(cmd_in_resp, "\n".join(response.stdout.split("\n")[1:]))
    else:
        response_str = response.stdout

    formatted_response = re.sub(r'Id:\s\d+\n', '', response_str)

    return formatted_response


def run_cmd(cmd, host, sim=None, node_names=None, password='netsim', executor_script_path="/tmp/command_executor.sh"):
    # This function should be merged with shell.run_remote_cmd or altered to state this function is only for running
    # towards netsims as the password is hardcoded and the below call to shell hardcode's the user also as netsim.
    # Make amendments as part of JIRA TORF-242378. Run_sim_cmd and run_ne_cmd need to be looked at during this change
    # along with removing calls to this function overiding the password to None to avoid the below password check
    """
    Runs a command on a given host.
    :param cmd: str, The command to be run
    :param host: str, The host the command is to be run on
    :param sim: str, The simulation you wish to use on the Netsim box
    :param node_names: list, A list of node_names you wish to use
    :param password: str, The password to the netsim host
    :param executor_script_path: str, path to the remote command_executor

    :return: shell.Response, a shell.Response instance
    """

    node_names = node_names or []

    if not password:
        password = 'netsim'

    key = "command-executor-is-on-netsim-host-{0}".format(host)

    if not cache.has_key(key):
        with mutexer.mutex("check-for-command-executor-on-host-{0}".format(host), persisted=True):
            if persistence.has_key(key):
                log.logger.debug("The key: '{0}' is already set in persistence by another profile so we are setting it "
                                 "in the cache here for this separate process as we don't need to redeploy the script".format(key))
                cache.set(key, True)
            else:
                local_path = os.path.join(NSSUTILS_PATH, "external_sources", "scripts", "command_executor.sh")
                deploy_script(host, local_path=local_path, remote_path=executor_script_path)
                log.logger.debug("The netsim executer script on host: '{0}' in location: '{1}' has been deployed successfully".format(host, executor_script_path))
                cache.set(key, True)
                persistence.set(key, True, 900)

    # Build up the command to be executed
    netsim_cmd = "{0} '{1}'".format(executor_script_path, cmd)

    if sim:
        netsim_cmd = "{0} '{1}'".format(netsim_cmd, sim)

        if node_names:
            if isinstance(node_names, list):
                node_names = " ".join(node_names)
            netsim_cmd = "{0} '{1}'".format(netsim_cmd, node_names)

    response = shell.run_remote_cmd(shell.Command(netsim_cmd, timeout=600), host, "netsim", password, add_linux_timeout=True, keep_connection_open=True)

    return response


def deploy_script(host, local_path, remote_path, permissions=755, user='netsim', password='netsim', force=False):
    """
    B{Ensures that the script is located on the netsim, if not it will upload it. Optionally changes permissions of file}
    @type host: string
    @param host: hostname of netsim target
    @type local_path: string
    @param local_path: path to local file
    @type remote_path: string
    @param remote_path: path to remote location
    @rtype: void
    """

    if force or not filesystem.does_remote_file_exist(remote_path, host, user, password) \
            or filesystem.get_local_file_checksum(local_path) != filesystem.get_remote_file_checksum(remote_path, host, user, password):

        shell.upload_file(local_path, remote_path, host, user, password)

        if not filesystem.does_remote_file_exist(remote_path, host, user, password):
            raise RuntimeError("Could not upload script on netsim")

        if permissions:
            response = shell.run_remote_cmd(shell.Command("chmod {0} {1}".format(permissions, remote_path)), host, user, password)
            if response.rc != 0:
                raise RuntimeError("Could notset permissions {0} to file {1}".format(permissions, local_path))


def check_nodes_started(nodes):
    """
    B{Runs the show started command and checks for the IP in the response}
    @type nodes: list
    @param nodes: List of nodes to check status of
    @rtype: list
    @return: list of nodes which are stopped
    """
    checked_nodes = []
    found_nodes = []
    nodes_dict = {}

    for host in set(node.netsim for node in nodes):
        nodes_dict[host] = [node for node in nodes if node.netsim == host]

    for host, node_list in nodes_dict.items():
        try:
            checked_nodes.extend(node_list)
            response = run_cmd(".show started", host)

            for node in node_list:
                match = re.search(r"\s{0}\s".format(node.node_ip), response.stdout)
                if match:
                    found_nodes.append(node)
        except Exception as e:
            raise Exception("Failed to connect to netsim {0}: {1}".format(host, e.message))
    return set(checked_nodes) - set(found_nodes)
