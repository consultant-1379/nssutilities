import os
import sys

from fabric.api import env, run, prefix
from fabric.context_managers import cd, settings
from fabric.contrib.files import exists, append, comment
from fabric.contrib.project import rsync_project
from fabric.operations import get, put
from unipath import Path

VENV_DIR_NAME = '.env'
NSSUTILS_PROJECT_DIR_NAME = 'ERICnssutilities_CXP9035994'
PROD_BIN_DIR = "/opt/ericsson/nssutils/bin/"


def copy_new(clean='False', jenkins='False'):
    """
    Usage: fab copy_new remote_dir:<name_of_dir>

    @type clean: string
    @param clean: Option to remove the target directory on the remote MS before copying
    @type jenkins: bool
    @param jenkins: Boolean to indicate if jenkins server used or not

    Either provide the host as a global env var in env.hosts in this
    module above or enter host on the command line as hosts:<host>. If
    host is not found, it will be prompted for on the command line.
    """

    if clean == "True":
        run("rm -rf {0}".format(env.project_root))

    run("mkdir -p {0}".format(env.project_root))

    local_project_path = Path(__file__).ancestor(4)
    if jenkins == "True":
        put(local_path=local_project_path.child(NSSUTILS_PROJECT_DIR_NAME), remote_path=env.project_root,
            mirror_local_mode=True)
    else:
        rsync_project(remote_dir=env.project_root, local_dir=os.path.join(local_project_path, ''), delete=False,
                      extra_opts='-ra', exclude=("*.doc", "*.pyc", "*.idea", "*.git", "*.egg-info", "*.env",
                                                 "test-results"))


def ensure_pip():
    """
    Ensure that pip is installed on the remote host
    """
    with settings(warn_only=True):
        result = run('which pip')
    if result.return_code != 0:
        run('easy_install --no-deps {0}'.format(env.epp.child('pip-6.1.1-py2.7.egg')))


def ensure_virtualenv():
    """
    Ensure that virtualenv is installed on the remote host
    """

    ensure_pip()

    # If '.env' is already installed return
    if exists('{0}/bin'.format(env.venv)):
        return

    python27_path = '/opt/ericsson/nssutils/.env/bin/python2.7'

    # Defaults to centos 6.4 system python 2.6.6
    interpreter = '/usr/bin/python'

    run('pip install {0}'.format(env.epp.child('virtualenv-1.11.6-py2.py3-none-any.whl')))

    # If production rpm is installed with python 2.7.x, use that interpreter
    if exists(python27_path):
        interpreter = python27_path

    # Change to project root directory and install virtualenv with the specified interpreter
    with cd(env.project_root):
        run("virtualenv --no-site-packages -p {0} {1}".format(interpreter, env.venv))


def change_local_prop(prop_name, prop_val):
    """
    Change the ENVIRON from 'local' to 'testing'  in the local properties file

    @type prop_name: string
    @param prop_name: The property name to look for in the file
    @type prop_val: string
    @param prop_val: The property value to replace with in the file
    """
    local_props_file = env.project_root.child(NSSUTILS_PROJECT_DIR_NAME, 'nssutils', 'local_properties.py')

    # Change to the parent root directory an
    with cd(env.project_root):
        prop_name = prop_name.upper()
        # Find 'ENVIRON' pattern in the local props file and comment the line away
        comment(local_props_file, r"^{0}\s*=".format(prop_name))
        prop_string = '{0}="{1}"'.format(prop_name, prop_val)
        # Add a new string pattern to the file
        append(local_props_file, prop_string)


def deploy(remote_dir, clean='False', jenkins='False'):
    """
    Copy the code to a remote server and enable virtualenv

    @type remote_dir: string
    @param remote_dir: The remote directory to deploy the code on
    @type clean: string
    @param clean: Option to remove the target directory on the remote MS before copying
    @type jenkins: string
    @param jenkins: Boolean to indicate if jenkins server used or not
    """

    # Get all the necessary paths on the remote host
    env.project_root = Path(remote_dir)
    env.venv = env.project_root.child(VENV_DIR_NAME)
    nssutils_path = env.project_root.child(NSSUTILS_PROJECT_DIR_NAME)
    env.epp = nssutils_path.child('nssutils', '3pp')

    # Copy the code
    copy_new(clean=clean, jenkins=jenkins)

    # Change the ENVIRON from 'local' to 'testing'  in the local properties file
    change_local_prop("ENVIRON", "testing")

    # Ensure that virtualenv is enabled and installed
    ensure_virtualenv()

    # We need to activate the virtualenv first in order to install production and internal packages.
    # Deactivate when done
    with prefix('source {0}/bin/activate'.format(env.venv)):
        with cd(env.project_root):
            # Install the production lib package
            run('pip install --no-index --find-links={0} --ignore-installed --editable {1}'
                .format(env.epp, nssutils_path))


def run_acceptance(remote_dir, clean='False', jenkins='False'):
    """
    Copy the code to a remote server and enable virtualenv and run acceptance tests
    @type remote_dir: string
    @param remote_dir: The remote directory to deploy the code on
    @type clean: str
    @param clean: Option to remove the target directory on the remote MS before copying
    @type jenkins: str
    @param jenkins: Boolean to indicate if jenkins server used or not
    """
    out_path = '.'  # Current path on jenkins build directory
    remote_log_path = os.path.join(remote_dir, 'test-results/allure-results')

    deploy(remote_dir=os.path.join(remote_dir), clean=clean, jenkins=jenkins)

    # Activate the virtualenv and run acceptance job
    with prefix('source {0}/bin/activate'.format(env.venv)):
        with settings(warn_only=True):
            result = run('tester acceptance --root_path=%s' % remote_dir)

    # Get allure reports from the server
    get(remote_path=remote_log_path, local_path=out_path)

    sys.exit(result.return_code)


def remove_persisted_key(key, index="0", force="false"):
    """
    Runs the persistence tool out of production directory to clear the specified key

    @type key: string
    @param key: The key in persistence to remove
    @type index: string
    @param index: Optional argument to remove the key from a specific persistence index
    @type force: string
    @param force: Optional argument to remove the key using force flag
    """

    if force == "false":
        run(os.path.join(PROD_BIN_DIR, "persistence") + ' remove ' + key + " --index=" + index)
    else:
        run(os.path.join(PROD_BIN_DIR, "persistence") + ' remove ' + key + " --index=" + index + " force")


def delete_persisted_node_list(node_file_path=None):
    """
    Runs the node populator tool out of production directory to delete the specified list of nodes

    @type node_file_path: string
    @param node_file_path: The absolute path to the list of nodes in persistence to delete,
    @returns: Integer to indicate return code
    @rtype: int
    """
    with prefix('source {0}/bin/activate'.format(env.venv)):
        if not node_file_path:
            run(('node_populator delete /root/nssutilities/jenkins/ERICnssutilities_CXP9035994/nssutils'
                 '/tests/etc/network_nodes/acceptance_list'))
        else:
            run('node_populator delete ' + node_file_path)
    return 0


def get_remote_files(remote_path, local_path):
    """
    Get files from remote server
    @type remote_path: string
    @param remote_path: Absolute path to directory or file on remote server
    @type local_path: string
    @param local_path: Path where files should be stored locally
    example:
        fab -f 'ERICnssutilities_CXP9035994/nssutils/lib/fabfile.py' -H
        root@$remote_hostname get_remote_files:remote_path='/root/nssutilities/jenkins/logs',local_path='.'"""
    get(remote_path=remote_path, local_path=local_path)


def acceptance_test_setup(remote_dir, clean='False', jenkins='False', simulations=None, start=False, fetch=False):
    """
    Runs the netsim tool  directory to start the specified simulations

    @type remote_dir: string
    @param remote_dir: Absolute path to directory or file on remote server
    @type simulations: str
    @param simulations: Optional string of simulations i.e. "LTE01;LTE02"
    @type start: bool
    @param start: True if we want to start the simulations
    @type fetch: bool
    @param fetch: True if we want to fetch and parse the acceptance simulations
    @type jenkins: bool
    @param jenkins: Boolean to indicate if jenkins server used or not
    @type clean: string
    @param clean: Option to remove the target directory on the remote MS before copying
    """
    simulations = simulations or []
    deploy(remote_dir=os.path.join(remote_dir), clean=clean, jenkins=jenkins)

    default_simulations = {"LTEJ1180-limx40-1.8K-FDD-LTE05": [1, 20], "LTEH1160-V2limx40-1.8K-FDD-LTE03": [1, 40],
                           "LTEH1160-V2limx40-1.8K-FDD-LTE08": [1, 40], "CORE-ST-4.5K-SGSN-16A-CP01-V1x4": [1, 1],
                           "CORE-3K-ST-MGw-C1214-16Ax2": [1, 1]}
    parsed_nodes_dir = "/var/nssutils/acceptance_list"
    with prefix('source {0}/bin/activate'.format(env.venv)):
        sims = default_simulations.keys() if not simulations else simulations.split(";")

        with settings(warn_only=True):
            if start:
                result = run('netsim start netsim {0}'.format(",".join(sims)))
                if result.return_code != 0:
                    _copy_netsim_id_and_restart_netsim(",".join(sims))
            dir_not_exists = run('ls {0}'.format(parsed_nodes_dir))
            if dir_not_exists:
                run("mkdir -p /var/nssutils ; touch /var/nssutils/acceptance_list")
                if fetch:
                    position = 0
                    for sim in sims:
                        _fetch_and_parse_nodes(sim)
                        if position == 0:
                            run('sed -n 1,1p {0} > {1}'.format("{0}{1}".format("/root/nssutils/jenkins/"
                                                                               "ERICnssutilities_CXP9035994/int/nodes/",
                                                                               sims[0]), parsed_nodes_dir))
                            position += 1
                        start = end = 0
                        if len(default_simulations.get(sim)) > 1:
                            start, end = default_simulations.get(sim)[0], default_simulations.get(sim)[1]
                        _create_nodes_and_write_acceptance_list(sim, range_start=start, range_end=end)
                        result = run('network netsync')
                    if result.return_code != 0:
                        run('/opt/ericsson/enminst/bin/vcs.bsh --restart -g Grp_CS_svc_cluster_cmserv')
                        run('network netsync')


def _fetch_and_parse_nodes(sim, rpm=False):
    """
    Fetch and parse the provided simulation

    :type rpm: bool
    :param rpm: Boolean to indicate if rom is being used or not
    :type sim: str
    :param sim: Name of the simulation to be fetched and parse

    """
    root_dir = "/opt/ericsson/nssutils/bin/" if rpm else ""
    fetched_nodes_dir = "/tmp/{0}".format(sim)
    result = run('netsim fetch netsim {0} {1}'.format(sim, fetched_nodes_dir))
    if result.return_code != 0:
        _copy_netsim_id_and_restart_netsim(sim)
        run('netsim fetch netsim {0} {1}'.format(sim, fetched_nodes_dir))
    result = run('{2}node_populator parse {0} {1}'.format(sim, fetched_nodes_dir, root_dir))
    if result.return_code != 0:
        run('/opt/ericsson/enminst/bin/vcs.bsh --restart -g Grp_CS_svc_cluster_cmserv')
        run('{2}node_populator parse {0} {1}'.format(sim, fetched_nodes_dir, root_dir))


def _create_nodes_and_write_acceptance_list(sim, range_start=0, range_end=0):
    """
    Create node(s) on enm and, write the created nodes, to the acceptance list

    :type sim: str
    :param sim: Name of the simulation to perform the  creation upon
    :type range_start: int
    :param range_start: Index of the node, to execute the create function from
    :type range_end: int
    :param range_end: Index of the node, to execute the create function to

    """
    parsed_nodes_dir = "/var/nssutils/acceptance_list"
    jenkins_nodes = "/root/nssutils/jenkins/ERICnssutilities_CXP9035994/int/nodes/"
    if range_start or range_end:
        run(('node_populator create {0} {1}-{2}'.format(sim, range_start, range_end)))
        run('sed -n {0},{1}p {2} >> {3}'.format(range_start + 1, range_end + 1, "{0}{1}".format(jenkins_nodes, sim),
                                                parsed_nodes_dir))
    else:
        run(('node_populator create {0}'.format(sim)))
        run('cat /tmp/{0} >> {1}'.format("{0}/{1}".format(jenkins_nodes, sim), parsed_nodes_dir))


def _copy_netsim_id_and_restart_netsim(sims):
    """
    Method to copy the netsim ssh key, restart the netsim, and start the simulations provided

    :param sims: str, Simulation or comma separated list of simulations to start
    :type sims: str

    """
    with settings(prompts={'Password: ': 'netsim'}):
        run('ssh-copy-id netsim@netsim')
    run('ssh netsim@netsim \'inst/restart_netsim\'')
    run('netsim start netsim {0}'.format(sims))


def run_performance_tests(rpm, remote_dir, clean='False', jenkins='False'):
    """
    Executes the tool performance tests

    :type rpm: str
    :param rpm: Version of the rpm to be downloaded and installed.
    :type remote_dir: str
    :param remote_dir: Absolute path to directory or file on remote server
    :type clean: str
    :param clean: Override the existing directory
    :type jenkins: str
    :param jenkins: Use the default jenkins directory
    """

    wget_cmd = ('wget https://arm1s11-eiffel004.eiffel.gic.ericsson.se:8443/nexus/content/repositories/releases/com/ericsson/'
                'ci/nss/ERICnssutilities_CXP9035994/{0}/ERICnssutilities_CXP9035994-{0}.rpm'.format(rpm))
    deploy(remote_dir=os.path.join(remote_dir), clean=clean, jenkins=jenkins)
    with prefix('source {0}/bin/activate'.format(env.venv)):
        run('{0}; rpm -Uvh --replacepkgs --oldpackage ERICnssutilities_CXP9035994-{1}.rpm'.format(wget_cmd, rpm))
        run('tester performance')
