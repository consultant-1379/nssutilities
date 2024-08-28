import os
import sys
import time
import random
import subprocess
import multiprocessing
import pstats
import unipath
import pkgutil
import StringIO
import datetime
import re
from time import strftime
from nssutils.lib import log, filesystem, shell
from nssutils.tests import test_utils
from nssutils.lib.enm_user_2 import get_or_create_admin_user
from nssutils.lib.netsim_mgr import get_all_simulations_on_netsim


WORKER_PRINT_LOCK = multiprocessing.Lock()

RESULTS_DIR = "test-results"
DEFAULT_USER = 'root'
NOSETESTS_PATH = os.path.join(os.path.dirname(sys.executable), "nosetests")

NSSUTILS_PATH = unipath.Path(pkgutil.get_loader('nssutils').filename)
FABFILE = NSSUTILS_PATH.child('lib', 'fabfile.py')
COVERAGE_RC_FILE = os.path.abspath(os.path.join(NSSUTILS_PATH, "etc", "tester", "coverage.rc"))

# ALLURE
ALLURE_JAR = os.path.join(NSSUTILS_PATH, "etc", "tester", "allure-cli.jar")
ENVIRONMENT_XML = os.path.join(NSSUTILS_PATH, "etc", "tester", "environment.template")
ALLURE_REPORT_GENERATION_CMD = "java -jar \"{0}\" report generate \"{1}\" -o \"{2}\" -v 1.4.15"
SERVE_ALLURE_REPORT_CMD = "java -jar \"{0}\" report open -o \"{1}\""
ALLURE_TEST_CMD = NOSETESTS_PATH + " --nologcapture --with-allure --logdir={0} {1}"
ALLURE_RESULT_THREAD_UPDATE_CMD = """find {0} -name \"*-testsuite.xml\" -print | xargs perl -i -pe \"s|<labels/>|<labels><label name=\\"thread\\" value=\\"root\\@localhost.{1}({2})\\"/></labels>|g\""""
ALLURE_RESULTS_DIR = os.path.join(RESULTS_DIR, "allure-results")

# UNIT TESTS
# more about below flags here: http://nose.readthedocs.io/en/latest/usage.html#extended-usage
FAST_UNIT_TEST_CMD = NOSETESTS_PATH + " -v -d --exe --processes=-1 {dirs}"
UNIT_TEST_CMD = NOSETESTS_PATH + " -v -d --exe --with-coverage --cover-min-percentage={cover_min_percentage} --cover-package={packages} --cover-erase --cover-branches --cover-config-file={cover_config_path} {dirs}"
UNIT_SINGLE_TEST_CMD = NOSETESTS_PATH + " -v -d --exe  --tests={modules} --with-coverage --cover-min-percentage={cover_min_percentage} --cover-package={packages} --cover-erase --cover-branches --cover-config-file={cover_config_path}"
PROFILED_UNIT_TEST_CMD = NOSETESTS_PATH + " -v -d --exe --with-coverage --cover-min-percentage={cover_min_percentage} --cover-package={packages} --cover-erase --cover-branches --cover-config-file={cover_config_path} --with-cprofile --cprofile-stats-erase --profile-stats-file={stats_file} {dirs}"

# COVERAGE COMMAND
COVERED_THROUGH_ACCEPTANCE_TESTS = '*alarm_routing*'
COVERAGE_CMD = "coverage combine; coverage html -d {html_dir} -i --omit=*test.py,*logger*,*fabfile.py,*default_configurations*,*deprecated*,*__init__.py,*enm_role.py,{accept_tests}"

# PEP CHECKS
PEP_CHECK_CMD = "pep8 --ignore=E501,W601,E401 {0}"

# PYLINT CHECKS
PYLINT_RC_FILE = os.path.abspath(os.path.join(NSSUTILS_PATH, "etc", "tester", "pylint.rc"))
PYLINT_LOAD_PLUGINS = "pylint.extensions.docparams"
PYLINT_CHECK_CMD = "pylint --load-plugins={0} --rcfile={1} {2}"

# MAX WORKERS (This is the number of test processes that will run in parallel)
MAX_WORKERS = 16
RESULTS_PATH = ''

# COLOR TEXT
RED_TEXT = '\033[91m'
GREEN_TEXT = '\033[92m'
PURPLE_TEXT = '\033[95m'
YELLOW_TEXT = '\033[33m'
NORMAL_TEXT = '\033[0m'

IGNORED_FILES = ['__init__.py', 'tester.py', 'test.py', '/lib/schedules', 'fabfile.py']
COMMON_LIB = "nssutils/lib"
FILES_TO_CHECK = "enm_node.py,enm_role.py,enm_user_2.py,load_node.py,profile.py"

# Performance Test
BASELINE_RPM = "1.0.9"
TOOL_AND_COMMANDS = {
    "netsim": [
        "netsim stop netsim {simulations}", "netsim start netsim {simulations}", "netsim restart netsim {simulation}",
        "netsim list netsim {simulations}", "netsim info netsim {simulations}",
        "netsim fetch netsim {simulations} performance_nodes", "netsim activities netsim {simulation}",
        "netsim cli netsim {simulation} all showscanners"
    ]
}


# Used for nose-timer plugin
TIMER_OK_LIMIT = "1s"

######################
# SOURCE CODE CHECKS #
######################


def _get_modified_python_files(git_repo_dir):
    """
    Return a list of all modified files in the repo

    :param git_repo_dir: path to the git repository root
    :rtype: list[string]

    """

    (rc, stdout) = _execute_command("cd {0}; git diff --cached --name-status".format(os.path.abspath(git_repo_dir)))
    if rc:
        raise RuntimeError("Could not get list of modified files ({rc}): {error}".format(rc=rc, error=stdout))

    modified_files = set()

    for line in stdout.strip().splitlines():
        modification_type, file_path = line.split()
        if modification_type != "D" and file_path.endswith(".py") and not any(f in file_path for f in IGNORED_FILES):
            modified_files.add(os.path.abspath(file_path))

    return modified_files


def _get_acceptance_tests(dirs, modules=None, unit=None):
    """
    Gets all acceptance tests if none specified in modules

    :param dirs: list of directories to look for acceptance tests
    :param modules: comma separated list of test modules
    :type unit: bool
    :param unit: Flag indicating that the modules are unit tests

    :return: acceptance tests list
    """
    tests = []
    acceptance_prefix = "a_tests_" if not unit else "u_tests_"
    if modules:
        module_names = [acceptance_prefix + module if acceptance_prefix not in module else module for module in modules.split(",")]
    else:
        module_names = [acceptance_prefix]

    for dirname in dirs:
        for module_name in module_names:
            filtered = _get_filtered_files(dirname, filter_name=lambda file_name, m=module_name: file_name.startswith(m) and file_name.endswith(".py"))
            tests.extend(filtered)
    return list(set(tests))


def _get_all_python_files_in_repo(root_path, exclude_dirs=None):
    """
    Build a list of the python modules we want to check in the local repository

    :param root_path: root path to walk to discover Python source modules
    :param exclude_dirs: list of directory paths to exclude

    :return: A tuple where: index 0 is a boolean indicating whether Windows line endings were found; index 1 is a message to be displayed on error
    :rtype: Tuple

    """

    python_files = []
    if exclude_dirs is None:
        exclude_dirs = []

    def filter_name(file_name):
        return file_name.endswith(".py") and not any(f in file_name for f in IGNORED_FILES)

    filtered = _get_filtered_files(root_path, filter_name=filter_name, exclude_dirs=exclude_dirs)
    python_files.extend(filtered)
    return python_files


def _get_filtered_files(directory, filter_name, exclude_dirs=None):
    """
    :param directory: path to the directory
    :param filter_name: callable for filtering the paths, must take single arg file name
    :exclude_dirs: list of directory names to be excluded
    """
    filtered = []

    for (dirpath, dirnames, files) in os.walk(directory):
        if exclude_dirs is not None:
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs and not d.startswith('.')]
        for file_name in files:
            if filter_name(file_name):
                filtered.append(os.path.abspath(os.path.join(dirpath, file_name)))

    return filtered


def _check_line_endings(file_name):
    """
    Checks if any files in the list contain Windows line endings

    :param file_name: Absolute path of the file to be checked
    :type file_name: string

    :return: A tuple where: index 0 is a boolean indicating whether Windows line endings were found; index 1 is a message to be displayed on error
    :rtype: Tuple

    """

    found_windows_lines = False
    msg = ""

    (rc, _) = _execute_command("file {0} | grep -E 'CRLF line terminators|\015'".format(file_name))
    if rc == 0:
        msg = "ERROR: File {0} has Windows line endings".format(file_name)
        found_windows_lines = True

    return (found_windows_lines, msg)


def check_line_endings(files_to_check):
    """
    Checks source code modules for UNIX line terminators

    :param files_to_check: List of absolute file paths of source modules to be checked
    :type files_to_check: list

    :rtype: boolean

    """

    line_ending_result = True

    print "\n**************************************"
    print "* CHECKING FOR UNIX LINE TERMINATORS *"
    print "**************************************\n"

    # Create a pool of processes to execute the modules
    return_tuples = _pool(_check_line_endings, files_to_check)

    for return_tuple in return_tuples:
        if return_tuple[0]:
            line_ending_result = False
            print "{0}{1}{2}".format(RED_TEXT, return_tuple[1], NORMAL_TEXT)

    if line_ending_result:
        print "{0}All modules have UNIX line terminators{1}".format(GREEN_TEXT, NORMAL_TEXT)
    else:
        print "\n{0}One or more modules does not have proper UNIX line terminators{1}".format(RED_TEXT, NORMAL_TEXT)

    return line_ending_result


def _execute_pep_check(file_name):
    """
    Checks each source file for PEP violations

    :param file_name: Absolute path of the file to be checked
    :type file_name: string

    :return: Tuple where: index 0 is a boolean indicating whether check was successful or not; index 1 is a message to be displayed on error
    :rtype: Tuple

    """

    check_successful = False
    msg = ""

    (rc, stdout) = _execute_command(PEP_CHECK_CMD.format(file_name))

    if rc == 0:
        check_successful = True
    else:
        msg = "{0}PEP8 checks for file {1} failed:\n{2}{3}".format(RED_TEXT, file_name, NORMAL_TEXT, stdout)

    return (check_successful, msg)


def execute_pep_checks(files_to_check):
    """
    Checks source code modules for PEP code format violations

    :param files_to_check: List of absolute file paths of source modules to be checked
    :type files_to_check: list

    :return: Whether the pep checks ran or not
    :rtype: boolean

    """

    pep_result = True

    print "\n******************************************"
    print "* CHECKING FOR PEP FORMATTING VIOLATIONS *"
    print "******************************************\n"

    # Create a pool of processes to execute the modules
    return_tuples = _pool(_execute_pep_check, files_to_check)

    for return_tuple in return_tuples:
        if not return_tuple[0]:
            pep_result = False
            print return_tuple[1]

    if pep_result:
        print "{0}All module PEP checks have passed{1}".format(GREEN_TEXT, NORMAL_TEXT)
    else:
        print "\n{0}One or more module have PEP code formatting violations{1}".format(RED_TEXT, NORMAL_TEXT)

    return pep_result


def _execute_pylint_check(pylint_input_data):
    """
    Checks each source file for Pylint syntax violations

    :param pylint_input_data: Tuple containing string (absolute path of the file to be checked) and boolean (to indicate if docstring check to be performed or not)
    :type pylint_input_data: tuple

    :return: Whether the pylint checks ran or not
    :rtype: Tuple where: index 0 is a boolean indicating whether check was successful or not; index 1 is a message to be displayed on error

    """

    check_successful = False
    msg = ""

    file_name, pylint_docstring_check = pylint_input_data

    load_plugins = PYLINT_LOAD_PLUGINS if pylint_docstring_check else ""
    (rc, stdout) = _execute_command(PYLINT_CHECK_CMD.format(load_plugins, PYLINT_RC_FILE, file_name))

    if rc == 0:
        check_successful = True
    else:
        msg = "{0}Pylint checks for file {1} failed:\n{2}{3}".format(RED_TEXT, file_name, NORMAL_TEXT, stdout)

    return (check_successful, msg)


def execute_pylint_checks(files_to_check, pylint_docstring_check):
    """
    Checks source code modules for Pylint syntax violations

    :param files_to_check: List of absolute file paths of source modules to be checked
    :type files_to_check: list
    :param pylint_docstring_check: bool to indicate if extra docstring checks are to be performed
    :type pylint_docstring_check: bool

    :return: True or False whether the checks ran or not
    r:type: boolean

    """

    pylint_result = True

    print "\n*****************************************"
    print "* CHECKING FOR PYLINT SYNTAX VIOLATIONS *"
    print "*****************************************\n"

    # Create a pool of processes to execute the modules
    pylint_input = zip(files_to_check, [pylint_docstring_check for _ in files_to_check])
    return_tuples = _pool(_execute_pylint_check, pylint_input)

    for return_tuple in return_tuples:
        if not return_tuple[0]:
            pylint_result = False
            print return_tuple[1]

    if pylint_result:
        print "{0}All module Pylint checks have passed{1}".format(GREEN_TEXT, NORMAL_TEXT)
    else:
        print "\n{0}One or more module have Pylint syntax violations{1}".format(RED_TEXT, NORMAL_TEXT)

    return pylint_result


#########################
# COMMON TEST FUNCTIONS #
#########################
def _execute_test(test_module):
    """
    Run a single acceptance test module using an available test index

    :param test_module: The name of the test module to execute
    :type test_module: string

    :return: The return code from function "_execute_command"
    :rtype: int

    """

    # If this is the first test executed by this process, sleep for a small, random amount of time
    if "TEST_SLEEP_DONE" not in os.environ:
        time.sleep(random.random())
        os.environ["TEST_SLEEP_DONE"] = "TEST_SLEEP_DONE"

    # Get what we need to create the full allure test command (test name and results dir)
    module_name = os.path.basename(test_module).replace(".py", "")

    result_dir = os.path.join(RESULTS_PATH, ALLURE_RESULTS_DIR, module_name)

    cmd = ALLURE_TEST_CMD.format(result_dir, test_module)

    WORKER_PRINT_LOCK.acquire()
    print "Executing test module {0}{1}{2} [PID {3}]...".format(PURPLE_TEXT, module_name, NORMAL_TEXT, os.getpid())
    WORKER_PRINT_LOCK.release()

    try:
        # Get an available test DB index from the index pool
        index = test_utils.get_test_db_index()

        # Set an environment variable indicating which DB test index the worker process should use
        cmd = "export REDIS_DB_INDEX={0}; {1}".format(index, cmd)

        # Execute the test
        (rc, output) = _execute_command(cmd)
    finally:
        # Return the test DB index to the index pool
        test_utils.return_test_db_index(index)

    # Update the result XML file with the name of the module for the timeline
    cmd = ALLURE_RESULT_THREAD_UPDATE_CMD.format(result_dir, module_name, os.getpid())
    (_, dummy) = _execute_command(cmd)

    WORKER_PRINT_LOCK.acquire()
    if rc == 0:
        print "{0}  Test module {1} finished with return code {2} [PID {3}]...{4}".format(GREEN_TEXT, test_module, rc, os.getpid(), NORMAL_TEXT)
    else:
        print "{0}  Test module {1} finished with return code {2} [PID {3}]...{4}".format(RED_TEXT, test_module, rc, os.getpid(), NORMAL_TEXT)

        if rc != 1 and output is not None and len(output) > 0:
            print "\n{0}\n".format(output)
    WORKER_PRINT_LOCK.release()

    # Return the rc so that the main process can determine if everything ran fine or not
    return rc


def _generate_allure_report(results_dir):
    """
    Generates the Allure report from all of the test result XML files

    :rtype: None

    """

    xml_path = None
    report_path = None
    jar_path = None
    cmd = None
    result = False

    # Build the absolute paths
    xml_path = os.path.abspath(os.path.join(results_dir, ALLURE_RESULTS_DIR))
    report_path = os.path.abspath(os.path.join(results_dir, RESULTS_DIR, "report"))
    jar_path = os.path.abspath(ALLURE_JAR)

    if None not in [xml_path, report_path, jar_path]:
        cmd = ALLURE_REPORT_GENERATION_CMD.format(jar_path, xml_path, report_path)

    if cmd is not None:
        print "\nGenerating Allure report..."
        (rc, stdout) = _execute_command(cmd)

        if rc == 0:
            print "Allure report generated successfully"
            print "\nReport can be found at {0}{1}{2}".format(PURPLE_TEXT, report_path, NORMAL_TEXT)
            print "Acceptance test report can be served for local or remote viewing by re-runnng the tester tool with the {0}view-report{1} operation\n".format(PURPLE_TEXT, NORMAL_TEXT)
            result = True
        else:
            print "{0}ERROR: Could not generate Allure report{1}".format(RED_TEXT, NORMAL_TEXT)
            print stdout
    else:
        print "{0}ERROR: Unable to compile Allure test report after test execution{1}".format(RED_TEXT, NORMAL_TEXT)

    return result


def _update_environment_info(results_dir):
    """
    Adds information to the Allure report about the test environment, code versions, etc.

    :rtype: None

    """

    # Read in the template environment.xml
    file_contents = None
    with open(ENVIRONMENT_XML, "r") as handle:
        file_contents = handle.read()

    if file_contents is not None:
        # Fetch the values we want to inject into the report
        (_, hostname) = _execute_command("hostname -f")
        hostname = hostname.strip()

        (_, ms_ip) = _execute_command("/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'")
        if not ms_ip:
            (_, ms_ip) = _execute_command("/sbin/ifconfig br0 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'")

        # Get the ENM ISO version
        (rc, enm_build) = _execute_command("find /var/tmp -name ERICenm_CXP*.iso -print | sort | grep -E '[0-9]+.[0-9]+.[0-9]+.iso' | tail -1 | sed -e 's/.*-//g' | sed -e 's/.iso//g'")
        if rc == 0 and len(enm_build) > 0:
            enm_build = enm_build.strip()
            file_contents = file_contents.replace("%%build%%", enm_build)
        else:
            # If we couldn't get the ISO version from the above directory try this one
            (rc, enm_build) = _execute_command("find /software/autoDeploy -name ERICenm_CXP*.iso -print | sort | grep -E '[0-9]+.[0-9]+.[0-9]+.iso' | tail -1 | sed -e 's/.*-//g' | sed -e 's/.iso//g'")
            enm_build = enm_build.strip()
            file_contents = file_contents.replace("%%build%%", enm_build)

        # Get the LITP ISO version
        (rc, litp_build) = _execute_command("find /var/tmp -name ERIClitp*.iso -print | sort | grep -E '[0-9]+.[0-9]+.[0-9]+.iso' | tail -1 | sed -e 's/.*-//g' | sed -e 's/.iso//g'")
        if rc == 0 and len(litp_build) > 0:
            litp_build = litp_build.strip()
            file_contents = file_contents.replace("%%litp_build%%", litp_build)
        else:
            # If we couldn't get the ISO version from the above directory try this one
            (rc, litp_build) = _execute_command("find /software/autoDeploy -name ERIClitp*.iso -print | sort | grep -E '[0-9]+.[0-9]+.[0-9]+.iso' | tail -1 | sed -e 's/.*-//g' | sed -e 's/.iso//g'")
            litp_build = litp_build.strip()
            file_contents = file_contents.replace("%%litp_build%%", litp_build)

        base_dir = os.path.abspath(os.path.join(NSSUTILS_PATH, "..", ".."))

        (rc, rpm_version) = _execute_command("rpm -qa | grep ERICnssutilities_CXP")
        if rc == 0:
            version = re.search('-([0-9]*.[0-9]*.[0-9]*)', rpm_version)
            file_contents = file_contents.replace("%%rpm_version%%", version.group(1))

        # Get the current date for the report
        current_time = strftime("%m-%d-%Y %H:%M:%S")

        # Replace the templated values with actual values
        file_contents = file_contents.replace("%%hostname%%", hostname).replace("%%directory%%", base_dir).replace("%%date%%", current_time).replace("%%ms_ip%%", ms_ip)

        # Write the file out into the Allure XML directory
        with open(os.path.join(results_dir, ALLURE_RESULTS_DIR, "environment.xml"), "w") as handle:
            handle.write(file_contents)


def _clear_test_results_dir(results_dir):
    """
    Clears the test results directory before running tests

    :rtype: None

    """

    # Clear out the test results directory
    msg = "Clearing test results directory {0}{1}{2}\n".format(PURPLE_TEXT, RESULTS_DIR, NORMAL_TEXT)
    if log.logger is not None:
        log.logger.info(msg)
    else:
        print msg
    _execute_command("rm -rf {0}/*".format(os.path.abspath(os.path.join(results_dir, RESULTS_DIR))))


def _execute_command(cmd):
    """
    Run a local command and return the rc and stdout

    :param cmd: The local command to be run as a python subprocess
    :type cmd: string

    :return: Tuple where index 0 is return code and index 1 is stderr merged into stdout
    :rtype: Tuple

    """

    log.logger.debug("Running local command '{0}'".format(cmd))
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, close_fds=True)
    stdout = process.communicate()[0]
    process.stdout.close()
    return process.returncode, stdout


def _pool(target, work_items, test_pool_timeout=None, max_num_test_processes=None):
    """
    Creates a worker pool to work through the passed work items in parallel

    :param target: Callable to be invoked by each worker for each work item
    :type target: callable
    :param max_num_test_processes: Maximum number of processes to create for testing executions
    :type max_num_test_processes: int
    :param work_items: List of work items; each invocation of the target callable will be passed one value from this list
    :type work_items: list
    :param test_pool_timeout: integer timeout value within which the test suite should complete
    :type test_pool_timeout: int

    :return: List of results returned from each invocation of the callable
    :rtype: list

    """

    # Figure out how many workers we need
    pool_size = (multiprocessing.cpu_count() * 2)
    if len(work_items) < pool_size:
        pool_size = len(work_items)

    # Check if we are overriding max workers in props
    if max_num_test_processes:
        pool_size = max_num_test_processes
    else:
        # Make sure we don't exceed the maximum number of workers
        if pool_size > MAX_WORKERS:
            pool_size = MAX_WORKERS

    log.logger.debug("Creating pool size of {0} processes to run tests".format(pool_size))
    pool = multiprocessing.Pool(pool_size)
    if not test_pool_timeout:
        test_timeout = 4000
    try:
        results_to_check = pool.map_async(target, work_items)
        return results_to_check.get(test_timeout)
    except multiprocessing.TimeoutError:
        log.logger.error("\n{0}ERROR: Test execution pool has exceeded timeout of {1}s{2}".format(RED_TEXT, test_timeout, NORMAL_TEXT))
        print "\n{0}ERROR: Test execution pool has exceeded timeout of {1}s{2}".format(RED_TEXT, test_timeout, NORMAL_TEXT)
        return [1]
    finally:
        pool.terminate()
        pool.join()


########
# COPY #
########

def _check_passwordless_access(remote_ms, port=22):
    """
    Checks if the client has passwordless access to the remote MS

    :param remote_ms: The IP of the remote MS
    :type remote_ms: string

    :return True or False whether passwordless access is available to the client
    :rtype: boolean

    """
    result = False

    ssh_cmd = "/usr/bin/ssh -p {0} -o PreferredAuthentications=publickey -o ConnectTimeout=5 -o StrictHostKeyChecking=no {1}@{2} ls".format(port, DEFAULT_USER, remote_ms)
    (rc, _) = _execute_command(ssh_cmd)
    if rc == 0:
        result = True

    return result


##############################
# PUBLIC OPERATION FUNCTIONS #
##############################

def copy(remote_host, remote_dir, clean_remote_dir, common_repo_path=None):
    """
    Copies source code from the local git repository to the specified directory on the remote host

    :param remote_host: IP address or hostname of remote host. If you want to connect to a specific port use xx.xx.xx.xx:<Port>
    :type remote_host: string
    :param remote_dir: Absolute path of the directory on the remote host that the local code repository will be copied to
    :type remote_dir: string
    :param clean_remote_dir: Flag controlling whether remote directory is deleted before code is copied over
    :type clean_remote_dir: boolean

    :return: A return code (0 on success; 1 on copy fail; 2 if remote host is not available)
    :rtype: int

    """

    host, port = remote_host, 22
    if ':' in remote_host:
        host, port = remote_host.split(':')

    if not _check_passwordless_access(host, port):
        print """Couldn't gain access to the remote host: {1} on port: {2}. You need passwordless access to copy files.
        Run: 'ssh-copy-id {0}@{1}' for Physical machine and: 'ssh-copy-id -p 2242 {0}@{1}' when using a vApp.""".format(DEFAULT_USER, host, port)
        return 2

    # Note that when the below command is executed, the deploy function within the fabfile.py will be called, with the parameters
    cmd = "fab -f {0} -H {1}@{2}:{3} deploy:remote_dir={4},clean={5}".format(FABFILE, DEFAULT_USER, host, port, remote_dir, clean_remote_dir)
    if common_repo_path:
        cmd = cmd + ',common_repo=%s' % common_repo_path
    print "\nCopying local repository to {0} on remote MS {1}...".format(remote_dir, host)

    (rc, stdout) = _execute_command(cmd)
    if rc == 0:
        print "\nSuccessfully copied repository to {0}{1}{2} on the remote MS".format(PURPLE_TEXT, remote_dir, NORMAL_TEXT)
        print "Run {0}source {1}/.env/bin/activate{2} on the MS to activate the virtual environment".format(PURPLE_TEXT, remote_dir, NORMAL_TEXT)
    else:
        print "\n{0}Unable to copy repo to {1} on the remote MS.{2}\n{3}".format(RED_TEXT, remote_dir, NORMAL_TEXT, stdout)
        rc = 1

    return rc


def check_source_code(git_repo, exclude_dirs=None, staged_files_only=False, pylint_docstring_check=False):
    """
    Checks source code modules for syntax and formatting errors

    :param git_repo: path to the git root directory
    :type git_repo: str
    :param exclude_dirs: names of the directories to exclude from the check
    :type exclude_dirs: list
    :param staged_files_only: bool indicating if we need to perform check on commited files only
    :type staged_files_only: bool
    :param pylint_docstring_check: bool indicating if pylint plugin will be loaded to check docstring
    :type pylint_docstring_check: bool

    :return: Return code (0 on success; 1 on fail)
    :rtype: int
    """

    # Build a list of all of the files in the repository we want to check
    if staged_files_only:
        files_to_check = _get_modified_python_files(git_repo)
    else:
        files_to_check = _get_all_python_files_in_repo(git_repo, exclude_dirs=exclude_dirs)

    if not files_to_check:
        log.logger.warn('No files to check, will not perform the checks')
        return 0

    # Run the checks and bail when we hit the first fail
    if not check_line_endings(files_to_check):
        return 1

    if not execute_pep_checks(files_to_check):
        return 1

    if not execute_pylint_checks(files_to_check, pylint_docstring_check):
        return 1

    # If we didn't fail and return above, all checks have passed
    return 0


def _get_subset_of_tests_from_list(test_modules, module_subset):
    """
    Checks if any of the required tests are specified in the list of modules found

    :param test_modules: a list of test modules
    :type test_modules: list
    :param module_subset: a list of modules
    :type module_subset: list

    :return: A List of subset_modules
    :rtype: List

    """
    subset_modules = []

    # Check if any of the required tests are specified in the list of modules found
    for required_module in module_subset:

        for test_module in test_modules:
            if required_module in test_module:
                subset_modules.append(test_module)
                continue

    return subset_modules


def execute_tests(dirs, results_dir, test_type="acceptance", clean_pool=False, modules=None):
    """
    Executes one or more tests for the specified test type

    :param test_type: Type of tests to be executed (acceptance)
    :type test_type: str

    :return: Return code (0 on success; 1 on test fail; 2 on test report generation fail)
    :rtype: int

    """

    admin_user = get_or_create_admin_user()

    start_time = datetime.datetime.now()

    # Clean pool if specified
    if test_type == "acceptance" or clean_pool:
        test_utils.clear_pool(test_type)

    # clear the test results directory
    _clear_test_results_dir(results_dir)
    # Make sure that the directory structure exists for Allure XML files
    allure_results_dir = os.path.join(results_dir, ALLURE_RESULTS_DIR)
    if not os.path.isdir(allure_results_dir):
        os.makedirs(allure_results_dir)

    global RESULTS_PATH
    RESULTS_PATH = results_dir

    # Get the list of test modules we want to execute
    test_modules = _get_acceptance_tests(dirs, modules=modules)

    # Initialize the node pool if not already done so
    if test_type == "acceptance":
        log.logger.debug("Initializing node pool for acceptance tests")
        test_utils.init_pool("acceptance")
    # Run the tests (Note: This forks individual processes for each test)
    log.logger.info("Running {0} test processes in parallel...".format(test_type))
    if not test_modules:
        log.logger.error('No files found matching the given criteria')
        return 1

    # Check nodes are started, added and synced
    try:
        check_nodes(test_type)
    except Exception as e:
        log.logger.error("Exception raised checking nodes: {0}".format(str(e)))
        return 1

    # Shuffle tests to mix up execution
    random.shuffle(test_modules)
    return_codes = _pool(_execute_test, test_modules)

    # Copy the logs
    logs_dir = "/root/nssutils/jenkins/logs"
    if filesystem.does_dir_exist(logs_dir):
        destination_path = "/tmp/acc_logs/{0}".format(time.time())
        filesystem.copy(logs_dir, destination_path)

    # Figure out the overall result of the run by analyzing all of the module results
    test_result = False if any(return_codes) != 0 else True

    # Inject environment and version information into the report
    _update_environment_info(results_dir)

    # Build the final report
    log.logger.debug("Generating allure report after test run...")
    report_result = _generate_allure_report(results_dir)

    # Determine the overall return code
    if not test_result:
        rc = 1
        print "{0}FAIL: One or more tests failed or errored{1}\n".format(RED_TEXT, NORMAL_TEXT)
    elif not report_result:
        rc = 2
        print "{0}All tests passed, but an error was encountered while generating the test report{1}\n".format(RED_TEXT, NORMAL_TEXT)
    else:
        rc = 0
        print "{0}PASS: All tests passed and test report was generated successfully{1}\n".format(GREEN_TEXT, NORMAL_TEXT)

    # Print out the execution time
    elapsed_time = datetime.datetime.now() - start_time
    duration = "%.3fs" % float((elapsed_time.microseconds + (float(elapsed_time.seconds) + elapsed_time.days * 24 * 3600) * 10 ** 6) / 10 ** 6)
    print "TEST EXECUTION + REPORT GENERATION TIME: {0}{1}{2}\n".format(GREEN_TEXT, duration, NORMAL_TEXT)

    return rc


def execute_unit_tests(dirs, results_dir, profile_code=False, fast_unit_tests=False,
                       nose_cover_packages=None, cover_min_percentage=60, modules=None):
    """
    Executes all unit test modules via nose

    :param dirs: directories which contain the unit tests
    :param results_dir: directory where to store the results under
    :param profile_code: Flag controlling whether modules will be profiled during unit test execution
    :type profile_code: boolean
    :param fast_unit_tests: Flag controlling whether unit tests should be run in parallel and without coverage to speed up execution
    :type fast_unit_tests: boolean
    :param show_time_taken_per_testcase: Flag controlling whether the execution times for the longest tests are shown or not
    :type show_time_taken_per_testcase: boolean
    :type nose_cover_packages: list
    :param nose_cover_packages: List of directories to be included in the coverage report
    :type cover_min_percentage: int
    :param cover_min_percentage: percentage of coverage required to pass the unit test execution
    :type modules: str
    :param modules: Comma separated list of test modules

    :return: Return code (0 on success; 1 on test fail)
    :rtype: int

    """

    print "\n************************"
    print "* EXECUTING UNIT TESTS *"
    print "************************"

    _clear_test_results_dir(results_dir)

    results_dir = os.path.join(results_dir, RESULTS_DIR)

    raw_stats_file_path = os.path.abspath(os.path.join(results_dir, ".profile.stats"))
    profile_report_file_path = os.path.abspath(os.path.join(results_dir, "unit-profile.stats"))
    output_dir = os.path.abspath(os.path.join(results_dir, "unit-coverage-report"))
    start_page = os.path.abspath(os.path.join(results_dir, "unit-coverage-report", "index.html"))
    test_modules = None

    if profile_code:
        cmd = PROFILED_UNIT_TEST_CMD
    elif fast_unit_tests:
        cmd = FAST_UNIT_TEST_CMD
    elif modules:
        cmd = UNIT_SINGLE_TEST_CMD
        cover_min_percentage = 1
        test_modules = ",".join(_get_acceptance_tests(dirs, modules=modules, unit=True))
    else:
        cmd = UNIT_TEST_CMD

    if nose_cover_packages is None:
        nose_cover_packages = ['nssutils.lib']

    cmd = cmd.format(dirs=' '.join(dirs), packages=','.join(nose_cover_packages),
                     stats_file=raw_stats_file_path, cover_min_percentage=cover_min_percentage,
                     cover_config_path=COVERAGE_RC_FILE, modules=test_modules)

    print "Executing unit tests... "
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

    # Grab stdout line by line as it becomes available
    while process.poll() is None:
        try:
            line = process.stdout.readline().strip()
            if len(line) > 0:
                print line
        except:
            pass

    # There may be some final output still available after the process has exited, print that
    print process.stdout.read()

    # Generate basic profiling data for the run
    if profile_code:
        output_stream = StringIO.StringIO()
        stats = pstats.Stats(raw_stats_file_path, stream=output_stream)
        stats.sort_stats('cumtime')
        stats.print_stats("/nssutils/lib/")

        with open(profile_report_file_path, 'w') as handle:
            handle.write(output_stream.getvalue())

        output_stream.close()

    rc = process.returncode

    if rc != 0:
        print "\n\n{0}FAIL: Fails and/or errors detected in unit test results (see output above for more information){1}\n".format(RED_TEXT, NORMAL_TEXT)
        rc = 1
    else:
        _, coverage_stdout = _execute_command(COVERAGE_CMD.format(html_dir=output_dir, accept_tests=COVERED_THROUGH_ACCEPTANCE_TESTS))
        print coverage_stdout

    if not fast_unit_tests and os.path.exists(start_page):
        print "\nUnit coverage report can be found at {0}{1}{2}\n".format(PURPLE_TEXT, start_page, NORMAL_TEXT)

    if profile_code and os.path.exists(profile_report_file_path):
        print "Profile statistics from unit test run can be found at {0}{1}{2}\n".format(PURPLE_TEXT, profile_report_file_path, NORMAL_TEXT)

    return rc


def display_allure_report(results_dir):
    """
    Serves out the Allure test report from the localhost

    :return: Return code (0 on success; 1 on fail)
    :rtype: int

    """

    ip_address = None
    rc = 1

    # Build the absolute paths
    jar_path = os.path.abspath(ALLURE_JAR)
    report_path = os.path.abspath(os.path.join(results_dir, RESULTS_DIR, "report"))

    # Get the IP address of the local host
    (rc, ip_address) = _execute_command("hostname -I | awk '{ print $1 }'")
    if rc == 0:
        ip_address = ip_address.strip()
    else:
        print "\nERROR: Could not determine primary IP address for local host"

    if ip_address is not None:
        cmd = SERVE_ALLURE_REPORT_CMD.format(jar_path, report_path)

        # Kick off the process
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

        # Grab stdout line by line as it becomes available
        while process.poll() is None:
            try:
                line = process.stdout.readline().strip()
                if len(line) > 0:
                    if "Open report [http://localhost" in line:
                        line = line.replace("Open report ", "")
                        line = line.replace("localhost", ip_address).replace("[", "").replace("]", "")
                        print "\nOpen this URL to view the Allure test report remotely in browser: {0}{1}{2}\n".format(PURPLE_TEXT, line, NORMAL_TEXT)
                        print "You may need to temporaily disable the firewall on the MS to view the report"
                        print "Hit {0}ctrl-c{1} when you are finished viewing the report to stop serving the report\n".format(YELLOW_TEXT, NORMAL_TEXT)
            except:
                pass

        # When the subprocess terminates there might be unconsumed output, so grab any remaining output
        rc = 0

    return rc


def check_nodes(test_type):

    nodes = test_utils.get_pool(test_type).allocate_nodes(UnavailableNodes())
    log.logger.debug("There are {0} nodes in the acceptance pool.".format(len(nodes)))
    test_utils.get_pool("acceptance").return_nodes(nodes)


def categorise_staged_files(git_repo_dir):
    """
    Sort the the staged files into modification types

    :param git_repo_dir: path to the git repository root
    :rtype: dict

    """

    (rc, stdout) = _execute_command("cd {0}; git diff --cached --find-renames --name-status"
                                    .format(os.path.abspath(git_repo_dir)))
    if rc:
        raise RuntimeError("Could not get list of modified files ({rc}): {error}".format(rc=rc, error=stdout))

    modified = {}
    renamed = []
    deleted = []
    for line in stdout.strip().splitlines():
        data = line.split()
        if len(data) < 2:
            continue

        modification_type = data[0]
        file_path = data[1]

        if file_path.endswith(".py") and not any(f in file_path for f in IGNORED_FILES):

            split_path = file_path.split("/")
            module_name = split_path[-1]

            if "M" in modification_type:
                modified[module_name] = file_path
                continue

            if COMMON_LIB in file_path:
                if "R" in modification_type:
                    renamed.append(module_name)
                elif "D" in modification_type:
                    deleted.append(module_name)

    return modified, renamed, deleted


class UnavailableNodes(object):
    NUM_NODES = {}
    NODE_VERSION = None

    def __init__(self):
        self.__name__ = "UnavailableNodes"


def execute_tool_performance_tests(rpm_under_test):
    """
    Function that will handle the return code, and be called by the tool

    :param rpm_under_test: Rpm to be tested
    :type rpm_under_test: str

    :rtype: int
    :return: Return code indicating the success of the tool execution(s)
    """
    print "#####  Starting Performance Tests #####\n"
    rc = 0
    for tool, commands in TOOL_AND_COMMANDS.iteritems():
        rc = run_tool_performance_tests(tool, commands, rpm_under_test)
        if rc != 0:
            break
    return rc


def run_tool_performance_tests(tool, commands, rpm_under_test):
    """
    Invokes the commands, builds the timings , and invokes the evaluation

    :type tool: str
    :param tool: Name of the tool that will be tested
    :type commands: list
    :param commands: List of commands to be executed by the tool
    :param rpm_under_test: Rpm to be tested
    :type rpm_under_test: str

    :rtype: int
    :return: Return code indicating the success of the commands
    """
    timings = {}
    rc = 0
    for _ in [BASELINE_RPM, rpm_under_test]:
        try:
            install_rpm(_)
            print "Running performance tests of {0} on rpm {1}.\n".format(tool, _)
            timings[_] = run_performance_commands(commands)
        except RuntimeError:
            return 1
    try:
        evaluate_execution_times(timings, rpm_under_test)
    except RuntimeError:
        return 1
    return rc


def run_performance_commands(commands):
    """
    Executes the given list of commands

    :type commands: list
    :param commands: List of commands to be executed by the tool

    :raises: RuntimeError

    :rtype: dict
    :return: Key, Value pairs of command, elapsed time
    """
    timings = {}
    all_simulations = [sim for sim in get_all_simulations_on_netsim('netsim')]
    simulations = all_simulations[:5] + all_simulations[-5:]
    base_dir = "/opt/ericsson/nssutils/bin/{0}"
    for command in commands:
        if "{simulations}" in command:
            command = command.format(simulations=",".join(set(simulations)))
        elif "{simulation}" in command:
            command = command.format(simulation=simulations[0])
        print "Executing command {0}.".format(command)
        start = time.time()
        for _ in xrange(2):
            response = shell.run_local_cmd(shell.Command(base_dir.format(command), timeout=15 * 60, log_cmd=False))
            if response.rc > 1:
                print "Failed to execute command: {0}, Response: {1}.".format(command, response.stdout)
                raise RuntimeError("")
        elapsed = round(time.time() - start, 2)
        timings[command] = elapsed
    return timings


def install_rpm(rpm):
    """
    Installs the requested rpm version

    :type rpm: str
    :param rpm: Version of the rpm to be installed

    :raises: RuntimeError

    :return: None
    """
    wget_cmd = ('wget https://arm1s11-eiffel004.eiffel.gic.ericsson.se:8443/nexus/content/repositories/releases/com/ericsson/'
                'ci/nss/ERICnssutilities_CXP9035994/{0}/ERICnssutilities_CXP9035994-{0}.rpm'.format(rpm))
    update_rpm = '{0};rpm -Uvh --replacepkgs --oldpackage ERICnssutilities_CXP9035994-{1}.rpm'.format(wget_cmd, rpm)
    print "Starting installation of rpm {0}.\n".format(rpm)
    response = shell.run_local_cmd(shell.Command(update_rpm, timeout=15 * 60, log_cmd=False))
    if response.rc is not 0:
        print "Failed to update the rpm, response: {0}.".format(response.stdout)
        raise RuntimeError("")
    print "Successfully installed rpm version: {0}.\n".format(rpm)


def evaluate_execution_times(timings, rpm_under_test):
    """
    Evaluates the current elapsed times versus the baseline version, with a margin of 20%

    :type timings: dict
    :param timings: Dictionary, containing a dictionary for each rpm, with commands and timings
    :type rpm_under_test: str
    :param rpm_under_test: Rpm to be tested

    :raises: RuntimeError

    :return: None
    """
    base, latest = timings.get(BASELINE_RPM), timings.get(rpm_under_test)
    for key in base.iterkeys():
        if latest.get(key) > base.get(key) * 1.20 and latest.get(key) - base.get(key) > 120:
            print ("Performance failure, command {0} execution time has increased by {1} \nLatest: [{2}] {4}: "
                   "[{3}]\n".format(key, latest.get(key) - base.get(key), latest.get(key), base.get(key), BASELINE_RPM))
            raise RuntimeError("")
        print ("Performed command: {0}\nLatest: [{1}] {3}: [{2}]\n"
               .format(key.split(' ')[:-1], latest.get(key), base.get(key), BASELINE_RPM))
