import os
import re
import tempfile
import time
from contextlib import contextmanager

import grp
import pwd

import cache
import exception
import log
import shell


def does_file_exist(file_path, verbose=True):
    """
    B{Checks whether a local file exists}

    @type file_path: string
    @param file_path: Absolute path of the file to be checked
    @type verbose: bool
    @param verbose: Enable/Disable verbose logging
    @rtype: boolean
    """
    result = False

    # Some file paths that contain dollar signs will be escaped; we need to remove the backslash
    file_path = file_path.replace(r"\$", "$")

    if not os.path.exists(os.path.realpath(file_path)):
        if verbose:
            log.logger.debug("File {0} does not exist".format(file_path))
    else:
        result = True
        if verbose:
            log.logger.debug("Verified that file {0} exists".format(file_path))

    return result


def is_dir(directory_path):
    """
    B{Checks whether the path is a directory}

    @type directory_path: string
    @param directory_path: Absolute path of the directory
    @rtype: boolean
    """
    is_directory = False
    if os.path.isdir(directory_path):
        is_directory = True
    return is_directory


def assert_file_exists(file_path):
    """
    B{Asserts that a local file exists}

    @type file_path: string
    @param file_path: Absolute path of the file to be checked
    @rtype: void
    """

    if not does_file_exist(file_path):
        raise RuntimeError("File {0} does not exist".format(file_path))


def delete_file(file_path):
    """
    B{Deletes a local file}

    @type file_path: string
    @param file_path: Absolute path of the file to be deleted
    @rtype: void
    """

    try:
        os.remove(file_path)
    except:
        exception.process_exception("Could not delete file {0}".format(file_path))
        raise

    if does_file_exist(file_path):
        raise RuntimeError("Unable to remove file {0} as the file does not exist".format(file_path))
    else:
        log.logger.debug("Successfully deleted file {0}".format(file_path))


def delete_files_in_dir(dir_path):
    """
    B{Removes the files in the specified directory from the MS}

    @type dir_path: string
    @param dir_path: Absolute path of the directory
    @rtype: void
    """

    log.logger.debug("Attempting to remove files from directory: {0}".format(dir_path))
    if does_dir_exist(dir_path):
        response = shell.run_local_cmd(shell.Command("rm -rf {0}".format(os.path.join(dir_path, "*"))))
        if not response.ok:
            raise RuntimeError("Could not perform recursive delete of files in directory {path}. Error: {error}"
                               .format(path=dir_path, error=response.stdout))

    log.logger.debug("Successfully removed files in directory: {0}".format(dir_path))


def assert_dir_exists(dir_path):
    """
    B{Asserts that a local directory exists}

    @type dir_path: string
    @param dir_path: Absolute path of the directory to be checked
    @rtype: void
    """

    if not does_dir_exist(dir_path):
        raise RuntimeError("Directory {0} does not exist".format(dir_path))


def does_dir_exist(dir_path):
    """
    Checks if a local directory exists

    :type dir_path: string
    :param dir_path: Absolute path of the directory to be checked

    :rtype: boolean
    """

    result = False

    # Some file paths that contain dollar signs will be escaped; we need to remove the backslash
    dir_path = dir_path.replace(r"\$", "$")

    if not os.path.isdir(dir_path):
        log.logger.debug("Directory {0} does not exist".format(dir_path))
    else:
        log.logger.debug("Verified that directory {0} exists".format(dir_path))
        result = True

    return result


def create_dir(dir_path, group_name=None):
    """
    Creates a local directory if one doesnt exist

    :type dir_path: string
    :param dir_path: Absolute path of the directory to be created
    :type group_name: string
    :param group_name: The group name that the directory should have. This group name is applied even if the directory exists
    """
    try:
        os.makedirs(dir_path)
        log.logger.debug("Created local directory: '{0}'".format(dir_path))
    except OSError:
        log.logger.debug("Directory: '{0}' already exists".format(dir_path))

    if group_name:
        change_owner(dir_path, group_name=group_name)


def change_owner(path, username=None, group_name=None, recursive=False):
    """
    :type path: string
    :param path: Path of the file or directory to update
    :type username: string
    :param username: The username to change the file owner to. If not specified, the owner is not changed
    :type group_name: string
    :param group_name: The group to change the file to. If not specified, the group is not changed
    :type recursive: bool
    :param recursive: Change owner of files beneath the directory specified
    """
    uid = pwd.getpwnam(username).pw_uid if username else os.stat(path).st_uid
    gid = grp.getgrnam(group_name).gr_gid if group_name else os.stat(path).st_gid

    if recursive:
        paths = set(tree[0] for tree in os.walk(path))
    else:
        paths = {path}

    for resource_path in paths:
        os.chown(resource_path, uid, gid)


def create_remote_dir(dir_path, host, user, password=None):
    """
    B{Creates a remote directory on a remote host}

    @type dir_path: string
    @param dir_path: Absolute path of the directory to be created on the remote host
    @type host: string
    @param host: hostname or IP address
    @type user: string
    @param user: SSH login username
    @type password: string
    @param password: SSH login password [optional]
    @rtype: void
    """
    remote_hostname = get_remote_hostname(host, user, password)
    cmd = shell.Command("{1}mkdir -p {0}".format(dir_path, add_sudo_if_cloud(remote_hostname)))
    response = shell.run_remote_cmd(cmd, host, user, password)

    if response.rc == 0 and does_remote_dir_exist(dir_path, host, user, password):
        log.logger.debug("Successfully created directory {0} on host {1}".format(dir_path, host))
    else:
        raise RuntimeError("Unable to create directory {0} on host {1}".format(dir_path, host))


def remove_dir(dir_path):
    """
    B{Removes the specified directory from the local environment}

    @type dir_path: string
    @param dir_path: Absolute path of the directory to be removed
    @rtype: void
    """

    log.logger.debug("Attempting to remove directory: {0}".format(dir_path))
    if does_dir_exist(dir_path):
        response = shell.run_local_cmd(shell.Command("rm -rf {0}".format(dir_path)))
        if not response.ok:
            raise RuntimeError("Could not perform recursive delete of directory {0}".format(dir_path))

        if does_dir_exist(dir_path):
            raise RuntimeError("Unable to remove directory {0}; directory still exists after deletion".format(dir_path))
    log.logger.debug("Successfully removed directory: {0}".format(dir_path))


def copy(source_path, destination_path):
    """
    B{Performs a recursive copy of the source file or directory to the specified destination}

    @type source_path: string
    @param source_path: Absolute path of the file or directory to be copied
    @type destination_path: string
    @param destination_path: Absolute path of the destination to which the file or directory is to be copied
    @rtype: void
    """

    destination_dir = os.path.dirname(os.path.realpath(destination_path))
    if not does_dir_exist(destination_dir):
        create_dir(destination_dir)

    response = shell.run_local_cmd(shell.Command("cp -rf {0} {1}".format(source_path, destination_path)))
    if not response.ok:
        raise RuntimeError("Could not copy {0} to {1}".format(source_path, destination_path))


def get_remote_file_size_in_mb(file_path, host, user, password=None):
    """
    B{Gets the size of a file (in MB) on a remote host}

    @type file_path: string
    @param file_path: Absolute path of the file to be sized on the remote host
    @type host: string
    @param host: hostname or IP address
    @type user: string
    @param user: SSH login username
    @type password: string
    @param password: SSH login password [optional]
    @rtype: string
    """

    size = None

    if not does_remote_file_exist(file_path, host, user, password):
        raise RuntimeError("File {0} does not exist on host {1}".format(file_path, host))

    cmd = shell.Command("{1}du -m {0}".format(file_path, add_sudo_if_cloud(get_remote_hostname(host, user, password))))
    response = shell.run_remote_cmd(cmd, host, user, password)

    if response.rc != 0 or response.stdout is None or len(response.stdout) < 1:
        raise RuntimeError("Could not get file size for file {0} on host {1}".format(file_path, host))

    try:
        size = response.stdout.split()[0].strip()
    except:
        raise RuntimeError("Could not process file size for file {0} on host {1}".format(file_path, host))

    return size


def get_file_size_in_mb(file_path):
    """
    B{Returns the filesize of a local file in MB}

    @type file_path: string
    @param file_path: Absolute path to the local file
    @rtype: string
    """

    response = shell.run_local_cmd(shell.Command("du -m {0}".format(file_path)))
    if not response.ok or response.stdout is None or len(response.stdout) < 1:
        raise RuntimeError("Could not get file size for file {0}".format(file_path))

    try:
        return response.stdout.split()[0].strip()
    except:
        raise RuntimeError("Could not process file size for file {0}".format(file_path))


def touch_file(file_path):
    """
    B{Creates an empty file on the MS at the specified location}

    @type file_path: string
    @param file_path: Absolute path to the local file
    @rtype: void
    """

    if not does_file_exist(file_path):
        log.logger.debug("Creating file {0} on the MS".format(file_path))
        shell.run_local_cmd(shell.Command("touch {0}".format(file_path)))
    else:
        raise RuntimeError("File {0} already exists".format(file_path))


def delete_remote_file(file_path, host, user, password=None):
    """
    B{Deletes a file on a remote host}

    @type file_path: string
    @param file_path: Absolute path of the file to be deleted on the remote host
    @type host: string
    @param host: hostname or IP address
    @type user: string
    @param user: SSH login username
    @type password: string
    @param password: SSH login password [optional]
    @rtype: void
    """

    cmd = shell.Command("{1}rm {0}".format(file_path, add_sudo_if_cloud(get_remote_hostname(host, user, password))))
    response = shell.run_remote_cmd(cmd, host, user, password)

    if response.rc == 0 and not does_remote_file_exist(file_path, host, user, password):
        log.logger.debug("Successfully deleted file {0} on host {1}".format(file_path, host))
    else:
        raise RuntimeError("Unable to delete file {0} on host {1}. Reason {2}".format(file_path, host, response.stdout))


def does_remote_file_exist(file_path, host, user, password=None):
    """
    B{Determines whether a file exists on a remote host}

    @type file_path: string
    @param file_path: Absolute path of the file to be checked on the remote host
    @type host: string
    @param host: hostname or IP address
    @type user: string
    @param user: SSH login username
    @type password: string
    @param password: SSH login password [optional]
    @rtype: boolean
    """

    result = False
    cmd = shell.Command("{1}ls -1 {0}".format(file_path, add_sudo_if_cloud(get_remote_hostname(host, user, password))))
    response = shell.run_remote_cmd(cmd, host, user, password)

    if response.rc == 0:
        log.logger.debug("Determined that file {0} exists on host {1}".format(file_path, host))
        result = True
    else:
        log.logger.debug("Determined that file {0} does not exist on host {1}".format(file_path, host))

    return result


def does_remote_dir_exist(dir_path, host, user, password=None):
    """
    B{Determines whether a directory exists on a remote host}

    @type dir_path: string
    @param dir_path: Absolute path of the directory to be checked on the remote host
    @type host: string
    @param host: hostname or IP address
    @type user: string
    @param user: SSH login username
    @type password: string
    @param password: SSH login password [optional]
    @rtype: boolean
    """

    result = False
    cmd = shell.Command("{1}test -d {0}".format(dir_path, add_sudo_if_cloud(get_remote_hostname(host, user, password))))
    response = shell.run_remote_cmd(cmd, host, user, password)

    if response.rc == 0:
        log.logger.debug("Determined that directory {0} exists on host {1}".format(dir_path, host))
        result = True
    else:
        log.logger.debug("Determined that directory {0} does not exist on host {1}".format(dir_path, host))

    return result


def _perform_file_operation_on_ms(task_callback_remote, task_callback_local, *args):
    ms_host = cache.get_ms_host()
    cloud = cache.is_emp()
    if cloud:
        ms_host = cache.get_emp()
        username, password = cache.get_vnf_laf_credentials()
    elif ms_host == 'localhost':
        return task_callback_local(*args)
    else:
        username, password = cache.get_ms_credentials()
    args = args + (ms_host, username, password)
    return task_callback_remote(*args)


def does_file_exist_on_ms(file_path):
    log.logger.debug('Checking if file %s exists on deployment' % file_path)
    return _perform_file_operation_on_ms(does_remote_file_exist, does_file_exist, file_path)


def does_dir_exist_on_ms(dir_path):
    log.logger.debug('Checking if dir exists on deployment %s' % dir_path)
    return _perform_file_operation_on_ms(does_remote_dir_exist, does_dir_exist, dir_path)


def delete_file_on_ms(file_path):
    log.logger.debug('Deleting file %s from deployment' % file_path)
    return _perform_file_operation_on_ms(delete_remote_file, delete_file, file_path)


def create_dir_on_ms(dir_path):
    log.logger.debug('Creating directory on deployment %s' % dir_path)
    return _perform_file_operation_on_ms(create_remote_dir, create_dir, dir_path)


def get_files_in_remote_directory(directory, host, user, password=None, ends_with="", full_paths=False):
    """
    B{Gets a list of all of the files in the specified directory on the remote host}

    @type directory: str
    @param directory: Absolute path of the directory to be checked on the remote host
    @type host: str
    @param host: Hostname or IP address of remote server
    @type user: str
    @param user: SSH login username
    @type password: str
    @param password: SSH login password [optional]
    @type ends_with: str
    @param ends_with: Pattern that the end of the filenames much match
    @type full_paths: bool
    @param full_paths: Whether the returned list of files will have the full absolute path or just the basename
    @rtype: list[str]
    @raises OSError: If specified directory does not exist
    """
    if not does_remote_dir_exist(directory, host, user, password):
        raise OSError("Directory {0} does not exist on host {1}".format(directory, host))
    remote_hostname = get_remote_hostname(host, user, password)
    list_files_cmd = shell.Command("{2}ls -1 {0} | grep '{1}$'"
                                   .format(directory, ends_with, add_sudo_if_cloud(remote_hostname)), timeout=60)
    response = shell.run_remote_cmd(list_files_cmd, host, user, password)
    # Must not throw error when grep finds nothing (return code 1, but not error)
    if (response.rc != 0 and response.stdout != "") or response.stdout is None:
        raise RuntimeError("Could not get list of files in directory {0} on host {1}".format(directory, host))

    if full_paths:
        return [os.path.join(directory, filename) for filename in response.stdout.splitlines()]
    else:
        return response.stdout.splitlines()


def get_files_in_remote_directory_recursively(directory, host, user, password=None, ends_with="", full_paths=False):
    """
    B{Gets a list of all of the files in the specified directory and all child directories on the remote host}

    @type directory: str
    @param directory: Absolute path of the directory to be checked on the remote host
    @type host: str
    @param host: Hostname or IP address of remote server
    @type user: str
    @param user: SSH login username
    @type password: str
    @param password: SSH login password [optional]
    @type ends_with: str
    @param ends_with: Pattern that the end of the filenames much match
    @type full_paths: bool
    @param full_paths: Whether the returned list of files will have the full absolute path or just the basename
    @rtype: list[str]
    @raises OSError: If specified directory does not exist
    """
    if not does_remote_dir_exist(directory, host, user, password):
        raise OSError("Directory {0} does not exist on host {1}".format(directory, host))
    remote_hostname = get_remote_hostname(host, user, password)
    list_files_recursively_cmd = shell.Command("{sudo}find {dir} -name '*{suffix}' -print"
                                               .format(dir=directory, suffix=ends_with,
                                                       sudo=add_sudo_if_cloud(remote_hostname)), timeout=60)
    response = shell.run_remote_cmd(list_files_recursively_cmd, host, user, password)
    if response.rc != 0 or response.stdout is None:
        raise RuntimeError("Could not get list of files in directory '{dir}' on host '{host}': {error}"
                           .format(dir=directory, host=host, error=response.stdout))

    if ends_with:
        # Spliced to ignore trailing new line
        files = response.stdout.split("\n")[:-1]
    else:
        # Ignore directory name (the first line if 'ends_with' not specified)
        files = response.stdout.split("\n")[1:-1]

    if full_paths:
        return files
    else:
        return [os.path.basename(filename) for filename in files]


def get_remote_files_with_pattern_in_content(directory, host, user, file_name, pattern, password=None):
    """
    B{Gets a list of all of the files in the specified directory that contain a pattern}

    @type directory: str
    @param directory: Absolute path of the directory to be checked on the remote host
    @type host: str
    @param host: Hostname or IP address of remote server
    @type user: str
    @param user: SSH login username
    @type file_name: string
    @param file_name: Name of file to search for
    @type pattern: string
    @param pattern: Pattern that will be searched for in file_name
    @type password: str
    @param password: SSH login password [optional]
    @rtype: list[str]
    @raises OSError: If specified directory does not exist
    @raises RuntimeError: If return code isn't 0 or if the return value is empty or None
    """
    if not does_remote_dir_exist(directory, host, user, password):
        raise OSError("Directory {0} does not exist on host {1}".format(directory, host))
    remote_hostname = get_remote_hostname(host, user, password)
    list_files_with_pattern_cmd = shell.Command("bash -c \"{sudo}find {dir} -type f -name {name} -exec egrep -le "
                                                "'{pattern}' {{}} +\""
                                                .format(dir=directory, name=file_name, pattern=pattern,
                                                        sudo=add_sudo_if_cloud(remote_hostname)), timeout=180)
    response = shell.run_remote_cmd(list_files_with_pattern_cmd, host, user, password)

    files_with_pattern = [line for line in response.stdout.splitlines() if line.endswith(file_name) and line.startswith(directory)]
    error_output = [line for line in response.stdout.splitlines() if not line.endswith(file_name) or not line.startswith(directory) or "permission denied" in line.lower()]

    if error_output:
        log.logger.debug("Errors output from get_remote_files_with_pattern_in_content: {}"
                         .format("\n\t".join(error_output)))

    if not files_with_pattern:
        raise RuntimeError("Could not find pattern '{pattern}' in files named '{file}' located within {directory} "
                           "on host '{host}': {error}".format(pattern=pattern, file=file_name, directory=directory,
                                                              host=host, error=response.stdout))

    return files_with_pattern


def get_files_in_remote_directory_created_since_last(dir_path, minute, host, user, password, ends_with=""):
    """
    B{Gets a list of all of the files that ends with a pattern in the specified directory that was created within a specific minute period}

    @type dir_path: string
    @param dir_path: Absolute path of the directory to be checked on the remote host
    @type minute: string
    @param minute: minute to check for
    @type host: string
    @param host: hostname or IP address
    @type user: string
    @param user: SSH login username
    @type password: string
    @param password: SSH login password [optional]
    @type ends_with: str
    @param ends_with: Pattern that the end of the filenames much match
    @rtype: list of strings
    """

    if not does_remote_dir_exist(dir_path, host, user, password):
        raise RuntimeError("Directory {0} does not exist on host {1}".format(dir_path, host))
    remote_hostname = get_remote_hostname(host, user, password)
    cmd = shell.Command("{3}find {0} -type f -name '*{1}' -cmin -{2}"
                        .format(dir_path, ends_with, minute, add_sudo_if_cloud(remote_hostname)), timeout=60)
    response = shell.run_remote_cmd(cmd, host, user, password)

    if response.rc != 0 or response.stdout is None:
        raise RuntimeError("Could not get list of files in directory {0} on host {1} for the last {2}min"
                           .format(dir_path, host, minute))

    file_list = []
    for f in response.stdout.split("\n"):
        if len(f) > 0:
            file_list.append(f.strip())

    return file_list


def get_files_in_directory(directory, ends_with="", full_paths=False):
    """
    B{Gets a list of all of the files in the specified directory. This includes hard linked files, but does not follow symlinks)}

    @type directory: str
    @param directory: Absolute path of the directory to be checked
    @type ends_with: str | tuple[str]
    @param ends_with: Pattern or patterns that the end of the filenames much match
    @type full_paths: bool
    @param full_paths: Whether the returned list of files will have the full absolute path or just the basename
    @rtype: list
    @return: The files in the given directory
    """

    files = [filename for filename in os.listdir(directory) if filename.endswith(ends_with)]

    if full_paths:
        files = [os.path.join(directory, filename) for filename in files]

    return files


def get_files_in_directory_recursively(directory, ends_with="", exclude_dirs=()):
    """
    :type directory: string
    :type ends_with: string
    :type exclude_dirs: set[string]
    :rtype: set[string]
    """
    files_in_dir = set()
    for (dirpath, dirnames, files) in os.walk(directory):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        files_in_dir.update(os.path.join(dirpath, filename) for filename in files if filename.endswith(ends_with))

    return files_in_dir


def get_lines_from_remote_file(file_path, host, user, password=None):
    """
    B{Reads the lines of a file on a remote host}

    @type file_path: string
    @param file_path: Absolute path of the file to be read on the remote host
    @type host: string
    @param host: hostname or IP address
    @type user: string
    @param user: SSH login username
    @type password: string
    @param password: SSH login password [optional]
    @rtype: list
    @return: List of strings
    """

    lines = []

    if does_remote_file_exist(file_path, host, user, password):
        remote_hostname = get_remote_hostname(host, user, password)
        cmd = shell.Command("{1}cat {0}".format(file_path, add_sudo_if_cloud(remote_hostname)))
        response = shell.run_remote_cmd(cmd, host, user, password)

        if response.rc == 0 and response.stdout is not None and len(response.stdout) > 0:
            log.logger.debug("Successfully read lines from file {0} on host {1}".format(file_path, host))
            lines = response.stdout.split("\n")
    else:
        log.logger.debug("Remote file {0} does not exist".format(file_path))

    return lines


def get_lines_from_file(input_file):
    """
    B{Returns a list containing all of the lines from the specified file}

    @type input_file: string
    @param input_file: Absolute path to the local file
    @rtype: list of strings
    """

    if not does_file_exist(input_file):
        raise RuntimeError("Input file {0} doesn't exist".format(input_file))

    file_lines = []
    file_handle = open(input_file, "r")

    for line in file_handle:
        line = line.strip()

        # If the line is not a comment line or an empty line, add it
        if not re.match(r"\s*#", line) and not re.match(r"^\s*$", line):
            file_lines.append(line)

    file_handle.close()

    return file_lines


def write_data_to_file(data, output_file, append=False):
    """
    B{Writes the specified string (single or multi-line) to the specified file creating the file if it does not exist}

    NOTE: Overwrites any data in the file before writing

    @type data: str
    @param data: Data to be written to file
    @type output_file: str
    @param output_file: Absolute path to the local file
    @type append: bool
    @param append: Boolean set to True to append to file
    @rtype: bool
    """
    log.logger.debug('Attempting to WRITE DATA: "{0}" TO FILE: {1} . Append mode: {2}'
                     .format(data[:100], output_file, append))
    dir_path = os.path.dirname(output_file)
    if not does_dir_exist(dir_path):
        create_dir(dir_path)
    mode = "a" if append else "w"
    with open(output_file, mode) as file_handle:
        file_handle.write(data)
    log.logger.debug('Finished WRITING DATA TO FILE: {0}'.format(output_file))
    return True  # For backward compatability


@contextmanager
def open_file_on_ms(file_path):
    """
    :param file_path: path of the file
    :returns: file like object
    :raises: IOError
    """
    if cache.is_host_ms():
        fl = open(file_path, 'r')
    elif cache.is_vnf_laf():
        fl = tempfile.NamedTemporaryFile()
        ms_username, ms_password = cache.get_vnf_laf_credentials()
        shell.download_file(
            file_path, fl.name, cache.get_vnf_laf(), ms_username, ms_password)
    else:
        fl = tempfile.NamedTemporaryFile()
        ms_username, ms_password = cache.get_ms_credentials()
        shell.download_file(
            file_path, fl.name, cache.get_ms_host(), ms_username, ms_password)
    try:
        yield fl
    finally:
        fl.close()


def write_file_to_ms(file_path, contents):
    """
    :param file_path: path of the file
    :param contents: bytes to be written to the file
    :returns: None
    :raises: IOError
    """
    if cache.is_host_ms():
        write_data_to_file(contents, file_path)
        return
    with tempfile.NamedTemporaryFile() as temp:
        temp.write(contents)
        temp.flush()
        shell.upload_file_to_ms(temp.name, file_path)


def get_remote_file_checksum(file_path, host, user, password=None):
    """
    B{Gets the checksum of a file on a remote host}

    @type file_path: string
    @param file_path: Absolute path of the file to be sized on the remote host
    @type host: string
    @param host: hostname or IP address
    @type user: string
    @param user: SSH login username
    @type password: string
    @param password: SSH login password [optional]
    @rtype: string
    """

    checksum = None

    if not does_remote_file_exist(file_path, host, user, password):
        raise RuntimeError("File {0} does not exist on host {1}".format(file_path, host))

    # using CRC check 'cksum' for inter platform support. 'sum' will not spot byte reversal
    # or even lines swapped over. cksum will.
    cmd = shell.Command("{1}cksum {0}".format(file_path, add_sudo_if_cloud(get_remote_hostname(host, user, password))),
                        timeout=300)
    response = shell.run_remote_cmd(cmd, host, user, password)

    if response.rc != 0 or response.stdout is None or len(response.stdout) < 1:
        raise RuntimeError("Could not get checksum for remote file {0} on host {1}".format(file_path, host))

    try:
        checksum = response.stdout.split()[0].strip()
    except:
        raise RuntimeError("Could not parse checksum for remote file {0} on host {1}".format(file_path, host))

    return checksum


def get_local_file_checksum(file_path):
    """
    B{Gets the checksum of a file}

    @type file_path: string
    @param file_path: Absolute path of the file to be sized on the remote host
    @rtype: string
    """

    if not does_file_exist(file_path):
        raise RuntimeError("File {0} does not exist".format(file_path))
    # using CRC check 'cksum' for inter platform support. 'sum' will not spot byte reversal
    # or even lines swapped over. cksum will.
    response = shell.run_local_cmd(shell.Command("cksum {0}".format(file_path)))
    if not response.ok:
        raise RuntimeError("Could not get checksum for file {0}".format(file_path))

    try:
        return response.stdout.split()[0].strip()
    except:
        raise RuntimeError("Could not parse checksum for file {0}".format(file_path))


def verify_remote_directory_exists(path, host, username, password=None):
    """
    B{Checks if remote directory exists}

    @type path: str
    @param path: Absolute path of the directory on the remote host
    @type host: str
    @param host: String object containing the remote host name
    @type username: str
    @param username: String object containing the remote host username
    @type password: str
    @param password: String object containing the remote host password
    @rtype: None
    @raises OSError: If the remote directory doesn't exist
    """
    if not does_remote_dir_exist(path, host, username, password):
        raise OSError(
            "Remote directory does not exist - Host: {hostname}, Directory: {path}. This is directory is required".
            format(hostname=host, path=path))


def remove_local_files_over_certain_age(directory, regex, file_retention):
    """
    Delete any files that have not been modified in the specified period of time

    @param directory: directory to search
    @type directory: str
    @param regex: regex to search for in file name
    @type regex: str
    @param file_retention: Any file over file_retention time will be deleted. Measured in seconds eg 60 * 10 (10 minutes)
    @type file_retention: int
    """

    for tmp_file in os.listdir(directory):
        file_path = os.path.join(directory, tmp_file)
        if os.stat(file_path).st_mtime < time.time() - file_retention:
            if re.search(regex, tmp_file, flags=re.IGNORECASE):
                os.remove(file_path)
                if not file_retention / (60 * 60) < 0:
                    log.logger.debug(
                        "File '{0}' removed as it is over {1} hours old: {2}".format(file_path,
                                                                                     file_retention / (60 * 60),
                                                                                     file_path))
                else:
                    log.logger.debug(
                        "File '{0}' removed as it is over {1} seconds old: {2}".format(file_path, file_retention,
                                                                                       file_path))


def add_sudo_if_cloud(hostname):
    """
    Add sudo to commands that will be ran as cloud-user

    :rtype: str
    :return: String depending on whether or not we are on the cloud
    """
    cmd_str = ""

    if cache.get_vnf_laf() == hostname and hostname:
        cmd_str = "sudo "
    return cmd_str


def get_remote_hostname(host, user, password):
    """
    Retrieve the hostname of the given host

    :type: str
    :param host: Name of the host to query
    :type user: str
    :param user: User who will perform the query
    :type password: str
    :param password: Password to use

    :rtype: str
    :return: Hostname or empty string
    """
    if _is_remote_host_solaris_system(host, user, password):
        response = shell.run_remote_cmd(shell.Command("ifconfig -a | awk 'BEGIN { count=0; } { if ( $1 ~ /inet/ ) { count++; if( count==2 ) { print $2; } } }'"), host, user, password)
    else:
        response = shell.run_remote_cmd(shell.Command('hostname -i'), host, user, password)
    if response.ok:
        return response.stdout.strip()
    else:
        return ""


def _is_remote_host_solaris_system(host, user, password):
    """
    :type: str
    :param host: Name of the host to query
    :type user: str
    :param user: User who will perform the query
    :type password: str
    :param password: Password to use
    :return: True if remote host is Solaris otherwise False
    """
    response = shell.run_remote_cmd(shell.Command('uname'), host, user, password)
    if response.ok:
        return "SunOS" in response.stdout
    else:
        return False
