import os
import random
import socket
import threading
import config
import log
import shell
import mutexer
from nssutils.lib.exceptions import EnvironError

access_mutex = threading.Lock()

__global_cache_dict = {}
CLOUD_USER_SSH_PRIVATE_KEY_FILE_ON_WL_VM = '/var/tmp/enm_keypair.pem'
CLOUD_USER_SSH_PRIVATE_KEY_FILE_ON_EMP = '/ericsson/enm/dumps/.cloud_user_keypair.pem'


def has_key(key):
    """
    B{Checks if the cache has the specified key}

    @type key: string
    @param key: cache key
    @rtype: boolean
    """

    return bool(__global_cache_dict.has_key(key))


def get(key):
    """
    B{Returns the primitive or object associated with the specified key}

    @type key: string
    @param key: cache key
    @rtype: primitive || object
    """

    if not __global_cache_dict.has_key(key):
        return None

    return __global_cache_dict[key]


def set(key, value):  # pylint: disable=redefined-builtin
    """
    B{Sets the specified primitive or object in the cache with the specified key}

    @type key: string
    @param key: cache key
    @type value: primitive || object
    @param value: data to be stored in the cache
    @rtype: void
    """

    global __global_cache_dict
    access_mutex.acquire()
    __global_cache_dict[key] = value
    access_mutex.release()


def remove(key):
    """
    B{Removes the key-value pair from the cache for the specified key}

    @type key: string
    @param key: cache key
    @rtype: void
    """

    if has_key(key):
        access_mutex.acquire()
        del __global_cache_dict[key]
        access_mutex.release()


def clear():
    """
    B{Resets the cache by removing all existing key-value pairs}

    @rtype: void
    """

    global __global_cache_dict
    access_mutex.acquire()
    __global_cache_dict = {}
    access_mutex.release()


def copy_cloud_user_ssh_private_key_file_to_emp():
    """
    Checks cloud-user private key file exists on EMP,if not copies the key from Workload VM to EMP
    During ENM upgrade, /var/tmp/enm_keypair.pem on EMP gets removed.
    Profiles using enm_keypair.pem on EMP to connect to other servers must call this function
    before using the enm_keypair.pem, to ensure that enm_keypair.pem exists on EMP
    :return: bool
    :return: True if enm_keypair exists on EMP or enm_keypair is successfully copied to EMP
    """
    temporary_storage_location = "/tmp/enm_keypair.pem"
    enm_user = "cloud-user"
    emp_host = get_emp()
    cmd = shell.Command("ls -la {0}".format(CLOUD_USER_SSH_PRIVATE_KEY_FILE_ON_EMP))
    response = shell.run_remote_cmd(cmd, emp_host, enm_user)
    if response.rc:
        cmd = "scp  -i {0} -o stricthostkeychecking=no {0} {1}@{2}:{3}".format(CLOUD_USER_SSH_PRIVATE_KEY_FILE_ON_WL_VM,
                                                                               enm_user,
                                                                               emp_host,
                                                                               temporary_storage_location)
        response = shell.run_local_cmd(cmd)
        if response.rc:
            raise EnvironError(
                "Failed to copy {0} from Workload VM to {1} on {2}".format(CLOUD_USER_SSH_PRIVATE_KEY_FILE_ON_WL_VM,
                                                                           temporary_storage_location,
                                                                           emp_host))
        else:
            log.logger.info(
                "Successfully copied {0} from Workload VM to {1} on {2}".format(CLOUD_USER_SSH_PRIVATE_KEY_FILE_ON_WL_VM,
                                                                                temporary_storage_location,
                                                                                emp_host))
        cmd = shell.Command("sudo mv {0} {1}".format(temporary_storage_location,
                                                     CLOUD_USER_SSH_PRIVATE_KEY_FILE_ON_EMP))
        response = shell.run_remote_cmd(cmd, emp_host, enm_user, get_pty=True)
        if response.rc:
            raise EnvironError("Failed to move {0} to {1} on {2}".format(temporary_storage_location,
                                                                         CLOUD_USER_SSH_PRIVATE_KEY_FILE_ON_EMP,
                                                                         emp_host))
        else:
            log.logger.info("Successfully moved  {0} to {1} on {2}".format(temporary_storage_location,
                                                                           CLOUD_USER_SSH_PRIVATE_KEY_FILE_ON_EMP,
                                                                           emp_host))
    else:
        log.logger.info("File {0} exists on {1} - "
                        "Copying from Workload VM to {1} is not required".format(CLOUD_USER_SSH_PRIVATE_KEY_FILE_ON_EMP,
                                                                                 emp_host))
    return True


def get_apache_url():
    """
    Builds the base FQDN Apache URL
    :return: hostname
    """

    return 'https://' + get_haproxy_host()


def get_apache_ip_url():
    """
    Builds the base FQDN Apache IP address
    :return: IP Address
    """

    with mutexer.mutex("acquire-httpd-ip"):
        if not has_key('httpd-ip_url'):
            hostname = get_haproxy_host()
            port = 443
            addrs = socket.getaddrinfo(hostname, port)
            ips = []

            ipv4_addrs = [addr[4][0] for addr in addrs if addr[0] == socket.AF_INET]
            if ipv4_addrs:
                ips.append("https://{0}:{1}".format(random.choice(ipv4_addrs), port))

            ipv6_addrs = [addr[4][0] for addr in addrs if addr[0] == socket.AF_INET6]
            if ipv6_addrs:
                ips.append("https://[{0}]:{1}".format(random.choice(ipv6_addrs), port))

            ip = random.choice(ips)
            set("httpd-ip_url", ip)

    return get("httpd-ip_url")


def get_haproxy_host():
    """
    Builds the base FQDN Apache URL
    :return: hostname
    """

    enm_url_key = "ENM_URL"

    if not has_key("httpd-hostname"):
        with mutexer.mutex("acquire-httpd-fqdn"):
            if enm_url_key in os.environ:
                set("httpd-hostname", "{}".format(os.environ[enm_url_key]))
            else:
                # Check if we are on the cloud
                if is_enm_on_cloud():
                    cmd = "consul kv get enm/deprecated/global_properties/UI_PRES_SERVER"
                else:
                    cmd = "getent hosts haproxy | awk '{ print $3 }'"

                response = shell.run_cmd_on_ms(cmd)
                if response.rc == 0 and response.stdout:
                    set("httpd-hostname", "{}".format(response.stdout.strip()))

    haproxy_host = get("httpd-hostname")

    if haproxy_host is None:
        raise RuntimeError("Could not get hostname for Apache")

    return haproxy_host


def get_ms_host():
    ms_host_key = 'LMS_HOST'
    host = None
    if config.has_prop(ms_host_key):
        host = config.get_prop(ms_host_key)
    elif ms_host_key in os.environ:
        host = os.environ[ms_host_key]
    return host or 'localhost'


def is_host_ms():
    return get_ms_host() == 'localhost'


def get_vnf_laf():
    """
    Perform a check for the vnflaf key in config dict or environment

    :rtype: str
    :return: Returns either the vnflaf ip as a string or None
    """
    vnf_host_key = 'VNF_LAF'
    host = None
    if config.has_prop(vnf_host_key):
        host = config.get_prop(vnf_host_key)
    elif vnf_host_key in os.environ:
        host = os.environ[vnf_host_key]
    return host or None


def get_emp():
    """
    Perform a check for the emp key in config dict or environment

    :rtype: str
    :return: Returns either the emp ip as a string or None
    """
    emp_host_key = 'EMP'
    host = None
    # Todo: add EMP to config file
    if config.has_prop(emp_host_key):
        host = config.get_prop(emp_host_key)
    elif emp_host_key in os.environ:
        host = os.environ[emp_host_key]
    return host or None


def is_emp():
    """
    Indicate whether or not we have retrieved the key for the emp

    :rtype: bool
    :return: Returns either the emp ip as a string or None
    """
    return bool(get_emp() or is_vnf_laf())


def is_vnf_laf():
    """
    Indicate whether or not we have retrieved the key for the vnflaf

    :rtype: bool
    :return: Returns either the vnflaf ip as a string or None
    """
    return bool(get_vnf_laf() or None)


def is_enm_on_cloud():
    """
    B{Determines whether the enm environment is on the cloud or not
    :rtype: bool
    :return: True if enm is on cloud
    """
    response = shell.run_cmd_on_ms("consul kv get enm/deprecated/global_properties/DDC_ON_CLOUD")
    return bool(response.ok and response.stdout.strip() == "TRUE")


def _get_credentials(username_key, password_key):
    """
    Gets credentials from credentials file

    :raises ValueError: - If credentials can't be defined
    :returns: vm user credentials
    :rtype: tuple

    """
    if has_key(username_key) and has_key(password_key):
        return (get(username_key), get(password_key))

    credentials = config.load_credentials_from_props(username_key, password_key)

    # Check that we have VM credentials in props
    if not credentials:
        raise ValueError("Property 'vm_username' and/or 'vm_password' is undefined")

    if len(credentials) > 1:
        set(password_key, credentials[1])
    set(username_key, credentials[0])

    return credentials


def get_vm_credentials():
    """
    Gets VM credentials

    :raises ValueError: - If credentials can't be defined
    :returns: vm user credentials
    :rtype: tuple

    """
    return _get_credentials('vm_username', 'vm_password')


def get_ms_credentials():
    """
    Gets MS credentials

    :raises ValueError: - If credentials can't be defined
    :returns: MS user credentials
    :rtype: tuple

    """
    return _get_credentials('ms_username', 'ms_password')


def get_vnf_laf_credentials():
    """
    Gets VNFLAF credentials

    :raises ValueError: - If credentials can't be defined
    :returns: VNFLAF cloud user credentials

    :rtype: tuple

    """
    return _get_credentials('vnflaf_username', 'vnflaf_password')
