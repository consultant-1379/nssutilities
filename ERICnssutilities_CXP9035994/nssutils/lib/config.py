import os
import pkgutil
import shutil

import cache
import filesystem
import mutexer

NSSUTILS_PATH = pkgutil.get_loader('nssutils').filename

GLOBAL_CONFIG_DICT = {}
PROD_CONFIG_FILE = os.path.join(NSSUTILS_PATH, 'etc', 'properties.conf')


def is_a_cloud_deployment():
    """
    Checks if the ENM deployment is a cloud deployment by checking the GLOBAL_CONFIG_DICT for the emp key

    :return: bool, True if it is else False
    """

    emp_host_key = 'EMP'

    if has_prop(emp_host_key) or emp_host_key in os.environ:
        return True

    return False


def load_config(tool_class='prod', force_reload=False):
    """
    Loads all properties from a set of defined configuration files

    :param: tool_class: Denotes the type of tool being executed, if "int" is supplied the
    internal properties will be loaded as well as production props
    :type: tool_class: string
    :param: force_reload: Forces configuration to be re-read from file(s), even if it was previously loaded
    :type: force_reload: boolean

    :rtype: None

    """
    cache_key = "config-loaded"

    if not cache.has_key(cache_key) or force_reload:
        # Always load the production props
        load_config_from_file(PROD_CONFIG_FILE)
        load_local_config()
        cache.set(cache_key, True)


def parse_conf_file(config_file):
    """
    Parses the config file into a dict
    :param config_file: path of the configuration file
    :type config_file: string

    :return: parsed dict of the config file
    :rtype: dict
    """
    parsed_dict = {}
    with open(config_file) as f:
        for line in f:
            property_name, property_value = _parse_conf_line(line)
            if property_name:
                parsed_dict[property_name] = property_value
    return parsed_dict


def _parse_conf_line(line):
    """
    Parses the line from a configuration file and returns the key value pair

    :param line: A line from a configuration file
    :type line: string
    :return: The property name and property value
    :rtype: (string, string)
    """
    line = line.strip()

    if not line or line.startswith("#"):
        property_name, property_value = None, None
    elif "=" not in line:
        print "WARNING: Non-standard line in configuration file: '{}'".format(line)
        property_name, property_value = None, None
    else:
        property_name, property_value = [item.strip() for item in line.split("=", 1)]

        property_value = property_value.replace("~~~", "\n").strip()

        if property_value.startswith('"') and property_value.endswith('"'):
            property_value = property_value[1:-1]
        elif "|||" in property_value:
            property_value = [item.strip() for item in property_value.split("|||")]
        elif "," in property_value:
            property_value = [item.strip() for item in property_value.split(",")]

    return property_name, property_value


def load_config_from_file(config_file):
    """
    Loads the configuration from the config file

    :param config_file: path to the config file
    :type config_file: string

    :return: void

    """
    global GLOBAL_CONFIG_DICT
    GLOBAL_CONFIG_DICT.update(parse_conf_file(config_file))


def _write_config_to_file(config, f):
    """
    Writes a configuration to a file, overwriting if any file already exists

    :param config: Configuration to write
    :type config: dict
    :param f: Name of file to write the configuration to
    :type f: str

    :rtype: None

    """

    with open(f, 'w') as config_file:
        for key, value in config.iteritems():
            config_file.write("{key}={value}\n".format(key=key, value=value))


def update_config_file(config_file, new_property_name, new_property_value):
    """
    Updates an existing configuration file with the provided property, and adds the property if it does not already exist

    :param: config_file: Path of the configuration file
    :type: config_file: string
    :param: property_key: Name of the property that is to be updated or added
    :type: property_key: string
    :param: property_value: Value of the property that is being updated
    :type: property_value: string | list

    :returns: Returns whether or not the property already existed in the file
    :rtype: bool

    """

    if isinstance(new_property_value, basestring):
        if ("," in new_property_value or "|||" in new_property_value) and not (new_property_value.startswith('"') and new_property_value.endswith('"')):
            new_property_value = '"{}"'.format(new_property_value)
    else:
        new_property_value = ", ".join(new_property_value)

    temp_config_filename = os.path.join(os.path.dirname(config_file), ".{}.swp".format(os.path.basename(config_file)))
    updated_property = False
    with open(config_file) as source_config, open(temp_config_filename, 'w') as temp_config:
        for line in source_config:
            property_name = _parse_conf_line(line)[0]
            if property_name == new_property_name:
                line = "{} = {}\n".format(property_name, new_property_value)
                updated_property = True

            temp_config.write(line)

        if not updated_property:
            temp_config.write("{} = {}\n".format(new_property_name, new_property_value))

    shutil.move(temp_config_filename, config_file)


def load_local_config():
    """
    Loads the local configuration from the local_properties file

    :returns: void

    """
    global GLOBAL_CONFIG_DICT
    try:
        from nssutils import local_properties
    except ImportError:
        return

    for key in dir(local_properties):
        if key.isupper():
            GLOBAL_CONFIG_DICT[key] = getattr(local_properties, key)


def has_prop(key):
    """
    Checks whether the specified property exists or not

    :param: key: Key to check
    :type: key: string

    :returns: whether the specified property exists or not
    :rtype: boolean

    """

    return key in GLOBAL_CONFIG_DICT


def get_prop(key):
    """
    Returns the property or list of properties for the specified key

    :param: key: Key to check
    :type: key: string

    :returns: property or list of properties for the specified key
    :rtype: string, list of strings, or None

    """

    if not GLOBAL_CONFIG_DICT:
        load_config()

    if key not in GLOBAL_CONFIG_DICT:
        raise RuntimeError("Could not find configuration property '{0}' in configuration dictionary.".format(key))

    return GLOBAL_CONFIG_DICT[key]


def set_prop(key, value):
    """
    Sets a new property

    :param: key: Key to set
    :type: key: string
    :param: value: string or list of strings to set
    :type: value: string

    :rtype: None

    """

    global GLOBAL_CONFIG_DICT

    if GLOBAL_CONFIG_DICT is None:
        load_config()

    if value is None:
        raise RuntimeError("No value provided for " + key)

    if isinstance(value, str):
        value = value.strip()

    with mutexer.mutex("config-set-prop"):
        GLOBAL_CONFIG_DICT[key.strip()] = value


def get_config_dict():
    """
    Returns the configuration dictionary

    :returns: configuration dict
    :rtype: dict

    """

    if GLOBAL_CONFIG_DICT is None:
        load_config()

    return GLOBAL_CONFIG_DICT.copy()


def set_config_dict(config_dict):
    """
    Sets the configuration dictionary

    <br><br>NOTE: Only to be used for testing

    :param: config_dict: Dictionary to set as config dictionary
    :type: config_dict: dict

    :rtype: None

    """

    global GLOBAL_CONFIG_DICT
    GLOBAL_CONFIG_DICT = config_dict.copy()


def get_nodes_data_dir():
    """
    Returns the installation directory

    :returns: installation directory
    :rtype: str

    """
    data_file_dir_name = get_prop('data_file_dir')
    if has_prop('LOCAL_DIR'):
        return os.path.join(get_prop('LOCAL_DIR'), 'int', data_file_dir_name)
    else:
        return os.path.join(get_prop('production_dir'), 'etc', data_file_dir_name)


def get_log_dir():
    """
    Returns the log directory

    :returns: log directory
    :rtype: str

    """

    if "NSSUTILS_LOG_DIR" in os.environ:
        return os.environ["NSSUTILS_LOG_DIR"]
    if get_environ() != 'production' and has_prop('LOCAL_DIR'):
        return os.path.join(get_prop('LOCAL_DIR'), "logs")
    else:
        return os.path.join(get_prop('log_dir'))  # log_dir is full path variable


def get_redis_db_index():
    """
    Returns the redis db index based on the environment.

    :return: redis db index
    :rtype: int

    """
    production_db_index = 0

    if get_environ() != 'production' and "REDIS_DB_INDEX" in os.environ:
        return int(os.environ["REDIS_DB_INDEX"])
    elif get_environ() != 'production' and has_prop('REDIS_DB_INDEX'):
        return get_prop('REDIS_DB_INDEX')
    else:
        return production_db_index


def get_environ():
    """
    Returns the environ listed in the local_properties file.

    :return: ENVIRON property value
    :rtype: string

    """
    return get_prop('ENVIRON') if has_prop('ENVIRON') else 'production'


def load_credentials_from_props(username_key="username", password_key="password"):
    """
    Checks for the presence of a credentials properties file, and if found, loads credentials from it

    :type username_key: str
    :param username_key: The key name to use when obtaining the username from the credentials file
    :type password_key: str
    :param password_key: The key name to use when obtaining the password from the credentials file

    :rtype: tuple
    :returns: 2-element tuple consisting of (username, password) or None

    """

    credentials = ()

    internal_package = pkgutil.get_loader('nssutils')
    if not internal_package:
        return credentials

    credentials_props_file = os.path.join(internal_package.filename, "etc", "enm_credentials.conf")

    if filesystem.does_file_exist(credentials_props_file):
        credentials_dict = parse_conf_file(credentials_props_file)

        if username_key in credentials_dict and password_key in credentials_dict:
            credentials = (credentials_dict[username_key], credentials_dict[password_key])

    return credentials
