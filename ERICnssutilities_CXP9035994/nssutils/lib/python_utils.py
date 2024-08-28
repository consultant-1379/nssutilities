import operator
import os
import pkgutil
import xml.etree.ElementTree as ET

from nssutils.lib import filesystem


def get_all_subclasses(cls):
    """
    :type cls: type[T]
    :rtype: set[type[U <= T]]
    """
    subclasses = cls.__subclasses__()

    for subclass in subclasses:
        subclasses += get_all_subclasses(subclass)

    return subclasses


def split_list_into_chunks(l, chunk_size):
    """
    @type l: list
    @type chunk_size: int
    @rtype: list[list]
    """
    return [l[i:i + chunk_size] for i in xrange(0, len(l), chunk_size)]


def get_from_dict(d, key_path):
    """
    Get value from nested dict.

    :type d: dict[string]
    :type key_path: list[string]
    :param key_path: Path as a list of keys. For example, for dict d, the path [1, 2, 3] returns d[1][2][3]
    :rtype: any
    """
    return reduce(operator.getitem, key_path, d)


def set_in_dict(d, key_path, value):
    """
    Set value in nested dict using list of keys representing a path. For example:
        d = {
            1: {
                2: {}
            }
        }
        (d, [1, 2, 3], "value") == d[1][2][3] = "value"

    :type d: dict[string]
    :type key_path: list[string]
    :type value: any
    """
    get_from_dict(d, key_path[:-1])[key_path[-1]] = value


def right_pad_to_number(l, number_to_reach):
    """
    Repeat the last element of the list until the list of the specified size. For example (1, 2) can be extended to (1, 2, 2, 2)

    :type l: T <= list | tuple
    :type number_to_reach: int
    :rtype: T
    """
    return l + type(l)([l[-1]]) * (number_to_reach - len(l))


def generate_enum(**named_values):
    """
    B{Generates an Enum from name-value pairs entered}
    :param named_values: name-value entries
    :type named_values: str=str
    :return:
    """
    return type('Enum', (), named_values)


def create_xml_file(xml_string, file_path):
    """
    B{Creates an XML file from a string}
    :param xml_string: string containing xml info
    :type xml_string: string
    :param file_path: The path to the file to be created
    :type file_path: string

    :return:
    """
    filesystem.touch_file(file_path)
    tree = ET.ElementTree(ET.fromstring(xml_string))
    tree.write(file_path, encoding="utf-8")


def get_files_in_package(package_name, relative_paths=False):
    """
    :type package_name: string
    :type relative_paths: bool
    :rtype: set[string]
    """
    package_path = pkgutil.get_loader(package_name).filename
    files = set(file_path for file_path in filesystem.get_files_in_directory_recursively(package_path, ends_with=".py") if not file_path.endswith("__init__.py"))

    if relative_paths:
        package_parent_path = os.path.dirname(package_path)
        files = set(os.path.relpath(file_path, package_parent_path) for file_path in files)

    return files
