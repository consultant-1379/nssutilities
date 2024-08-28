import re

import exception
import network


def yields_valid_fqdn(host):
    """
    B{Verfiies that a FQDN can be obtained from the specified hostname or IP address}

    @type host: string
    @param host: Hostname or IP address
    @rtype: boolean
    """
    result = False

    if network.get_fqdn(host) is not None:
        result = True

    return result


def is_valid_email_address(address):
    """
    B{Verifies that the user-specified email address is correctly formatted}

    @type address: string
    @param address: Email address to verify
    @rtype: boolean
    """

    result = False
    if isinstance(address, str):
        if re.match(r"^([A-Za-z0-9_\-\.])+\@([A-Za-z0-9_\-\.])+\.([A-Za-z]{2,4})$", address) and len(address) <= 255:
            result = True

    return result


def is_valid_range(range_start, range_end):
    """
    B{Verifies the specified range ex. '5-10'}

    NOTE: Negative ranges are not supported, all values must be positive
    NOTE: Range is inclusive of end values

    @type range_start: int
    @param range_start: Start of the range
    @type range_end: int
    @param range_end: End of the range
    @rtype: boolean
    """

    result = False

    if isinstance(range_start, int) and isinstance(range_end, int) and range_start >= 0 and range_end >= 0 and range_end >= range_start:
        result = True

    return result


def is_valid_version_number(version_number):
    """
    B{Verifies the format of a version number}

    @type version_number: string
    @param version_number: the version number that needs to be checked
    @rtype: boolean
    """

    result = True

    try:
        # Check that the version number contains only numbers and dots
        if "-" in version_number or not re.match(r"[\d.]", version_number):
            result = False
    except AttributeError:
        result = False

    return result


def is_valid_hostname(hostname):
    """
    B{Verifies that the provided hostname is valid}

    @type hostname: str
    @param hostname: Hostname to validate
    @rtype: bool
    @return: Whether or not the provided hostname is valid
    """
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        # Strip exactly one dot from the right, if present
        hostname = hostname[:-1]

    # Non-highest level components of a hostname can be alphanumeric and have dashes (e.g. host1-23.athtem.999.ericsson')
    valid_hostname_component_pattern = re.compile(r'(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)
    non_top_level_components_are_valid = all(valid_hostname_component_pattern.match(hostname_component) for hostname_component in hostname.split(".")[:-1])

    # Highest level component in the hostname can not be entirely numeric
    valid_top_level_component_pattern = re.compile(r'(?!^\d+$)^.+$', re.IGNORECASE)
    top_level_component_is_valid = bool(valid_top_level_component_pattern.match(hostname.split(".")[-1]))

    return non_top_level_components_are_valid and top_level_component_is_valid


def validate_fqdn(host):
    """
    B{Validates that a fully qualified domain name can be obtained from the specified hostname or IP address}

    @type host: string
    @param host: Hostname or IP address
    @rtype: void
    """

    if not yields_valid_fqdn(host):
        exception.handle_invalid_argument("No fully-qualified domain name could be obtained for specified host {0}".format(host))


def validate_version_number(version_number):
    """
    B{Validates that the specified version number is formatted correctly}

    @type version_number: string
    @param version_number: the version number that needs to be checked
    @rtype: void
    """

    if not is_valid_version_number(version_number):
        exception.handle_invalid_argument("The specified version number ({0}) is not formatted correctly".format(version_number))


def validate_email_address(email_address):
    """
    B{Validates that the user-specified email addresses is properly formatted}

    @type email_address: string
    @param email_address: Email address
    @rtype: void
    """

    if not is_valid_email_address(email_address):
        exception.handle_invalid_argument("The specified email address ({0}) is not formatted correctly".format(email_address))


def validate_range(range_start, range_end):
    """
    B{Validates the specified range ex. '5-10'}

    NOTE: Negative ranges are not supported, all values must be positive
    NOTE: Range is inclusive of end values

    @type range_start: int
    @param range_start: Start of the range
    @type range_end: int
    @param range_end: End of the range
    @rtype: void
    """

    if not is_valid_range(range_start, range_end):
        exception.handle_invalid_argument("The specified numerical range ({0}-{1}) is not formatted correctly".format(range_start, range_end))


def is_valid_port_number(port_number):
    """
    B{To check for a valid port number}

    @type port_number: (int | str)
    @param port_number: Port Number
    @rtype: bool
    """
    return 1 <= int(port_number) <= 65535
