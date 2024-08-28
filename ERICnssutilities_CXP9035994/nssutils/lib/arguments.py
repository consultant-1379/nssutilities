import string

from random import choice

import validator


def get_numeric_range(number_range):
    """
    B{Returns the start and end index from the specified range [inclusively]}

    NOTE: If a single number is specified rather than a range then the start and end range will be set to this

    @type number_range: string
    @param number_range: String representation of a range ex. 5-10, or simply a number if no range given
    @rtype: tuple
    @return: Tuple where index 0 is the start range and index 1 is the end range
    """

    lower_bound = None
    upper_bound = None

    if isinstance(number_range, str):
        if "-" not in number_range:
            try:
                lower_bound = int(number_range)
                upper_bound = int(number_range)
            except ValueError:
                pass
        else:
            range_bounds = number_range.split("-")

            if len(range_bounds) == 2:
                try:
                    lower_bound = int(range_bounds[0].strip())
                    upper_bound = int(range_bounds[1].strip())
                except ValueError:
                    pass

    # Validate the range and exit if the range isn't valid
    validator.validate_range(lower_bound, upper_bound)

    return (lower_bound, upper_bound)


def get_email_addresses(email_addresses):
    """
    B{Processes user-specified email addresses}

    @type email_addresses: string
    @param email_addresses: Comma-delimited list of one or more email addresses
    @rtype: list
    @return: validated_emails
    """

    # If we have been given more than one address, split them out
    if not isinstance(email_addresses, str):
        addresses = [str(email_addresses)]
    elif "," in email_addresses:
        addresses = email_addresses.split(",")

        # Silently remove any duplicates (don't fail)
        addresses = list(set(addresses))
    else:
        addresses = [email_addresses]

    # Remove any whitespace
    addresses = [address.strip() for address in addresses]

    # Iterate over the email addresses and make sure that each one is valid
    for address in addresses:
        validator.validate_email_address(address)

    return addresses


# Putting it in because there is nowhere else to put it .......
def get_random_string(size=8, exclude=None, password=False):
    """
    B{Generates a random string of the specified size (defaults to 8 characters)}

    @type size: int
    @param size: Number of characters to include in random string
    @type exclude: string
    @param exclude: Characters that are to be excluded from selection

    @rtype: string
    """

    characters = string.ascii_letters + string.digits

    if exclude is not None:
        for char in exclude:
            characters = characters.replace(char, "")

    chars = ''.join(choice(characters) for _ in range(size))
    if password:
        chars = chars[:-4] + "H.8z"

    return chars


def grouper(sequence, n):
    return zip(*[iter(sequence)] * n)
