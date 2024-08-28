#!/usr/bin/env python
# -*- coding: utf-8 -*-
# *************************************************************************
# Ericsson LMI                 Utility Script
# *************************************************************************
#
# (c) Ericsson LMI 2015 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property of
# Ericsson LMI. The programs may be used and/or copied only with the
# written permission from Ericsson LMI or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
#
# *************************************************************************
# Name    : security.py
# Purpose : Utility module for ENM
# *************************************************************************


import getpass
import re
import string
import time
from base64 import (standard_b64decode, standard_b64encode)

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.Util import Counter

from nssutils.lib import log

ENM_USERNAME_PATTERN = re.compile(r"^[\w\.\-]{1,255}$", re.UNICODE)
ENM_NAME_PATTERN = re.compile(r"^[\w\'\-ÁüąĄćĆœŒÂęĘÐÛ¡ÚøÜ¿âŁÀÃłÅÄÇÆÉÈËÊÍÌÏÎÑùÓÒÕÔÖÙØśŚÝûßÞáàãúåäçæéèëêíìïîñðóòõôöŹŸŻźýżþ\s]{1,255}$", re.UNICODE)


def encrypt(data_to_encrypt, password, base_64_encoding=True):
    """
    B{It encrypts the specified data based on the given passphrase}

    @type data_to_encrypt: string
    @param data_to_encrypt: String that is to be encrypted
    @type password: string
    @param password: Password to derive cipher encryption key
    @type base_64_encoding: bool
    @param base_64_encoding: Base64 encode the resulting encrypted text
    @rtype: string
    @return: Encrypted data
    """
    ctr = Counter.new(128)
    salt, key = _derive_keys(password)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    encrypted_data = cipher.encrypt(data_to_encrypt)

    if base_64_encoding:
        return standard_b64encode(encrypted_data), salt
    else:
        return encrypted_data, salt


def _derive_keys(password, salt=None):
    """
    B{It derives encryption key and salt for cipher based on the given password}

    @type password: string
    @param password: Passphrase that is used to derive encryption keys
    @type salt: string
    @param salt: Salt that should be used to digest the password
    @rtype: list[string]
    @return: The salt and cipher key generated
    """

    if salt is None:
        random_generator = random.StrongRandom()
        salt = "".join(random_generator.choice(string.printable[:94]) for _ in range(8))

    sha256_hash_func = SHA256.new(salt)
    sha256_hash_func.update(password)
    key = sha256_hash_func.digest()

    return salt, key


def decrypt(encrypted_data, password, salt="", base_64_encoding=True):
    """
    B{It decrypts the specified data based on the given passphrase}

    @type encrypted_data: string
    @param encrypted_data: Encrypted text
    @type password: string
    @param password: Passphrase to derive cipher encryption key
    @type salt: string
    @param salt: Salt used in encryption
    @type base_64_encoding: bool
    @param base_64_encoding: Base64 decode is required before decryption
    @rtype: string
    @return: Decrypted data
    """
    ctr = Counter.new(128)
    _, key = _derive_keys(password, salt)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    if base_64_encoding:
        return cipher.decrypt(standard_b64decode(encrypted_data))
    else:
        return cipher.decrypt(encrypted_data)


def prompt_for_password_with_confirmation(prompt="Please enter a password: ", confirmation_prompt="Please confirm the password: ", allow_empty=False):
    """
    B{Prompts user for password to encrypt initial password file}

    @type prompt: string
    @type allow_empty: bool
    @param allow_empty: If the user provides an empty string (i.e. just presses entry on prompt) this function will return that without confirmation
    @rtype: string
    """

    password = None
    password_read_ok = False
    while not password_read_ok:
        password = getpass.getpass(log.purple_text(prompt))

        if allow_empty and password == "":
            password_read_ok = True
        elif password:
            confirmation_password = getpass.getpass(confirmation_prompt)
            if confirmation_password == password:
                password_read_ok = True
            else:
                log.logger.warn("    Passphrase and confirmation do not match. Please, try again!\n")
                time.sleep(.1)  # Allow the logger to flush before prompting for passphrase again.

    return password


def generate_alphanumeric_string(length):
    """
    @type length: int
    @rtype: string
    """
    return "".join([random.StrongRandom().choice(string.ascii_letters + string.digits) for _ in range(length)])


def is_valid_enm_username(username):
    """
    B{Validates the inputted password according to ENM's password policy}

    @type username: string
    @rtype: bool
    """
    return bool(re.match(ENM_USERNAME_PATTERN, username))


def is_valid_enm_name_or_surname(name):
    """
    B{Validates the inputted name according to ENM's First Name and Surname policy}

    @type name: string
    @rtype: bool
    """
    return bool(re.match(ENM_NAME_PATTERN, unicode(name, "utf-8")))
