import cPickle as pickle
import copy_reg
import os
import pkgutil
import random
import string
import time

import redis

import config
import exception
import log
import multitasking
import mutexer
import shell

NSSUTILS_PATH = pkgutil.get_loader('nssutils').filename
EXTERNAL_SOURCES_DIR = os.path.join(NSSUTILS_PATH, 'external_sources')

MUTEX_DB_INDEX = 32
INDEX_MGR_DB_INDEX = 33
NODE_POOL_DB_INDEX = 34
NSSUTILS_DB_PORT = 6379


class Persistence(object):

    def __init__(self, index):
        """
        Constructor for a Persistence object.
        :param index: redis db index (int)
        :returns: None
        """
        self.port = NSSUTILS_DB_PORT
        self.daemon_started = False
        self.server_db_name = "nssutils-db-{0}".format(self.port)
        self.server_db_dir = os.path.realpath(os.path.join(EXTERNAL_SOURCES_DIR, "db"))
        self.server_db_path = os.path.join(self.server_db_dir, "nssutils-db")
        self.server_db_conf_path = os.path.join(self.server_db_dir, "nssutils-db.conf")
        self.server_dir = '/var/db/nssutils'
        self.server_cli_path = os.path.join(self.server_db_dir, "redis-cli")
        self.connection = None
        self.index = index
        self.environ = config.get_environ()  # local, jenkins, testing, production
        self.production = self.environ in ["testing", "production"]
        self.logging_enabled = log.logger is not None
        self.db_daemon = None

    def establish_connection(self):
        """
        Establishes the connection to redis or fakeredis depending on the environ setup
        :returns: None
        """
        if self.connection:
            return
        if self.production:
            if self.logging_enabled:
                log.logger.debug("Initializing client Redis connection to DB index {0} running on local port {1}".format(self.index, self.port))
            self._start_redis_daemon()
            self.connection = redis.StrictRedis(port=self.port, db=self.index)
        else:
            import fakeredis
            self.connection = fakeredis.FakeStrictRedis()

    def _start_redis_daemon(self):
        """
        Starts redis daemon if not running on the deployment
        :returns: None
        """
        if self.daemon_started:
            return

        with mutexer.mutex("persistence-start-db"):
            if not os.path.exists(self.server_dir):
                os.makedirs(self.server_dir)

            self.db_daemon = multitasking.UtilitiesExternalDaemon(self.server_db_name, [self.server_db_path, self.server_db_conf_path, "--port {0}".format(self.port)])
            db_pid = self.db_daemon.get_pid()
            cmd = shell.Command("%s -p %d ping" % (self.server_cli_path, self.port), log_cmd=self.logging_enabled)
            response = shell.run_local_cmd(cmd)
            if response.ok:
                self.daemon_started = True
            else:
                if db_pid is not None:
                    self.db_daemon.delete_pid_file()
                    self.db_daemon.pid = None

            # Start the daemon if we need to
            if not self.daemon_started:
                self.db_daemon.close_all_fds = True
                self.db_daemon.start()
                time.sleep(1)
                self.daemon_started = True

    def set(self, key, value, expiry, log_values=True):
        """
        Values are persisted with a specified expiry time (in seconds), where a negative value denotes no expiry

        :param key: key identifier for the value
        :type key: string
        :param value: object to store
        :type value: object
        :param expiry: Duration of time until the key becomes invalid (seconds). A negitive value indicates no expiry
        :type expiry: int
        :param log_values: Security option to disable writing sensitive values to logs (optional)
        :type log_values: boolean (optional)

        :returns: void

        """
        # Make sure we have sane inputs
        if not isinstance(key, str):
            raise ValueError("Could not persist data; specified key is not of type string")
        elif value is None:
            raise ValueError("Could not persist data; specified value is NoneType")
        elif expiry is None:
            raise ValueError("Could not persist data; specified expiry is NoneType")

        # Print out a message stating what we are going to persist
        if expiry >= 0:
            expiry_string = "expires in %ss" % expiry
        else:
            expiry_string = "never expires"

        if log_values and self.logging_enabled:
            log.logger.debug("  Persisting %s = %s [%s]" % (key, value, expiry_string))

        # pickle the value before persisting
        value = pickle.dumps(value, pickle.HIGHEST_PROTOCOL)

        if expiry >= 0:
            self.connection.setex(key, expiry, value)
        else:
            self.connection.set(key, value)

    def get(self, key):
        """
        Retrieves a value from persistence using the key as it's identifier

        :param key: cache key
        :type key: string

        :returns: value of the specified key
        :rtype: object; None if the key doesn't exist

        """

        value = None

        if self.has_key(key):
            try:
                value = pickle.loads(self.connection.get(key))
            except Exception as e:
                if self.logging_enabled:
                    log.logger.debug('Error getting key %s, error was: %s' % (key, str(e)))
        return value

    def get_keys(self, keys):
        """
        Retrieves all values from persistence using the keys as identifiers

        :param keys: list, keys of the values to retrieve

        :returns: list of values from the db
        :rtype: object; [] if none of the keys exist

        """
        values = []

        pipeline = self.connection.pipeline()

        try:
            for key in keys:
                pipeline.get(key)
            values = pipeline.execute()
        except:
            if self.logging_enabled:
                log.logger.debug('Error getting keys %s' % keys)

        return [pickle.loads(value) for value in values if value]

    def has_key(self, key):
        """
        Checks if key exists in storage

        :param key: key to search for
        :type key: string

        :returns: True if the database has the specified key
        :rtype: boolean

        """
        return self.connection.exists(key)

    def remove(self, key):
        """
        Removes key and value from persistence

        :param key: key to remove
        :type key: string

        :returns: 1 if the removal was successful 0 if the key was not found.
        :rtype: int

        """
        result = 0
        try:
            result = self.connection.delete(key)
        except:
            if self.logging_enabled:
                log.logger.debug('Error removing the key %s' % key)
        return result

    def get_ttl(self, key):
        """
        Determines the ttl (time to live), the amount of time before the key expires

        :param key: persisted item's identifier, used to locate the item and check it's ttl
        :type key: string

        :returns: the amount of time before the key expires
        :rtype: int or None if no ttl is found with the specified key

        """
        ttl = None
        try:
            if self.connection.exists(key):
                ttl = self.connection.ttl(key)
        except:
            if self.logging_enabled:
                log.logger.debug('Error getting ttl for key %s' % key)

        return ttl

    def update_ttl(self, key, expiry):
        """
        Updates the ttl (time to live), the amount of time before the key expires

        :param key: persisted item's identifier, used to locate the item in persistence
        :type key: string
        :param expiry: Duration of time until the key becomes invalid (seconds). A negative value indicates no expiry
        :type expiry: int

        :returns: None

        """

        try:
            if self.connection.exists(key):
                self.connection.expire(key, expiry)
        except:
            if self.logging_enabled:
                log.logger.debug('Error updating ttl for key %s' % key)

    def get_all_keys(self):
        """
        Returns a list of all keys in storage

        :returns: list of keys
        :rtype: list

        """

        key_list = None

        try:
            key_list = self.connection.keys("*")
        except:
            if self.logging_enabled:
                log.logger.debug('Error getting all keys')

        return key_list

    def clear(self):
        """
        Removes all keys from storage that do not have an infinite expiration

        NOTE: Keys that have no expiration or begin with 'permanent-' will not be cleared

        :returns: void

        """

        try:
            keys = self.get_all_keys()
            for key in keys:
                if self.connection.ttl(key) > -1 and not key.startswith("permanent-"):
                    self.remove(key)
        except:
            exception.process_exception("Exception raised while clearing persistence DB")
            raise

        if log.logger is not None:
            log.logger.debug("Persistence cleared successfully [index {0}]".format(self.index))
        else:
            print "Persistence cleared successfully [index {0}]".format(self.index)

    def clear_all(self):
        """
        Removes all keys from storage

        :returns: void

        """

        result = False

        try:
            result = self.connection.flushdb()
        except:
            exception.process_exception("Exception raised while forcefully clearing persistence DB")
            raise

        if log.logger is not None:
            log.logger.debug("Successfully executed forceful clear of persistence DB [index {0}]".format(self.index))
        else:
            print "Successfully executed forceful clear of persistence DB [index {0}]".format(self.index)

        return result

    def publish(self, channel, msg):
        """
        Publishes the message to the specified channel

        :param channel: Channel to which message will be published
        :type channel: str
        :param msg: Message to be published
        :type msg: str

        :returns: void

        """

        self.connection.publish(channel, msg)

    def subscribe(self, channel):
        """
        Subscribes to the specified channel; messages are yielded to the caller

        :param channel: Channel to subscribe to
        :type channel: str

        :returns: void

        """
        subscription = self.connection.pubsub()
        subscription.subscribe([channel])

        for msg in subscription.listen():
            if "data" in msg and len(str(msg['data'])) > 1:
                yield str(msg['data'])

    def mutex_pop(self, identifier, timeout=30):
        """
        Obtains a mutex lock for a specified identifier

        :param identifier: Identifier to use for the queue name
        :type identifier: str
        :param timeout: Time to wait (in seconds) for the pop to return
        :type timeout: int

        :returns: tuple containing key and val from the mutex
        :rtype: tuple

        """

        # This idea stolen from Redlock-py library

        val = get_unique_id()

        while not self.connection.set(identifier, val, nx=True, px=timeout * 1000):
            time.sleep(0.2)
        return identifier, val

    def mutex_push(self, mutex):
        """
        Does a push of a token value onto the queue linked to the passed identifier}

        :type mutex: tuple
        :param mutex: tuple containing key and val for the mutex

        :returns: void

        """

        # This idea stolen from Redlock-py library

        unlock_script = """
                if redis.call("get",KEYS[1]) == ARGV[1] then
                    return redis.call("del",KEYS[1])
                else
                    return 0
                end"""
        try:
            self.connection.eval(unlock_script, 1, mutex[0], mutex[1])
        except Exception as e:
            log.logger.debug('Could not release lock. Reason "%s"' % str(e))

    def _is_expired(self, key):
        """
        Returns True if the persistence object has expired

        :param key: identifier for the persistence object
        :type key: str

        :returns: True if the persistence object has expired
        :rtype: boolean

        """
        return self.connection.get(key) is None

    def save(self):
        """
        Saves a snapshot of the Redis Db at the moment it is issued
        Snapshot stored in location specified under 'dir' in the nssutils-db.conf file

        """
        self.connection.save()

    def shutdown(self):
        """
        Shutdown the Redis process. Stops all persistence

        """
        self.connection.shutdown()

    @classmethod
    def get_db(cls, index):
        """
        classmethod to create a singleton instance of a Database connection for given name, if a connection does not already exist.

        :param index: Database index
        :type index: int

        :returns: Persistence object
        :rtype: object

        """
        index_str = 'db%d' % index

        if index_str not in cls.__dict__:
            db = cls(index=index)
            db.establish_connection()
            setattr(cls, index_str, db)
        return getattr(cls, index_str)


# Below are the helper functions to delegate the persistence operations on the persistence object
# This is for backword compatibility across the api

def get_db(index=None):
    """
    Returns the persistence object if exists otherwise create a new persistence connection

    :param index: Db index
    :type index: int

    :returns: Persistence object (singleton)
    :rtype: object

    """

    return Persistence.get_db(index=index)


def default_db():
    """
    Returns the default pesistence object using the redis db index.

    :returns: default persistence object
    :rtype: object

    """
    return Persistence.get_db(config.get_redis_db_index())


def mutex_db():
    """
    Returns the mutex persistence object.

    :returns: mutex persistence object
    :rtype: object

    """
    return Persistence.get_db(MUTEX_DB_INDEX)


def index_db():
    """
    Returns the index manager persistence object.

    :returns: index manager persistence object
    :rtype: object

    """
    return Persistence.get_db(INDEX_MGR_DB_INDEX)


def node_pool_db():
    """
    Returns the node pool persistence object.

    :returns: node pool persistence object
    :rtype: object

    """
    return Persistence.get_db(NODE_POOL_DB_INDEX)


def set(*args, **kwargs):  # pylint: disable=redefined-builtin
    """
    Values are persisted with a specified expiry time (in seconds), where a negative value denotes no expiry

    :param args: An ordered list of arguments required to persist an object, [key, value, expiry], where key (string) is the identifier used to persist the value under, value is the object to persist and expiry (int) is the time in seconds to persist the object for.
    :type args: list
    :param kwargs: A dictionary of optional keyword arguments used in persisting an object, {log_values: True}, where log_values specifies if the persistence of the object is logged
    :type kwargs: dict

    :returns: void

    """
    in_mutex_db = mutex_db().has_key(args[0])
    return mutex_db().set(*args, **kwargs) if in_mutex_db else default_db().set(*args, **kwargs)


def get(*args, **kwargs):
    """
    Retrieves a value from either the default or mutex persistence objects using the key as it's identifier

    :param args: An ordered list of arguments required to retrieve a value, [key] key (string) to retrieve the value
    :type args: list

    :returns: object from persistence; None if the key doesn't exist
    :rtype: object or None

    """
    return mutex_db().get(*args, **kwargs) or default_db().get(*args, **kwargs)


def get_keys(*args, **kwargs):
    """
    Retrieves a list of values from either the default or mutex persistence objects using the keys as identifiers

    :param args: An ordered list of arguments required to retrieve a value, [key] key (string) to retrieve the value
    :type args: list

    :returns: object from persistence; [] if none of the keys exist
    :rtype: object or None

    """

    return mutex_db().get_keys(*args, **kwargs) or default_db().get_keys(*args, **kwargs)


def remove(*args, **kwargs):
    """
    Removes an object from either the default or mutex persistence objects using the key as it's identifier.

    :param args: An ordered list of arguments required to remove an object, [key] key (string) to remove
    :type args: list

    :returns: return code of 1(Success) or 0(Fail)
    :rtype: int

    """
    return default_db().remove(*args, **kwargs) or mutex_db().remove(*args, **kwargs)


def get_ttl(*args, **kwargs):
    """
    Returns the ttl (time to live), the amount of time before the key expires

    :param args: An ordered list of arguments required to return the ttl, [key] key (string) of the persistence object.
    :type args: list

    :returns: the amount of time before the key expires;
    :rtype: int or None

    """
    return default_db().get_ttl(*args, **kwargs)


def update_ttl(*args, **kwargs):
    """
    Updates the ttl (time to live), the amount of time before the key expires

    :param args: An ordered list of arguments required to update the ttl, [key, expiry] key (string) of the persistence object, expiry (int) of the ttl.
    :type args: list

    :returns: void

    """
    return default_db().update_ttl(*args, **kwargs)


def has_key(*args, **kwargs):
    """
    Checks if key exists in either the default or mutex persistence objects

    :param args: An ordered list of arguments required to check if key exists in either the default or mutex persistence objects, [key] key (string) to search for.
    :type args: list

    :returns: True if the database has the specified key
    :rtype: boolean

    """
    return default_db().has_key(*args, **kwargs) or mutex_db().has_key(*args, **kwargs)


def clear(*args, **kwargs):
    """
    Removes all keys from storage that do not have an infinite expiration.
    NOTE: Keys that have no expiration or begin with 'permanent-' will not be cleared

    :return:void

    """
    rc1 = default_db().clear(*args, **kwargs)
    rc2 = mutex_db().clear(*args, **kwargs)
    return rc1 and rc2


def clear_all(*args, **kwargs):
    """
    Removes all keys from storage including those persisted infinitely

    :returns: void

    """
    rc1 = default_db().clear_all(*args, **kwargs)
    rc2 = mutex_db().clear_all(*args, **kwargs)
    return rc1 and rc2


def get_all_keys(*args, **kwargs):
    """
    Returns a list of all keys in the default or mutex persistence objects

    :returns: list of keys
    :rtype: list

    """
    db_keys = default_db().get_all_keys(*args, **kwargs)
    db_keys.extend(mutex_db().get_all_keys(*args, **kwargs))
    db_keys.sort()
    return db_keys


def publish(*args, **kwargs):
    """
    Publishes the message to the specified channel

    :param args: An ordered list of arguments required to publishes the message, [channel,msg], where channel (string) is the channel to which message will be published, msg (str) message to be published.
    :type channel: list

    :returns: void

    """
    return default_db().publish(*args, **kwargs)


def subscribe(*args, **kwargs):
    """
    Subscribes to the specified channel; messages are yielded to the caller

    :param args:An ordered list of arguments required to subscribe to a specified channel,[channel] where channel (string) is the channel to which message will be published, msg (str) message to be published.
    :type args: list

    :returns: void

    """
    return default_db().subscribe(*args, **kwargs)


def mutex_pop(*args, **kwargs):
    """
    Obtains a mutex lock for a specified identifier

    :param args: An ordered list of arguments required to obtain a mutex lock, [identifier] identifier (string) to use for the queue name.
    :type args: list
    :param kwargs: A dictionary of optional keyword arguments, {timeout:30} where timeout specifies time to wait (in seconds) for the pop to return.
    :type kwargs: dict

    :returns: tuple containing key and val from the mutex
    :rtype: tuple

    """
    return mutex_db().mutex_pop(*args, **kwargs)


def mutex_push(*args, **kwargs):
    """
    Returns a mutex lock for the specified identifier

    :param args: An ordered list of arguments required to return a mutex lock for the specified identifier, [mutex](tuple) containing key and val for the mutex
    :type args: list

    :return:void

    """
    return mutex_db().mutex_push(*args, **kwargs)


def _is_expired(*args, **kwargs):
    """
    Returns True if the persistence object has expired

    :param args: An ordered list of arguments required to check if the persistence object has expired, [key] (string) identifier for the persistence object
    :type args: list

    :returns: True if the persistence object has expired
    :rtype: boolean

    """
    return default_db()._is_expired(*args, **kwargs)


def save(*args, **kwargs):
    """
    Saves a snapshot of the Redis Db at the moment it is issued
    Snapshot stored in location specified under 'dir' in the nssutils-db.conf file

    """
    return default_db().save(*args, **kwargs)


def shutdown(*args, **kwargs):
    """
    Shutdown the Redis process. Stops all persistence

    """
    return default_db().shutdown(*args, **kwargs)


def get_unique_id():
    """
    Generates a random id

    :returns: random id
    :rtype: str

    """
    CHARACTERS = string.ascii_letters + string.digits
    return ''.join(random.choice(CHARACTERS) for _ in range(22))


class picklable_boundmethod(object):
    def __init__(self, method):
        self.method = method

    def __getstate__(self):
        return self.method.im_self, self.method.im_func.__name__

    def __setstate__(self, (s, fn)):
        self.method = getattr(s, fn)

    def __call__(self, *args, **kwargs):
        return self.method(*args, **kwargs)


def pickle_obj_state(inst_state):
    kwargs = inst_state.__dict__
    klass = inst_state.__class__
    return unpickle_obj_state, (klass, kwargs)


def unpickle_obj_state(klass, kwargs):
    if hasattr(klass, 'REPLACE_CLASS'):
        klass = klass.REPLACE_CLASS
    return klass(**kwargs)


def persistable(klass):
    copy_reg.pickle(klass, pickle_obj_state)
    return klass
