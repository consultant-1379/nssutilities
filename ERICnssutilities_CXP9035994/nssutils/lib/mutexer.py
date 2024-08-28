import threading
from contextlib import contextmanager

import cache
import exception
import log
import persistence

CACHE_KEY = "persistence-backed-mutex-keys"

__cache_lock = threading.RLock()


def add_mutex_key_to_cache(key):
    """
    B{Adds the key of a persistence-backed mutex to the list of keys in cache}

    @type key: str
    @param key: Key to be added to the cache

    @rtype: void
    """

    if cache.has_key(CACHE_KEY):
        cached_keys = cache.get(CACHE_KEY)
    else:
        cached_keys = []

    cached_keys.append(key)

    cache.set(CACHE_KEY, cached_keys)


def remove_mutex_key_from_cache(key):
    """
    B{Removes the key of a persistence-backed mutex from the list of keys in cache}

    @type key: str
    @param key: Key to be removed from the cache

    @rtype: void
    """

    cached_keys = cache.get(CACHE_KEY)

    if key in cached_keys:
        cached_keys.remove(key)

    cache.set(CACHE_KEY, cached_keys)


def terminate_mutexes():
    """
    B{Terminates all persistence-backed mutexes; to be invoked before exit}

    @rtype: void
    """

    cached_keys = cache.get(CACHE_KEY)
    if cached_keys:
        for key in cached_keys:
            log.logger.debug("Terminating persistence-backed mutex {0}".format(key))  # pylint: disable=logging-format-interpolation
            persistence.mutex_push(key)

        cache.set(CACHE_KEY, [])


def acquire_mutex(mutex_key):
    """
    B{Acquires the mutex with the specified key}

    @type mutex_key: str
    @param mutex_key: Mutex identifier

    @rtype: void
    """

    global __cache_lock
    with __cache_lock:
        # Grab the mutex from the cache if it already exists, or create it if it doesn't
        mutex = cache.get(mutex_key)

        if mutex is None:
            mutex = threading.Lock()
            cache.set(mutex_key, mutex)

    # Acquire the mutex
    mutex.acquire()

    with __cache_lock:
        # Store the mutex in the cache
        cache.set(mutex_key, mutex)


def release_mutex(mutex_key):
    """
    B{Releases the mutex of the specified key}

    @type mutex_key: str
    @param mutex_key: Mutex identifier
    @type persisted: bool
    @param persisted: Parameter indicating whether the mutex is to be backed in persistence

    @rtype: void
    """
    with __cache_lock:
        mutex = cache.get(mutex_key)

    # Release the mutex
    if mutex is not None:
        try:
            mutex.release()
        except Exception:
            exception.process_exception(
                "Exception raised during release of mutex: {0}".format(mutex_key))
        else:
            # Store the mutex in the cache
            with __cache_lock:
                cache.set(mutex_key, mutex)


@contextmanager
def mutex(identifier, persisted=False, timeout=30, db=None):
    """
    Context manager mutex generator

    :param identifier: string, name of the mutex.
    :param persisted: boolean, True if the mutex has already been persisted else False.
    :param timeout: int, the time to wait (in seconds) for the mutex_pop to return.
    :param db: None or database object to use.
    :return: None
    """

    if "mutex" in identifier:
        mutex_key = identifier
    else:
        mutex_key = "mutex-{0}".format(identifier)

    mutex_type = "local" if not persisted else 'persisted'
    mutex = None

    db = db or persistence

    try:
        if persisted:
            log.logger.debug("Attempting to acquire persisted mutex key: '{0}'".format(mutex_key))
            mutex = db.mutex_pop(mutex_key, timeout=timeout)
            add_mutex_key_to_cache(mutex)
        else:
            if log.logger:
                log.logger.debug("Attempting to acquire mutex: '{0}'".format(mutex_key))
            acquire_mutex(mutex_key)
        yield
    except BaseException:
        exception.process_exception("Exception raised during execution of critical area protected by {0} mutex: '{1}'".format(mutex_type, mutex_key))
        raise
    finally:
        if persisted:
            db.mutex_push(mutex)
            remove_mutex_key_from_cache(mutex)
        else:
            release_mutex(mutex_key)
