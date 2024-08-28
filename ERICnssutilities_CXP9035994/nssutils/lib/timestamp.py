import datetime
import time


def is_time_current(datetime_obj):
    """
    Checks if the time(hours and minutes) of the datetime object passed in matches the current time.

    :param datetime_obj: datetime.datetime object
    :return: boolean
    """

    result = False
    now = get_current_time()
    if now.hour == datetime_obj.hour and now.minute == datetime_obj.minute:
        result = True

    return result


def get_current_time():
    """
    B{Returns a datetime object with the current time}
    @rtype: datetime object
    """

    return datetime.datetime.now()


def get_elapsed_time(start_time):
    """
    B{Returns the elapsed time between the current time and the specified start time as a decimalized string}

    @type start_time: datetime object
    @param start_time: The start time to use for computing the elapsed time
    @rtype: string
    """

    elapsed_time = datetime.datetime.now() - start_time
    return get_string_elapsed_time(elapsed_time)


def get_elapsed_time_in_seconds(elapsed_time):
    """
    B{Converts an elapsed time in the form of a datetime.timedelta object to the total number of seconds}

    @type elapsed_time: datetime.timedelta object
    @param elapsed_time: The elapsed time (datetime.timedelta) to be converted into seconds
    @rtype: int
    """

    return (elapsed_time.microseconds + (float(elapsed_time.seconds) + elapsed_time.days * 24 * 3600) * 10 ** 6) / 10 ** 6


def get_string_elapsed_time(elapsed_time):
    """
    B{Converts the datetime.timedelta passed as a parameter to an elapsed time string rounded to 3 decimal places}

    @type elapsed_time: datetime.timedelta object
    @param elapsed_time: The elapsed time (datetime.timedelta) to be stringified
    @rtype: string
    """

    total_seconds = get_elapsed_time_in_seconds(elapsed_time)
    elapsed_time = "%.3f" % total_seconds
    return elapsed_time


def is_time_diff_greater_than_time_frame(start_time, end_time, time_frame):
    """
    Checks if the difference between the start and end time exceeds a given time frame

    :param start_time: datetime object
    :param end_time: datetime object
    :param time_frame: int, seconds

    :return: True if the difference exceeds the time frame else False
    """

    return (end_time - start_time) > datetime.timedelta(seconds=time_frame)


def get_elapsed_time_in_duration_format(start_time, completion_time):
    """
    B{Returns the elapsed time between the current time and the specified start time as a float}

    @type start_time: datetime object
    @param start_time: The start time to use for computing the time_diff
    @type completion_time: datetime object
    @param completion_time: The current time to use for computing the time_diff
    @rtype: string
    @return: duration in string format h:m:s
    """

    time_diff = ""
    elapsed_time = completion_time - start_time

    total_sec = str(elapsed_time.seconds % 60)
    total_min = str((elapsed_time.seconds % 3600) // 60)
    total_hour = str(elapsed_time.days * 24 + elapsed_time.seconds // 3600)

    if total_sec < 60:
        time_diff = str(total_sec) + " sec"
    else:
        time_diff = total_hour + "h:" + total_min + "m:" + total_sec + "s"

    return time_diff


def get_human_readable_timestamp(ts=None):
    """
    B{Returns the current time in a human readable format of YYYY/MM/DD HH:MM:SS}
    @rtype: string
    """
    date = ts or datetime.datetime.now()
    return date.strftime('%Y/%m/%d %H:%M:%S')


def get_datetime_from_js_time(ts):
    """
    Generates python datetime instance from the JS timestamp
    """
    return datetime.datetime.fromtimestamp(ts / 1000)


def get_js_timestamp(a_datetime):
    """
    Generates javascript timestamp from python datetime
    """
    return int(time.mktime(a_datetime.timetuple())) * 1000
