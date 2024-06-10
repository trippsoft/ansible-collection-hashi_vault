#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 60 * SECONDS_PER_MINUTE
SECONDS_PER_DAY = 24 * SECONDS_PER_HOUR

import re
import math


def duration_str_to_seconds(duration:str, default:int=0) -> int:
    """
    Convert a duration string to seconds.

    Args:
        duration (str): The duration string to convert.
        default (int): The default value to return if the duration string is invalid.

    Returns:
        int: The number of seconds represented by the duration string.
    """

    try:
        return int(duration)
    except ValueError:
        pass

    try:
        return int(math.floor(float(duration)))
    except ValueError:
        pass

    hours_regex = re.compile(r'(\d+\.?\d*)h')
    minutes_regex = re.compile(r'(\d+\.?\d*)m')
    seconds_regex = re.compile(r'(\d+\.?\d*)s')

    hours_match = hours_regex.search(duration)
    minutes_match = minutes_regex.search(duration)
    seconds_match = seconds_regex.search(duration)

    total_seconds = 0

    if hours_match is not None:
        try:
            total_seconds += int(int(hours_match.group(1)) * SECONDS_PER_HOUR)
        except ValueError:
            try:
                total_seconds += int(math.floor(float(hours_match.group(1))) * SECONDS_PER_HOUR)
            except ValueError:
                pass
    
    if minutes_match is not None:
        try:
            total_seconds += int(int(minutes_match.group(1)) * SECONDS_PER_MINUTE)
        except ValueError:
            try:
                total_seconds += int(math.floor(float(minutes_match.group(1))) * SECONDS_PER_MINUTE)
            except ValueError:
                pass

    if seconds_match is not None:
        try:
            total_seconds += int(seconds_match.group(1))
        except ValueError:
            try:
                total_seconds += int(math.floor(float(seconds_match.group(1))))
            except ValueError:
                pass

    return total_seconds if total_seconds > 0 else default
