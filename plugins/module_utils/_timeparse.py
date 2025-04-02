# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)

SECONDS_PER_MINUTE: int = 60
SECONDS_PER_HOUR: int = 60 * SECONDS_PER_MINUTE
SECONDS_PER_DAY: int = 24 * SECONDS_PER_HOUR

import re
import math


def duration_str_to_seconds(duration: str, default: int = 0) -> int:
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

    days_regex: re.Pattern[str] = re.compile(r'(\d+\.?\d*)d')
    hours_regex: re.Pattern[str] = re.compile(r'(\d+\.?\d*)h')
    minutes_regex: re.Pattern[str] = re.compile(r'(\d+\.?\d*)m')
    seconds_regex: re.Pattern[str] = re.compile(r'(\d+\.?\d*)s')

    days_match: re.Match[str] = days_regex.search(duration)
    hours_match: re.Match[str] = hours_regex.search(duration)
    minutes_match: re.Match[str] = minutes_regex.search(duration)
    seconds_match: re.Match[str] = seconds_regex.search(duration)

    total_seconds: int = 0

    if days_match is not None:
        try:
            total_seconds += int(int(days_match.group(1)) * SECONDS_PER_DAY)
        except ValueError:
            try:
                total_seconds += int(math.floor(float(days_match.group(1))) * SECONDS_PER_DAY)
            except ValueError:
                pass

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
