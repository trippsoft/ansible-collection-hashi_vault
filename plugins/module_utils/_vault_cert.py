#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


def other_sans_to_list_of_str(other_sans: list[dict]) -> list[str]:
    """
    Convert a list of other SANs in dictionary format to a list of strings.

    Args:
        other_sans (list[dict]): The list of other SANs in dictionary format.

    Returns:
        list[str]: The list of other SANs in string format.
    """

    converted = list()

    for san in other_sans:
        converted.append(f"{san['oid']};{san['type']}:{san['value']}")

    return converted
