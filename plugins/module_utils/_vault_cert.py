# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)

from typing import List


def other_sans_to_list_of_str(other_sans: List[dict]) -> List[str]:
    """
    Convert a list of other SANs in dictionary format to a list of strings.

    Args:
        other_sans (list[dict]): The list of other SANs in dictionary format.

    Returns:
        list[str]: The list of other SANs in string format.
    """

    converted: List[str] = []

    for san in other_sans:
        converted.append(f"{san['oid']};{san['type']}:{san['value']}")

    return converted
