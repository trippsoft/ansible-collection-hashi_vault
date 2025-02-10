# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)


class VaultModuleError():
    """
    Represents an error that occurred in a Vault module.
    """

    message: str
    exception: str | None

    def __init__(self, message: str, exception: str | None = None):
        self.message = message
        self.exception = exception
