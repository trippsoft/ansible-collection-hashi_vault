#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import hvac
import traceback

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.hashi_vault.plugins.module_utils._authenticator import HashiVaultAuthenticator
from ansible_collections.community.hashi_vault.plugins.module_utils._connection_options import HashiVaultConnectionOptions
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultValueError
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_module import HashiVaultModule

from ._vault_module_error import VaultModuleError


class VaultModule(HashiVaultModule):
    """
    Extends HashiVaultModule to simplify the creation of Vault modules.
    """

    client: hvac.Client

    def __init__(
            self,
            *args,
            argument_spec: dict = dict(),
            **kwargs):
        
        argspec = HashiVaultModule.generate_argspec(**argument_spec)

        super(VaultModule, self).__init__(
            *args,
            argument_spec=argspec,
            **kwargs
        )


    def handle_error(self, error) -> None:
        """
        Handle an error, if it occurred, in the module.

        Args:
            error (Any): A value that could be a VaultModuleError.
        """
        
        if isinstance(error, VaultModuleError):
            self.fail_json(msg=error.message, exception=error.exception)


    def initialize_client(self) -> None:
        """
        Initializes and authenticates the Vault client.
        If an error occurs, the module failure is handled.
        """
        
        self.connection_options.process_connection_options()
        client_args = self.connection_options.get_hvac_connection_options()
        self.client = self.helper.get_vault_client(**client_args)

        try:
            self.authenticator.validate()
            self.authenticator.authenticate(self.client)
        except (NotImplementedError, HashiVaultValueError) as e:
            self.fail_json(msg=to_native(e), exception=traceback.format_exc())


    def get_defined_non_connection_params(self) -> dict:
        """
        Get the defined non-connection parameters for the module.

        Returns:
            dict: The defined non-connection parameters for the module.
        """

        filtered_params = self.params.copy()
        delete_keys = [key for key in self.params.keys() if key in HashiVaultConnectionOptions.ARGSPEC]

        for key in delete_keys:
            del filtered_params[key]
        
        delete_keys = [key for key in self.params.keys() if key in HashiVaultAuthenticator.ARGSPEC]

        for key in delete_keys:
            del filtered_params[key]

        delete_keys = [key for key in self.params.keys() if self.params[key] is None]

        for key in delete_keys:
            del filtered_params[key]

        return filtered_params
