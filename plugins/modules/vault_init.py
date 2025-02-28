#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_init
version_added: 1.9.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Initializes a HashiCorp Vault instance.
description:
  - >-
    L(Initializes,https://python-hvac.org/en/stable/usage/system_backend/init.html#initialize)
    a HashiCorp Vault instance.
extends_documentation_fragment:
  - trippsc2.hashi_vault.action_group
  - trippsc2.hashi_vault.check_mode
  - trippsc2.hashi_vault.connection
  - trippsc2.hashi_vault.requirements
options:
  secret_shares:
    type: int
    required: true
    description:
      - The number of shares to split the master key into.
  secret_threshold:
    type: int
    required: true
    description:
      - The number of shares required to reconstruct the master key.
  pgp_keys:
    type: list
    required: false
    elements: str
    description:
      - The list of PGP public keys used to encrypt the output unseal keys.
  root_token_pgp_key:
    type: str
    required: false
    description:
      - The PGP public key used to encrypt the root token.
"""

EXAMPLES = r"""
- name: Initialize Vault
  trippsc2.hashi_vault.vault_init:
    url: https://vault:8201
    secret_shares: 5
    secret_threshold: 3
"""

RETURN = r"""
root_token:
  type: str
  returned: |
    changed
    not check_mode
  description:
    - The root token.
keys_hex:
  type: list
  returned: |
    changed
    not check_mode
  elements: str
  description:
    - The unseal keys in hexadecimal format.
keys_base64:
  type: list
  returned: |
    changed
    not check_mode
  elements: str
  description:
    - The unseal keys in base64 format.
"""

import traceback

from ansible_collections.community.hashi_vault.plugins.module_utils._connection_options import HashiVaultConnectionOptions
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_module import HashiVaultModule

from ..module_utils._vault_module_error import VaultModuleError

ARGSPEC = dict(
    secret_shares=dict(type='int', required=True),
    secret_threshold=dict(type='int', required=True),
    pgp_keys=dict(type='list', required=False, elements='str', no_log=True),
    root_token_pgp_key=dict(type='str', required=False, no_log=True)
)

try:
    import hvac
except ImportError:
    HAS_HVAC = False
    HVAC_IMPORT_ERROR = traceback.format_exc()

    class VaultInitModule(HashiVaultModule):
        """
        Extends HashiVaultModule to simplify the creation of Vault modules.
        """

        def __init__(
                self,
                *args,
                argument_spec: dict = None,
                **kwargs):

            if argument_spec is None:
                argument_spec = dict()

            argspec = ARGSPEC.copy()
            argspec.update(argument_spec.copy())
            argspec.update(HashiVaultConnectionOptions.ARGSPEC.copy())

            super(VaultInitModule, self).__init__(
                *args,
                argument_spec=argspec,
                supports_check_mode=True,
                **kwargs
            )

else:
    HAS_HVAC = True
    HVAC_IMPORT_ERROR = None

    class VaultInitModule(HashiVaultModule):
        """
        Extends HashiVaultModule to simplify the creation of Vault modules.
        """

        client: hvac.Client

        def __init__(
                self,
                *args,
                argument_spec: dict = None,
                **kwargs):

            if argument_spec is None:
                argument_spec = dict()

            argspec = ARGSPEC.copy()
            argspec.update(argument_spec.copy())
            argspec.update(HashiVaultConnectionOptions.ARGSPEC.copy())

            super(VaultInitModule, self).__init__(
                *args,
                argument_spec=argspec,
                supports_check_mode=True,
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

            delete_keys = [key for key in filtered_params.keys() if filtered_params[key] is None]

            for key in delete_keys:
                del filtered_params[key]

            return filtered_params

from ansible.module_utils.basic import missing_required_lib


def run_module():

    module = VaultInitModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    module.initialize_client()

    result = dict(changed=False)

    if not module.client.sys.is_initialized():

        result["changed"] = True

        if not module.check_mode:

            init_params = module.get_defined_non_connection_params()
            init_result = module.client.sys.initialize(**init_params)

            if init_result.get("keys", None) is not None:
                init_result["keys_hex"] = init_result["keys"]
                del init_result["keys"]

            result.update(init_result)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
