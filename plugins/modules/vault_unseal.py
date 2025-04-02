#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_unseal
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Unseals a HashiCorp Vault instance.
description:
  - >-
    L(Unseals,https://python-hvac.org/en/stable/usage/system_backend/seal.html#submit-unseal-key)
    a HashiCorp Vault instance.
extends_documentation_fragment:
  - trippsc2.hashi_vault.action_group
  - trippsc2.hashi_vault.check_mode
  - trippsc2.hashi_vault.connection
  - trippsc2.hashi_vault.requirements
options:
  unseal_keys:
    type: list
    required: true
    elements: str
    description:
      - The unseal keys.
"""

EXAMPLES = r"""
- name: Initialize Vault
  trippsc2.hashi_vault.vault_unseal:
    url: https://vault:8201
    unseal_keys:
      - '4UfnusZaITwi3n5uuMAzpe1IGbDDD2Xpm5e2DiGNHi+J'
      - 'o8i+FTRrwv88B55U5zx/VTn5DAVF3bKEjt00M/FiHsHB'
      - 'aWHBkoMHL3vk1dqdLernxNOqOVGpSLMFzzZfWg2S/d9m'
      - 'fnvPn0VsR7TNc8Sf09tpCIHncdGj8E+dWTsUFEENxRbU'
      - 'dixj6QizAge9F5YILJ3Fr/+avc8X5xkf7YWUFTlgP7K+'
"""

RETURN = r"""
unsealed:
  type: bool
  returned: not check_mode
  description:
    - Whether the Vault instance was unsealed.
"""

import traceback

from ansible_collections.community.hashi_vault.plugins.module_utils._connection_options import HashiVaultConnectionOptions
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_module import HashiVaultModule

from ansible.module_utils.basic import missing_required_lib

from typing import Optional

from ..module_utils._vault_module_error import VaultModuleError

ARGSPEC: dict = dict(
    unseal_keys=dict(type='list', required=True, elements='str', no_log=True)
)

try:
    import hvac
except ImportError:
    HAS_HVAC: bool = False
    HVAC_IMPORT_ERROR: Optional[str] = traceback.format_exc()

    class VaultUnsealModule(HashiVaultModule):
        """
        Extends HashiVaultModule to simplify the creation of Vault modules.
        """

        def __init__(
                self,
                *args,
                argument_spec: Optional[dict] = None,
                **kwargs) -> None:

            argspec: dict = ARGSPEC.copy()

            if argument_spec is not None:
                argspec.update(argument_spec)

            argspec.update(HashiVaultConnectionOptions.ARGSPEC.copy())

            super(VaultUnsealModule, self).__init__(
                *args,
                argument_spec=argspec,
                supports_check_mode=True,
                **kwargs
            )

else:
    HAS_HVAC: bool = True
    HVAC_IMPORT_ERROR: Optional[str] = None

    class VaultUnsealModule(HashiVaultModule):
        """
        Extends HashiVaultModule to simplify the creation of Vault modules.
        """

        client: hvac.Client

        def __init__(
                self,
                *args,
                argument_spec: Optional[dict] = None,
                **kwargs) -> None:

            argspec: dict = ARGSPEC.copy()

            if argument_spec is not None:
                argspec.update(argument_spec)

            argspec.update(HashiVaultConnectionOptions.ARGSPEC.copy())

            super(VaultUnsealModule, self).__init__(
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
            client_args: dict = self.connection_options.get_hvac_connection_options()
            self.client = self.helper.get_vault_client(**client_args)

        def get_defined_non_connection_params(self) -> dict:
            """
            Get the defined non-connection parameters for the module.

            Returns:
                dict: The defined non-connection parameters for the module.
            """

            filtered_params: dict = self.params.copy()
            delete_keys: list[str] = [key for key in self.params.keys() if key in HashiVaultConnectionOptions.ARGSPEC]

            for key in delete_keys:
                del filtered_params[key]

            delete_keys: list[str] = [key for key in filtered_params.keys() if filtered_params[key] is None]

            for key in delete_keys:
                del filtered_params[key]

            return filtered_params


def run_module():

    module: VaultUnsealModule = VaultUnsealModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    module.initialize_client()

    result: dict = dict(changed=False)

    if not module.client.sys.is_initialized():
        module.handle_error(VaultModuleError(message="Cannot unseal a Vault that has not been initialized."))

    if module.client.sys.is_sealed():

        result["changed"] = True

        if not module.check_mode:

            result["unsealed"] = False
            reset: bool = True

            for key in module.params["unseal_keys"]:

                module.client.sys.submit_unseal_key(key=key, reset=reset)
                reset: bool = False

                if not module.client.sys.is_sealed():
                    result["unsealed"] = True
                    break

    elif not module.check_mode:
        result["unsealed"] = True

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
