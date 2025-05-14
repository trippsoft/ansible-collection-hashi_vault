#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_ssh_sign_public_key
version_added: 1.10.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Signs an SSH public key with an SSH CA role in HashiCorp Vault
description:
  - >-
    Signs an L(SSH public key,https://python-hvac.org/en/stable/source/hvac_api_secrets_engines.html#hvac.api.secrets_engines.Ssh.sign_ssh_key)
    with an SSH CA role in HashiCorp Vault.
extends_documentation_fragment:
  - trippsc2.hashi_vault.auth
  - trippsc2.hashi_vault.connection
  - trippsc2.hashi_vault.action_group
  - trippsc2.hashi_vault.check_mode
  - trippsc2.hashi_vault.engine_mount
  - trippsc2.hashi_vault.requirements
options:
  name:
    type: str
    required: true
    description:
      - The name of the SSH CA role to use to sign the public key.
  public_key:
    type: str
    required: true
    description:
      - The SSH public key to sign.
  cert_type:
    type: str
    required: true
    choices:
      - host
      - user
    description:
      - The type of certificate to sign.
  ttl:
    type: str
    required: false
    description:
      - The TTL for the signed public key.
      - If not provided, the default TTL will be used.
  valid_principals:
    type: list
    required: false
    elements: str
    description:
      - A list of valid principals for the signed public key.
      - For O(cert_type=user), this is a list of user principals.
      - For O(cert_type=host), this is a list of host principals.
  key_id:
    type: str
    required: false
    description:
      - The key ID to use for the signed public key.
      - If not provided, the default key ID will be used.
  critical_options:
    type: dict
    required: false
    description:
      - A dictionary of critical options for the signed public key.
      - If not provided, the default critical options will be used.
  extensions:
    type: dict
    required: false
    description:
      - A dictionary of extensions for the signed public key.
      - If not provided, the default extensions will be used.
"""

EXAMPLES = r"""
- name: Sign an SSH user public key
  trippsc2.hashi_vault.vault_ssh_sign_public_key:
    name: ca_role
    public_key: |
      ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1y2+Y/
      ...
    cert_type: user
    valid_principals:
      - user@example.com

- name: Sign an SSH host public key
  trippsc2.hashi_vault.vault_ssh_sign_public_key:
    name: ca_role
    public_key: |
      ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1y2+Y/
      ...
    cert_type: host
    valid_principals:
      - host.example.com
"""

RETURN = r"""
signing_public_key:
  type: str
  returned: always
  description:
    - The public key used to sign the SSH public key.
serial_number:
  type: str
  returned: always
  description:
    - The serial number of the signed public key.
signed_key:
  type: str
  returned: always
  description:
    - The signed public key.
"""

import traceback

from ansible.module_utils.basic import missing_required_lib

from typing import List, Optional

try:
    import hvac
except ImportError:
    HAS_HVAC: bool = False
    HVAC_IMPORT_ERROR: Optional[str] = traceback.format_exc()
else:
    HAS_HVAC: bool = True
    HVAC_IMPORT_ERROR: Optional[str] = None

from ..module_utils._timeparse import duration_str_to_seconds
from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultSSHSignPublicKeyModule(VaultModule):
    """
    Vault SSH sign public key module.
    """

    ARGSPEC: dict = dict(
        engine_mount_point=dict(type='str', required=True),
        name=dict(type='str', required=True),
        public_key=dict(type='str', required=True),
        cert_type=dict(type='str', required=True, choices=['host', 'user']),
        valid_principals=dict(type='list', required=False, elements='str'),
        ttl=dict(type='str', required=False),
        key_id=dict(type='str', required=False),
        critical_options=dict(type='dict', required=False),
        extensions=dict(type='dict', required=False)
    )

    ROLE_PARAMS: List[str] = [
        'name',
        'public_key',
        'cert_type',
        'valid_principals',
        'ttl',
        'key_id',
        'critical_options',
        'extensions'
    ]

    DURATION_PARAMS: List[str] = ['ttl']

    def __init__(self, *args, **kwargs) -> None:

        argspec: dict = self.ARGSPEC.copy()

        super(VaultSSHSignPublicKeyModule, self).__init__(
            *args,
            argument_spec=argspec,
            supports_check_mode=True,
            **kwargs
        )

    def get_formatted_payload(self) -> dict:
        """
        Get the formatted payload for the SSH sign public key request.

        Returns:
            dict: The formatted payload.
        """

        payload: dict = self.params.copy()

        delete_keys: List[str] = [key for key in payload.keys() if key not in self.ROLE_PARAMS]

        for key in delete_keys:
            del payload[key]

        delete_keys: List[str] = [key for key, value in payload.items() if value is None]

        for key in delete_keys:
            del payload[key]

        for key, value in payload.items():
            if key in self.DURATION_PARAMS:
                payload[key] = duration_str_to_seconds(value)
            elif key == 'valid_principals':
                payload[key] = ','.join(value)

        return payload


def run_module() -> None:

    module: VaultSSHSignPublicKeyModule = VaultSSHSignPublicKeyModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR
        )

    mount_point: str = module.params['engine_mount_point']
    name: str = module.params['name']

    payload: dict = module.get_formatted_payload()

    module.initialize_client()

    try:
        response: dict = module.client.secrets.ssh.read_public_key(mount_point=mount_point)
        signing_public_key: str = response['data']['public_key']
    except hvac.exceptions.Forbidden:
        module.handle_error(
            VaultModuleError(
                message=f"Forbidden: Permission denied to read SSH CA key at mount point '{mount_point}'",
                exception=traceback.format_exc()
            )
        )
    except Exception:
        module.handle_error(
            VaultModuleError(
                message=f"Error reading SSH CA key at mount point '{mount_point}'",
                exception=traceback.format_exc()
            )
        )

    try:
        response: dict = module.client.secrets.ssh.sign_ssh_key(mount_point=mount_point, **payload)
    except Exception:
        module.handle_error(
            VaultModuleError(
                message=f"Error signing SSH public key with role '{name}' at mount point '{mount_point}'",
                exception=traceback.format_exc()
            )
        )

    result: dict = dict(
        changed=True,
        signing_public_key=signing_public_key,
        serial_number=response['data']['serial_number'],
        signed_key=response['data']['signed_key']
    )

    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
