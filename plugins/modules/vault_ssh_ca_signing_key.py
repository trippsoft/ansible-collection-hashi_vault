#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_ssh_ca_signing_key
version_added: 1.10.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures an SSH CA key in HashiCorp Vault
description:
  - >-
    Ensures an L(SSH CA key,https://python-hvac.org/en/stable/_modules/hvac/api/secrets_engines/ssh.html#Ssh.submit_ca_information)
    is configured as expected in HashiCorp Vault.
extends_documentation_fragment:
  - trippsc2.hashi_vault.auth
  - trippsc2.hashi_vault.connection
  - trippsc2.hashi_vault.action_group
  - trippsc2.hashi_vault.check_mode
  - trippsc2.hashi_vault.engine_mount
  - trippsc2.hashi_vault.requirements
options:
  state:
    type: str
    required: false
    default: present
    choices:
      - present
      - absent
    description:
      - Whether the SSH CA key should be present or absent.
      - If O(state=present) and a key pair is already present, this will not modify the key pair.
  private_key:
    type: str
    required: false
    description:
      - The content of the private key.
      - If O(state=absent), this will be ignored.
      - If this is provided, O(public_key) must also be provided.
      - If not provided, a key pair will be generated.
  public_key:
    type: str
    required: false
    description:
      - The content of the public key.
      - If O(state=absent), this will be ignored.
      - If this is provided, O(private_key) must also be provided.
      - If not provided, a key pair will be generated.
  key_type:
    type: str
    required: false
    default: ssh-rsa
    choices:
      - ssh-rsa
      - ecdsa-sha2-nistp256
      - ecdsa-sha2-nistp384
      - ecdsa-sha2-nistp521
      - rsa
      - ec
      - ed25519
    description:
      - The type of key to use when generating a key pair.
      - If O(state=absent), this will be ignored.
      - If O(private_key) and O(public_key) are provided, this will be ignored.
  key_bits:
    type: int
    required: false
    description:
      - The number of bits to use for the key when generating a key pair.
      - If O(state=absent), this will be ignored.
      - If O(private_key) and O(public_key) are provided, this will be ignored.
      - If O(key_type=rsa) or O(key_type=ssh-rsa), this will be used and defaults to V(4096).
      - Otherwise, this will be ignored.
"""

EXAMPLES = r"""
- name: Generate an SSH CA key
  trippsc2.hashi_vault.vault_ssh_ca_signing_key:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: ssh
    state: present

- name: Generate an SSH CA key with a specific key type and bits
  trippsc2.hashi_vault.vault_ssh_ca_signing_key:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: ssh
    key_type: rsa
    key_bits: 4096
    state: present

- name: Submit an SSH CA key pair
  trippsc2.hashi_vault.vault_ssh_ca_signing_key:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: ssh
    private_key: '{{ lookup("file", "private_key.pem") }}'
    public_key: '{{ lookup("file", "public_key.pem") }}'
    state: present

- name: Remove an SSH CA key
  trippsc2.hashi_vault.vault_ssh_ca_signing_key:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: ssh
    state: absent
"""

RETURN = r"""
public_key:
  type: str
  returned: O(state=present)
  description:
    - The public key.
  sample: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1234567890
previous_public_key:
  type: str
  returned: O(state=absent) and changed
  description:
    - The previous public key.
  sample: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1234567890
"""

import traceback

from ansible.module_utils.basic import missing_required_lib

from typing import Optional

try:
    import hvac
    import hvac.exceptions
except ImportError:
    HAS_HVAC: bool = False
    HVAC_IMPORT_ERROR: Optional[str] = traceback.format_exc()
else:
    HAS_HVAC: bool = True
    HVAC_IMPORT_ERROR: Optional[str] = None

from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultSSHCASigningKeyModule(VaultModule):
    """
    Vault SSH CA Signing Key module.
    """

    ARGSPEC: dict = dict(
        engine_mount_point=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        private_key=dict(type='str', required=False, no_log=True),
        public_key=dict(type='str', required=False),
        key_type=dict(
            type='str',
            required=False,
            default='ssh-rsa',
            choices=[
                'ssh-rsa',
                'ecdsa-sha2-nistp256',
                'ecdsa-sha2-nistp384',
                'ecdsa-sha2-nistp521',
                'rsa',
                'ec',
                'ed25519'
            ]
        ),
        key_bits=dict(type='int', required=False)
    )

    def __init__(self, *args, **kwargs) -> None:

        argspec: dict = self.ARGSPEC.copy()

        super(VaultSSHCASigningKeyModule, self).__init__(
            *args,
            argument_spec=argspec,
            required_together=[
                ('private_key', 'public_key')
            ],
            supports_check_mode=True,
            **kwargs
        )

    def get_existing_public_key(self) -> Optional[str]:
        """
        Get the existing public key.

        Returns:
            Optional[str]: The existing public key.
        """

        mount_point: str = self.params['engine_mount_point']

        try:
            response: dict = self.client.secrets.ssh.read_public_key(mount_point=mount_point)
            return response['data']['public_key']
        except hvac.exceptions.InvalidRequest:
            return None
        except hvac.exceptions.Forbidden:
            self.handle_error(
                VaultModuleError(
                    message=f"Forbidden: Permission denied to read SSH CA key at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )
        except Exception:
            self.handle_error(
                VaultModuleError(
                    message=f"Error reading SSH CA key at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )

    def get_payload(self) -> dict:
        """
        Get the payload for submitting the SSH CA key.

        Returns:
            dict: The payload for submitting the SSH CA key.
        """

        mount_point: str = self.params['engine_mount_point']
        private_key: Optional[str] = self.params.get('private_key', None)
        public_key: Optional[str] = self.params.get('public_key', None)
        key_type: str = self.params['key_type']
        key_bits: Optional[int] = self.params.get('key_bits', None)

        if private_key is not None and public_key is not None:
            return dict(
                private_key=private_key,
                public_key=public_key,
                mount_point=mount_point
            )

        if key_type in ['rsa', 'ssh-rsa']:
            if key_bits is None:
                key_bits = 4096

            return dict(
                key_type=key_type,
                key_bits=key_bits,
                mount_point=mount_point
            )

        return dict(
            key_type=key_type,
            mount_point=mount_point
        )


def ensure_key_absent(module: VaultSSHCASigningKeyModule, previous_key: Optional[str]) -> dict:
    """
    Ensure that an SSH CA key is absent.

    Args:
        module (VaultSSHCASigningKeyModule): The module object.
        previous_key (Optional[str]): The previous key.

    Returns:
        dict: The result of the operation.
    """

    if previous_key is None:
        return dict(changed=False)

    mount_point: str = module.params['engine_mount_point']

    if not module.check_mode:
        try:
            module.client.secrets.ssh.delete_ca_information(mount_point=mount_point)
        except Exception:
            module.handle_error(
                VaultModuleError(
                    message=f"Error deleting SSH CA key at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )

    return dict(changed=True, previous_public_key=previous_key)


def ensure_key_present(module: VaultSSHCASigningKeyModule, previous_key: Optional[str]) -> dict:
    """
    Ensure that an SSH CA key is present.

    Args:
        module (VaultSSHCASigningKeyModule): The module object.
        previous_key (Optional[str]): The previous key.
    """

    mount_point: str = module.params['engine_mount_point']

    if previous_key is not None:
        return dict(changed=False, public_key=previous_key)

    if module.check_mode:
        return dict(changed=True)

    payload: dict = module.get_payload()

    try:
        response: dict = module.client.secrets.ssh.submit_ca_information(**payload)
        return dict(changed=True, public_key=response['data']['public_key'])
    except Exception:
        module.handle_error(
            VaultModuleError(
                message=f"Error submitting SSH CA key at mount point '{mount_point}'",
                exception=traceback.format_exc()
            )
        )


def run_module() -> None:

    module: VaultSSHCASigningKeyModule = VaultSSHCASigningKeyModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR
        )

    state: str = module.params['state']

    module.initialize_client()

    previous_key: Optional[str] = module.get_existing_public_key()

    if state == 'present':
        result: dict = ensure_key_present(
            module,
            previous_key
        )
    else:
        result: dict = ensure_key_absent(
            module,
            previous_key
        )

    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
