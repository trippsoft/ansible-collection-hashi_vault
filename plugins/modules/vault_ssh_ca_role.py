#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_ssh_ca_role
version_added: 1.10.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures an SSH CA role in HashiCorp Vault
description:
  - >-
    Ensures an L(SSH CA role,https://python-hvac.org/en/stable/source/hvac_api_secrets_engines.html#hvac.api.secrets_engines.Ssh.create_role)
    is configured as expected in HashiCorp Vault.
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
      - The name of the role to manage.
  state:
    type: str
    default: present
    choices:
      - present
      - absent
    description:
      - Whether the role should be present or absent.
  overwrite_non_ca_role:
    type: bool
    required: false
    default: false
    description:
      - Whether to overwrite a non-CA role with the same name.
  algorithm_signer:
    type: str
    required: false
    choices:
      - default
      - ssh-rsa
      - rsa-sha2-256
      - rsa-sha2-512
    description:
      - The algorithm to use for the signer.
      - If O(state=absent), this is ignored.
      - If not provided and the role does not exist, this will default to V(default).
  allow_bare_domains:
    type: bool
    required: false
    description:
      - Whether to allow bare domains.
      - If O(state=absent), this is ignored.
      - If not provided and the role does not exist, this will default to V(false).
  allow_host_certificates:
    type: bool
    required: false
    description:
      - Whether to allow host certificates.
      - If O(state=absent), this is ignored.
      - If not provided and the role does not exist, this will default to V(false).
      - Either this or O(allow_user_certificates) must be set to V(true).
  allow_subdomains:
    type: bool
    required: false
    description:
      - Whether to allow subdomains.
      - If O(state=absent), this is ignored.
      - If not provided and the role does not exist, this will default to V(false).
  allow_user_certificates:
    type: bool
    required: false
    description:
      - Whether to allow user certificates.
      - If O(state=absent), this is ignored.
      - If not provided and the role does not exist, this will default to V(false).
      - Either this or O(allow_host_certificates) must be set to V(true).
  allow_user_key_ids:
    type: bool
    required: false
    description:
      - Whether to allow the user to specify the key ID.
      - If O(state=absent), this is ignored.
      - If not provided and the role does not exist, this will default to V(false).
  allowed_critical_options:
    type: list
    required: false
    elements: str
    description:
      - A list of critical options that are allowed to use this role.
      - If O(state=absent), this is ignored.
      - Providing an empty list will allow all critical options to be used.
      - If not provided and the role does not exist, this will default to an empty list.
  allowed_domains:
    type: list
    required: false
    elements: str
    description:
      - A list of domains that are allowed to use this role.
      - If O(state=absent), this is ignored.
      - If not provided and the role does not exist, this will default to an empty list.
  allowed_extensions:
    type: list
    required: false
    elements: str
    description:
      - A list of extensions that are allowed to use this role.
      - If O(state=absent), this is ignored.
      - If not provided and the role does not exist, this will default to an empty list.
  allowed_user_key_lengths:
    type: dict
    required: false
    description:
      - A dictionary of user key lengths that are allowed to use this role.
      - If O(state=absent), this is ignored.
      - Providing an empty dictionary will allow all key lengths to be used.
      - If not provided and the role does not exist, this will default to an empty dictionary.
    suboptions:
      rsa:
        type: list
        required: false
        elements: int
        description:
          - A list of RSA key lengths that are allowed to use this role.
          - If O(state=absent), this is ignored.
          - If not provided, the algorithm will not be allowed.
      dsa:
        type: list
        required: false
        elements: int
        description:
          - A list of DSA key lengths that are allowed to use this role.
          - If O(state=absent), this is ignored.
          - If not provided, the algorithm will not be allowed.
      ecdsa:
        type: list
        required: false
        elements: int
        description:
          - A list of ECDSA key lengths that are allowed to use this role.
          - If O(state=absent), this is ignored.
          - If not provided, the algorithm will not be allowed.
      ed25519:
        type: list
        required: false
        elements: int
        description:
          - A list of ED25519 key lengths that are allowed to use this role.
          - If O(state=absent), this is ignored.
          - If not provided, the algorithm will not be allowed.
  allowed_users:
    type: list
    required: false
    elements: str
    description:
      - A list of users that are allowed to use this role.
      - If O(state=absent), this is ignored.
      - Providing an empty list will allow all users to use this role.
      - If not provided and the role does not exist, this will default to an empty list.
  allowed_users_template:
    type: bool
    required: false
    description:
      - Whether to allow the users to be templated.
      - If O(state=absent), this is ignored.
      - If not provided and the role does not exist, this will default to V(false).
  default_critical_options:
    type: dict
    required: false
    description:
      - A dictionary of default critical options that are allowed to use this role.
      - If O(state=absent), this is ignored.
      - Providing an empty dictionary will default to no critical options.
      - If not provided and the role does not exist, this will default to an empty dictionary.
  default_extensions:
    type: dict
    required: false
    description:
      - A dictionary of default extensions that are allowed to use this role.
      - If O(state=absent), this is ignored.
      - Providing an empty dictionary will default to no extensions.
      - If not provided and the role does not exist, this will default to an empty dictionary.
  default_extensions_template:
    type: bool
    required: false
    description:
      - Whether to allow the extensions to be templated.
      - If O(state=absent), this is ignored.
      - If not provided and the role does not exist, this will default to V(false).
  default_user:
    type: str
    required: false
    description:
      - The default user to use for this role.
      - If O(state=absent), this is ignored.
      - If O(state=present), this is required.
  key_id_format:
    type: str
    required: false
    description:
      - The format of the key ID.
      - If O(state=absent), this is ignored.
      - Providing an empty string will default to the default key ID format.
      - If not provided and the role does not exist, this will default to an empty string.
  ttl:
    type: str
    required: false
    description:
      - The default expiration period for issued certificates from this role.
      - This value can be provided as a duration string, such as V(72h), or as an number of seconds.
      - If O(state=absent), this is ignored.
      - Providing V(0) will default to the secret engine V(default_lease_ttl) value.
      - If not provided and the role does not exist, this will default to V(0).
  max_ttl:
    type: str
    required: false
    description:
      - The maximum expiration period for issued certificates from this role.
      - This value can be provided as a duration string, such as V(72h), or as an number of seconds.
      - If O(state=absent), this is ignored.
      - Providing V(0) will default to the secret engine V(max_lease_ttl) value.
      - If not provided and the role does not exist, this will default to V(0).
"""

EXAMPLES = r"""
- name: Create an SSH CA role
  trippsc2.hashi_vault.vault_ssh_ca_role:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: ssh
    name: my-role
    default_user: my-user
    state: present

- name: Remove an SSH CA role
  trippsc2.hashi_vault.vault_ssh_ca_role:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: ssh
    name: my-role
    state: absent
"""

RETURN = r"""
config:
  type: dict
  returned: O(state=present)
  description:
    - The configuration of the SSH role.
  sample:
    algorithm_signer: default
    allow_bare_domains: false
    allow_host_certificates: false
    allow_subdomains: false
    allow_user_certificates: false
    allow_user_key_ids: false
    allowed_critical_options: []
    allowed_domains: []
    allowed_extensions: []
    allowed_user_key_lengths: {}
    allowed_users: []
    allowed_users_template: false
    default_critical_options: {}
    default_extensions: {}
    default_extensions_template: false
    default_user: my-user
    key_id_format: default
    max_ttl: 0
    ttl: 0
  contains:
    algorithm_signer:
      type: str
      choices:
        - default
        - ssh-rsa
        - rsa-sha2-256
        - rsa-sha2-512
      description:
        - The algorithm to use for the signer.
    allow_bare_domains:
      type: bool
      description:
        - Whether to allow bare domains.
    allow_host_certificates:
      type: bool
      description:
        - Whether to allow host certificates.
    allow_subdomains:
      type: bool
      description:
        - Whether to allow subdomains.
    allow_user_certificates:
      type: bool
      description:
        - Whether to allow user certificates.
    allow_user_key_ids:
      type: bool
      description:
        - Whether to allow the user to specify the key ID.
    allowed_critical_options:
      type: list
      elements: str
      description:
        - A list of critical options that are allowed to use this role.
    allowed_domains:
      type: list
      elements: str
      description:
        - A list of domains that are allowed to use this role.
    allowed_extensions:
      type: list
      elements: str
      description:
        - A list of extensions that are allowed to use this role.
    allowed_user_key_lengths:
      type: dict
      description:
        - A dictionary of user key lengths that are allowed to use this role.
    allowed_users:
      type: list
      elements: str
      description:
        - A list of users that are allowed to use this role.
    allowed_users_template:
      type: bool
      description:
        - Whether to allow the users to be templated.
    default_critical_options:
      type: dict
      description:
        - A dictionary of default critical options that are allowed to use this role.
    default_extensions:
      type: dict
      description:
        - A dictionary of default extensions that are allowed to use this role.
    default_extensions_template:
      type: bool
      description:
        - Whether to allow the extensions to be templated.
    default_user:
      type: str
      description:
        - The default user to use for this role.
    key_id_format:
      type: str
      description:
        - The format of the key ID.
    max_ttl:
      type: int
      description:
        - The maximum expiration period for issued certificates from this role.
    ttl:
      type: int
      description:
        - The default expiration period for issued certificates from this role.
prev_config:
  type: dict
  returned: changed
  description:
    - The previous configuration of the SSH role.
  sample:
    algorithm_signer: default
    allow_bare_domains: false
    allow_host_certificates: false
    allow_subdomains: false
    allow_user_certificates: false
    allow_user_key_ids: false
    allowed_critical_options: []
    allowed_domains: []
    allowed_extensions: []
    allowed_user_key_lengths: {}
    allowed_users: []
    allowed_users_template: false
    default_critical_options: {}
    default_extensions: {}
    default_extensions_template: false
    default_user: my-user
    key_id_format: default
    max_ttl: 0
    ttl: 0
  contains:
    algorithm_signer:
      type: str
      choices:
        - default
        - ssh-rsa
        - rsa-sha2-256
        - rsa-sha2-512
      description:
        - The algorithm to use for the signer.
    allow_bare_domains:
      type: bool
      description:
        - Whether to allow bare domains.
    allow_host_certificates:
      type: bool
      description:
        - Whether to allow host certificates.
    allow_subdomains:
      type: bool
      description:
        - Whether to allow subdomains.
    allow_user_certificates:
      type: bool
      description:
        - Whether to allow user certificates.
    allow_user_key_ids:
      type: bool
      description:
        - Whether to allow the user to specify the key ID.
    allowed_critical_options:
      type: list
      elements: str
      description:
        - A list of critical options that are allowed to use this role.
    allowed_domains:
      type: list
      elements: str
      description:
        - A list of domains that are allowed to use this role.
    allowed_extensions:
      type: list
      elements: str
      description:
        - A list of extensions that are allowed to use this role.
    allowed_user_key_lengths:
      type: dict
      description:
        - A dictionary of user key lengths that are allowed to use this role.
    allowed_users:
      type: list
      elements: str
      description:
        - A list of users that are allowed to use this role.
    allowed_users_template:
      type: bool
      description:
        - Whether to allow the users to be templated.
    default_critical_options:
      type: dict
      description:
        - A dictionary of default critical options that are allowed to use this role.
    default_extensions:
      type: dict
      description:
        - A dictionary of default extensions that are allowed to use this role.
    default_extensions_template:
      type: bool
      description:
        - Whether to allow the extensions to be templated.
    default_user:
      type: str
      description:
        - The default user to use for this role.
    key_id_format:
      type: str
      description:
        - The format of the key ID.
    max_ttl:
      type: int
      description:
        - The maximum expiration period for issued certificates from this role.
    ttl:
      type: int
      description:
        - The default expiration period for issued certificates from this role.
"""

import traceback

from ansible.module_utils.basic import missing_required_lib

from typing import List, Optional

try:
    import hvac
    import hvac.exceptions
except ImportError:
    HAS_HVAC: bool = False
    HVAC_IMPORT_ERROR: Optional[str] = traceback.format_exc()
else:
    HAS_HVAC: bool = True
    HVAC_IMPORT_ERROR: Optional[str] = None

from ..module_utils._timeparse import duration_str_to_seconds
from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultSSHCARoleModule(VaultModule):
    """
    Vault SSH CA role module.
    """

    ARGSPEC: dict = dict(
        engine_mount_point=dict(type='str', required=True),
        name=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        overwrite_non_ca_role=dict(type='bool', required=False, default=False),
        algorithm_signer=dict(type='str', required=False, choices=['default', 'ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512']),
        allow_bare_domains=dict(type='bool', required=False),
        allow_host_certificates=dict(type='bool', required=False),
        allow_subdomains=dict(type='bool', required=False),
        allow_user_certificates=dict(type='bool', required=False),
        allow_user_key_ids=dict(type='bool', required=False),
        allowed_critical_options=dict(type='list', elements='str', required=False),
        allowed_domains=dict(type='list', elements='str', required=False),
        allowed_extensions=dict(type='list', elements='str', required=False),
        allowed_user_key_lengths=dict(
            type='dict',
            required=False,
            options=dict(
                rsa=dict(type='list', elements='int', required=False),
                dsa=dict(type='list', elements='int', required=False),
                ecdsa=dict(type='list', elements='int', required=False),
                ed25519=dict(type='list', elements='int', required=False)
            )
        ),
        allowed_users=dict(type='list', elements='str', required=False),
        allowed_users_template=dict(type='bool', required=False),
        default_critical_options=dict(type='dict', required=False),
        default_extensions=dict(type='dict', required=False),
        default_extensions_template=dict(type='bool', required=False),
        default_user=dict(type='str', required=False),
        key_id_format=dict(type='str', required=False),
        max_ttl=dict(type='str', required=False),
        ttl=dict(type='str', required=False)
    )

    DEFAULT_VALUES: dict = dict(
        algorithm_signer='default',
        allow_bare_domains=False,
        allow_host_certificates=False,
        allow_subdomains=False,
        allow_user_certificates=False,
        allow_user_key_ids=False,
        allowed_critical_options=[],
        allowed_domains=[],
        allowed_extensions=[],
        allowed_user_key_lengths={},
        allowed_users=[],
        allowed_users_template=False,
        default_critical_options={},
        default_extensions={},
        default_extensions_template=False,
        default_user='',
        key_id_format='default',
        max_ttl=0,
        ttl=0
    )

    SET_COMPARE_PARAMS: List[str] = [
        'allowed_critical_options',
        'allowed_domains',
        'allowed_extensions',
        'allowed_users'
    ]

    DURATION_PARAMS: List[str] = ['max_ttl', 'ttl']

    def __init__(self, *args, **kwargs) -> None:

        argspec: dict = self.ARGSPEC.copy()

        super(VaultSSHCARoleModule, self).__init__(
            *args,
            argument_spec=argspec,
            supports_check_mode=True,
            **kwargs
        )

    def get_defined_role_params(self) -> dict:
        """
        Get the defined role parameters.

        Returns:
            dict: The defined role parameters.
        """

        filtered_params: dict = self.params.copy()

        delete_keys: List[str] = [key for key in filtered_params.keys() if key not in self.DEFAULT_VALUES.keys()]

        for key in delete_keys:
            del filtered_params[key]

        delete_keys: List[str] = [key for key, value in filtered_params.items() if value is None]

        for key in delete_keys:
            del filtered_params[key]

        for key, value in filtered_params.items():
            if key in self.DURATION_PARAMS:
                filtered_params[key] = duration_str_to_seconds(value)

        if 'allowed_user_key_lengths' in filtered_params:

            delete_keys: List[str] = [key for key, value in filtered_params['allowed_user_key_lengths'].items() if value is None]

            for key in delete_keys:
                del filtered_params['allowed_user_key_lengths'][key]

        filtered_params['key_type'] = 'ca'

        return filtered_params

    def format_role_data(self, config_data: dict) -> dict:
        """
        Format the data for an SSH CA role.

        Args:
            config_data (dict): The data to format.

        Returns:
            dict: The formatted data.
        """

        formatted_config_data: dict = {}

        key_type: str = config_data['key_type']

        formatted_config_data['key_type'] = key_type

        if key_type != 'ca':
            return formatted_config_data

        for key, value in config_data.items():
            if key in self.DEFAULT_VALUES:
                if key in self.SET_COMPARE_PARAMS:
                    formatted_config_data[key] = value.split(',')
                else:
                    formatted_config_data[key] = value

        return formatted_config_data

    def get_formatted_role_data(self) -> Optional[dict]:
        """
        Get the formatted data for an SSH CA role.

        Returns:
            dict: The formatted data for the SSH CA role.
        """

        name: str = self.params['name']
        mount_point: str = self.params['engine_mount_point']

        try:
            config: dict = self.client.secrets.ssh.read_role(name=name, mount_point=mount_point)
        except hvac.exceptions.InvalidPath:
            return None
        except hvac.exceptions.UnexpectedError:
            return None
        except hvac.exceptions.Forbidden:
            self.handle_error(
                VaultModuleError(
                    message=f"Forbidden: Permission denied to read SSH role '{name}' at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )
        except Exception:
            self.handle_error(
                VaultModuleError(
                    message=f"Error reading SSH role '{name}' at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )

        formatted_config: dict = self.format_role_data(config.get('data', dict()))

        return formatted_config

    def compare_role(self, previous_config: dict, desired_config: dict) -> dict:
        """
        Compare the previous and desired configurations of an SSH CA role.

        Args:
            previous_config (dict): The previous configuration of the SSH CA role.
            desired_config (dict): The desired configuration of the SSH CA role.

        Returns:
            dict: The comparison of the previous and desired configurations.
        """

        if previous_config['key_type'] != desired_config['key_type']:
            return desired_config

        config_diff: dict = {}

        for key, value in desired_config.items():
            if key not in previous_config:
                if key in self.SET_COMPARE_PARAMS:
                    if set(value) != set(self.DEFAULT_VALUES[key]):
                        config_diff[key] = value
                else:
                    if value != self.DEFAULT_VALUES[key]:
                        config_diff[key] = value
            else:
                if key in self.SET_COMPARE_PARAMS:
                    if set(value) != set(previous_config[key]):
                        config_diff[key] = value
                elif key == 'allowed_user_key_lengths':
                    previous_allowed_user_key_lengths: dict = previous_config['allowed_user_key_lengths']
                    allowed_user_key_lengths_diff: Optional[dict] = self.compare_allowed_user_key_lengths(
                        previous_allowed_user_key_lengths,
                        value
                    )

                    if allowed_user_key_lengths_diff is not None:
                        config_diff['allowed_user_key_lengths'] = allowed_user_key_lengths_diff
                else:
                    if value != previous_config[key]:
                        config_diff[key] = value

        return config_diff

    def compare_allowed_user_key_lengths(self, previous_config: dict, desired_config: dict) -> Optional[dict]:
        """
        Compare the allowed user key lengths of the previous and desired configurations of an SSH CA role.

        Args:
            previous_config (dict): The previous configuration of the allowed user key lengths.
            desired_config (dict): The desired configuration of the allowed user key lengths.

        Returns:
            Optional[dict]: The comparison of the previous and desired configurations.
        """

        config_diff: dict = {}

        for key, value in desired_config.items():
            if key not in previous_config:
                config_diff[key] = value
            elif set(value) != set(previous_config[key]):
                config_diff[key] = value

        if len(config_diff) > 0:
            return config_diff

        return None

    def format_payload(self, config_data: dict, previous_config_data: Optional[dict]) -> dict:
        """
        Format the payload for an SSH CA role.

        Args:
            config_data (dict): The data to format.
            previous_config_data (Optional[dict]): The previous configuration of the SSH CA role.
        Returns:
            dict: The formatted payload.
        """

        formatted_payload: dict = {}

        for key, value in config_data.items():
            if key in self.SET_COMPARE_PARAMS:
                formatted_payload[key] = ','.join(value)
            else:
                formatted_payload[key] = value

        allow_host_certificates: bool = self.params.get('allow_host_certificates', None)

        if allow_host_certificates is None:
            if previous_config_data is not None:
                allow_host_certificates = previous_config_data.get('allow_host_certificates', False)
            else:
                allow_host_certificates = False

        allow_user_certificates: bool = self.params.get('allow_user_certificates', None)

        if allow_user_certificates is None:
            if previous_config_data is not None:
                allow_user_certificates = previous_config_data.get('allow_user_certificates', False)
            else:
                allow_user_certificates = False

        formatted_payload['key_type'] = 'ca'
        formatted_payload['allow_host_certificates'] = allow_host_certificates
        formatted_payload['allow_user_certificates'] = allow_user_certificates

        return formatted_payload


def ensure_role_absent(module: VaultSSHCARoleModule, previous_role_data: Optional[dict]) -> dict:
    """
    Ensure an SSH CA role is absent.

    Args:
        module (VaultSSHCARoleModule): The module instance.
        previous_role_data (Optional[dict]): The previous role data.

    Returns:
        dict: The result of the operation.
    """

    if previous_role_data is None:
        return dict(changed=False)

    name: str = module.params['name']
    mount_point: str = module.params['engine_mount_point']
    overwrite_non_ca_role: bool = module.params['overwrite_non_ca_role']

    if previous_role_data['key_type'] != 'ca' and not overwrite_non_ca_role:
        module.handle_error(
            VaultModuleError(
                message=f"SSH role '{name}' at mount point '{mount_point}' is not a CA role and overwrite_non_ca_role is not set",
                exception=traceback.format_exc()
            )
        )

    if not module.check_mode:
        try:
            module.client.secrets.ssh.delete_role(name=name, mount_point=mount_point)
        except Exception:
            module.handle_error(
                VaultModuleError(
                    message=f"Error deleting SSH role '{name}' at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )

    return dict(changed=True, prev_role=previous_role_data)


def ensure_role_present(module: VaultSSHCARoleModule, previous_role_data: Optional[dict], desired_role_data: dict) -> dict:
    """
    Ensure an SSH CA role is present.

    Args:
        module (VaultSSHCARoleModule): The module instance.
        previous_role_data (Optional[dict]): The previous role data.
        desired_role_data (dict): The desired role data.

    Returns:
        dict: The result of the operation.
    """

    name: str = module.params['name']
    mount_point: str = module.params['engine_mount_point']
    overwrite_non_ca_role: bool = module.params['overwrite_non_ca_role']

    if previous_role_data is None:

        if not module.check_mode:
            try:
                module.client.secrets.ssh.create_role(
                    name=name,
                    mount_point=mount_point,
                    **module.format_payload(desired_role_data, previous_role_data)
                )
            except Exception:
                module.handle_error(
                    VaultModuleError(
                        message=f"Error creating SSH role '{name}' at mount point '{mount_point}'",
                        exception=traceback.format_exc()
                    )
                )

        return dict(changed=True, role=desired_role_data)

    if previous_role_data['key_type'] != 'ca' and not overwrite_non_ca_role:
        module.handle_error(
            VaultModuleError(
                message=f"SSH role '{name}' at mount point '{mount_point}' is not a CA role and overwrite_non_ca_role is not set",
                exception=traceback.format_exc()
            )
        )

    config_diff: dict = module.compare_role(
        previous_role_data,
        desired_role_data
    )

    if not config_diff:
        return dict(changed=False, role=desired_role_data)

    if not module.check_mode:
        try:
            module.client.secrets.ssh.create_role(
                name=name,
                mount_point=mount_point,
                **module.format_payload(config_diff, previous_role_data)
            )
        except Exception:
            module.handle_error(
                VaultModuleError(
                    message=f"Error updating SSH role '{name}' at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )

    return dict(changed=True, prev_role=previous_role_data, role=desired_role_data)


def run_module() -> None:

    module: VaultSSHCARoleModule = VaultSSHCARoleModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR
        )

    state: str = module.params['state']

    desired_role_data: dict = module.get_defined_role_params()

    module.initialize_client()

    previous_role_data: Optional[dict] = module.get_formatted_role_data()

    if state == 'present':
        result: dict = ensure_role_present(
            module,
            previous_role_data,
            desired_role_data
        )
    else:
        result: dict = ensure_role_absent(
            module,
            previous_role_data
        )

    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
