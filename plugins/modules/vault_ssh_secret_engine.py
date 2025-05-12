#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_ssh_secret_engine
version_added: 1.10.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures an SSH secret engine in HashiCorp Vault
description:
  - >-
    Ensures an L(SSH secret engine,https://python-hvac.org/en/stable/source/hvac_api_secrets_engines.html#hvac.api.secrets_engines.Ssh)
    is configured as expected in HashiCorp Vault.
extends_documentation_fragment:
  - trippsc2.hashi_vault.connection
  - trippsc2.hashi_vault.auth
  - trippsc2.hashi_vault.action_group
  - trippsc2.hashi_vault.check_mode
  - trippsc2.hashi_vault.engine_mount
  - trippsc2.hashi_vault.requirements
  - trippsc2.hashi_vault.secret_engine
"""

EXAMPLES = r"""
- name: Create a SSH secret engine
  trippsc2.hashi_vault.vault_ssh_secret_engine:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: secret
    state: present

- name: Remove a SSH secret engine
  trippsc2.hashi_vault.vault_ssh_secret_engine:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: secret
    state: absent
"""

RETURN = r"""
config:
  type: dict
  returned: O(state=present)
  description:
    - The configuration of the secret engine.
  sample:
    description: 'The SSH secret engine.'
    default_lease_ttl: 2678400
    max_lease_ttl: 2678400
    audit_non_hmac_request_keys: []
    audit_non_hmac_response_keys: []
    listing_visibility: unauth
    passthrough_request_headers: []
  contains:
    description:
      type: str
      description:
        - The description of the secret engine.
    default_lease_ttl:
      type: int
      description:
        - The default lease TTL of the secret engine in seconds.
    max_lease_ttl:
      type: int
      description:
        - The maximum lease TTL of the secret engine in seconds.
    audit_non_hmac_request_keys:
      type: list
      elements: str
      description:
        - The list of non-HMAC request keys to audit.
    audit_non_hmac_response_keys:
      type: list
      elements: str
      description:
        - The list of non-HMAC response keys to audit.
    listing_visibility:
      type: str
      description:
        - The listing visibility of the secret engine.
    passthrough_request_headers:
      type: list
      elements: str
      description:
        - The list of request headers to pass through.
prev_config:
  description:
    - The previous configuration of the secret engine.
  type: dict
  returned: changed
  sample:
    description: 'The SSH secret engine.'
    default_lease_ttl: 2678400
    max_lease_ttl: 2678400
    audit_non_hmac_request_keys: []
    audit_non_hmac_response_keys: []
    listing_visibility: unauth
    passthrough_request_headers: []
  contains:
    description:
      type: str
      description:
        - The description of the secret engine.
    default_lease_ttl:
      type: int
      description:
        - The default lease TTL of the secret engine in seconds.
    max_lease_ttl:
      type: int
      description:
        - The maximum lease TTL of the secret engine in seconds.
    audit_non_hmac_request_keys:
      type: list
      elements: str
      description:
        - The list of non-HMAC request keys to audit.
    audit_non_hmac_response_keys:
      type: list
      elements: str
      description:
        - The list of non-HMAC response keys to audit.
    listing_visibility:
      type: str
      description:
        - The listing visibility of the secret engine.
    passthrough_request_headers:
      type: list
      elements: str
      description:
        - The list of request headers to pass through.
"""

import traceback

try:
    import hvac
except ImportError:
    HAS_HVAC = False
    HVAC_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_HVAC = True
    HVAC_IMPORT_ERROR = None

from ansible.module_utils.basic import missing_required_lib

from typing import Optional

from ..module_utils._vault_secret_engine_module import VaultSecretEngineModule
from ..module_utils._vault_module_error import VaultModuleError


def ensure_engine_absent(
        module: VaultSecretEngineModule,
        previous_mount_config: Optional[dict],
        previous_backend_type: Optional[str]) -> dict:
    """
    Ensure that a secret engine is absent.

    Args:
        module (VaultSecretEngineModule): The module object.
        previous_mount_config (dict): The configuration of the secret engine.
        previous_backend_type (str): The backend type of the secret engine.

    Returns:
        dict: The result of the operation.
    """

    engine_mount_point: str = module.params['engine_mount_point']

    if previous_mount_config is None:
        return dict(changed=False)

    if previous_backend_type is None or previous_backend_type != 'ssh':
        module.handle_error(
            VaultModuleError(
                message=f"The secret engine at '{engine_mount_point}' has backend '{previous_backend_type}' that is not an SSH secret engine"
            )
        )

    module.disable_mount()

    return dict(changed=True, prev_config=previous_mount_config)


def ensure_engine_present(
        module: VaultSecretEngineModule,
        previous_mount_config: Optional[dict],
        previous_backend_type: Optional[str],
        desired_mount_config: dict) -> dict:
    """
    Ensure that the secret engine is present.

    Args:
        module (VaultSecretEngineModule): The module object.
        previous_mount_config (Optional[dict]): The previous configuration of the secret engine.
        previous_backend_type (Optional[str]): The backend type of the secret engine.
        desired_mount_config (dict): The desired configuration of the secret engine.

    Returns:
        dict: The result of the operation to be sent to Ansible.
    """

    engine_mount_point: str = module.params['engine_mount_point']
    replace_non_ssh_secret_engine: bool = module.params['replace_different_backend_type']

    if previous_mount_config is None:

        description: Optional[str] = desired_mount_config.pop('description', None)

        module.enable_mount(desired_mount_config)

        return dict(changed=True, config=dict(description=description, **desired_mount_config))

    if previous_backend_type is None or previous_backend_type != 'ssh':
        if not replace_non_ssh_secret_engine:
            module.handle_error(
                VaultModuleError(
                    message=f"The secret engine at '{engine_mount_point}' has backend '{previous_backend_type}' that is not an SSH secret engine"
                )
            )

        module.disable_mount()

        description: Optional[str] = desired_mount_config.pop('description', None)

        module.enable_mount(desired_mount_config)

        return dict(changed=True, config=dict(description=description, **desired_mount_config))

    mount_config_diff: dict = module.compare_mount_config(
        previous_mount_config,
        desired_mount_config
    )

    if mount_config_diff:
        module.configure_mount(mount_config_diff)

        return dict(
            changed=True,
            prev_config=previous_mount_config,
            config=desired_mount_config
        )

    return dict(changed=False, config=previous_mount_config)


def run_module() -> None:

    module = VaultSecretEngineModule(backend_type='ssh')

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    state: str = module.params.get('state')

    desired_mount_config: dict = module.get_defined_mount_config_params()

    module.initialize_client()

    previous_mount_config: Optional[dict] = module.get_formatted_mount_config()
    previous_backend_type: Optional[str] = module.get_mount_backend_type()

    if state == 'absent':
        result: dict = ensure_engine_absent(
            module,
            previous_mount_config,
            previous_backend_type
        )

    if state == 'present':
        result: dict = ensure_engine_present(
            module,
            previous_mount_config,
            previous_backend_type,
            desired_mount_config
        )

    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
