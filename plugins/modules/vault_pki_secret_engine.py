#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_pki_secret_engine
version_added: 1.0.0
author:
  - Jim Tarpley
short_description: Configures a PKI secret engine in HashiCorp Vault.
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - Creates a L(new PKI secret engine,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/pki.html),
    identified by its O(engine_mount_point) in HashiCorp Vault.
attributes:
  check_mode:
    support: full
    details:
      - This module supports check mode.
extends_documentation_fragment:
  - trippsc2.hashi_vault.attributes
  - trippsc2.hashi_vault.connection
  - trippsc2.hashi_vault.auth
  - trippsc2.hashi_vault.engine_mount
  - trippsc2.hashi_vault.secret_engine
"""

EXAMPLES = r"""
- name: Create a new PKI secret engine
  trippsc2.hashi_vault.vault_pki_secret_engine:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: secret
    state: present


- name: Remove a PKI secret engine
  trippsc2.hashi_vault.vault_pki_secret_engine:
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
  returned:
    - success
    - state is C(present)
  description:
    - The configuration of the secret engine.
  sample:
    description: 'The PKI secret engine.'
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
  returned:
    - success
    - changed
  sample:
    description: 'The PKI secret engine.'
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

from ..module_utils._vault_secret_engine_module import VaultSecretEngineModule
from ..module_utils._vault_module_error import VaultModuleError


def ensure_engine_absent(
        module: VaultSecretEngineModule,
        previous_mount_config: dict | None,
        previous_backend_type: str | None) -> dict:
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
    
    if previous_backend_type is None or previous_backend_type != 'pki':
        module.handle_error(
            VaultModuleError(
                message=f"The secret engine at '{engine_mount_point}' has backend '{previous_backend_type}' that is not a PKI secret engine"
            )
        )
    
    module.disable_mount()
    
    return dict(changed=True, prev_config=previous_mount_config)


def ensure_engine_present(
        module: VaultSecretEngineModule,
        previous_mount_config: dict | None,
        previous_backend_type: str | None,
        desired_mount_config: dict) -> dict:
    """
    Ensure that the secret engine is present.

    Args:
        client (Client): The Vault client to use.
        engine_mount_point (str): The path of the secret engine to manage.
        previous_mount_config (dict): The previous configuration of the secret engine.
        previous_backend_type (str): The backend type of the secret engine.
        desired_mount_config (dict): The desired configuration of the secret engine.
        replace_non_pki_secret_engine (bool): Whether to replace a non-PKI secret engine.
        check_mode (bool): Whether to run in check mode.
    
    Returns:
        dict: The result of the operation to be sent to Ansible.
    """

    engine_mount_point: str = module.params['engine_mount_point']
    replace_non_pki_secret_engine: bool = module.params['replace_different_backend_type']

    if previous_mount_config is None:
        
        description = desired_mount_config.pop('description', None)
        
        module.enable_mount(desired_mount_config)
        
        return dict(changed=True, config=dict(description=description, **desired_mount_config))
    
    if previous_backend_type is None or previous_backend_type != 'pki':
        if not replace_non_pki_secret_engine:
            module.handle_error(
                VaultModuleError(
                    message=f"The secret engine at '{engine_mount_point}' has backend '{previous_backend_type}' that is not a PKI secret engine"
                )
            )

        module.disable_mount()
        
        description = desired_mount_config.pop('description', None)
        
        module.enable_mount(desired_mount_config)

        return dict(changed=True, config=dict(description=description, **desired_mount_config))
    
    mount_config_diff = module.compare_mount_config(
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


def run_module():

    module = VaultSecretEngineModule(backend_type='pki')

    state: str = module.params.get('state')

    desired_mount_config = module.get_defined_mount_config_params()

    module.initialize_client()
    
    previous_mount_config = module.get_formatted_mount_config()
    previous_backend_type = module.get_mount_backend_type()

    if state == 'absent':
        result = ensure_engine_absent(
            module,
            previous_mount_config,
            previous_backend_type
        )
    
    if state == 'present':
        result = ensure_engine_present(
            module,
            previous_mount_config,
            previous_backend_type,
            desired_mount_config
        )
        
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
