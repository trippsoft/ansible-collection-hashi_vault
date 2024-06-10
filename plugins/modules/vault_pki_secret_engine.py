#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_pki_secret_engine
version_added: 1.0.0
author:
  - Jim Tarpley (jtarpley@ismro.com)
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
  - community.hashi_vault.attributes
  - community.hashi_vault.attributes.action_group
  - community.hashi_vault.connection
  - community.hashi_vault.auth
  - community.hashi_vault.engine_mount
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

RETURN = r""""""

import traceback

import hvac

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_module import HashiVaultModule
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultValueError

from ..module_utils._timeparse import duration_str_to_seconds
from ..module_utils._vault_secret_engine import (
    get_secret_engine_argspec,
    get_mount_backend_type,
    get_formatted_mount_config,
    compare_mount_config,
    disable_mount,
    enable_mount,
    configure_mount
)


def ensure_engine_absent(
    module: HashiVaultModule,
    client: hvac.Client,
    engine_mount_point: str,
    previous_mount_config: dict,
    previous_backend_type: str | None) -> dict | Exception:
    """
    Ensure that a secret engine is absent.

    Args:
        module (HashiVaultModule): The module using this function.
        client (hvac.Client): The Vault client to use.
        engine_mount_point (str): The mount point of the secret engine.
        previous_mount_config (dict): The configuration of the secret engine.
        previous_backend_type (str): The backend type of the secret engine.

    Returns:
        dict: The result of the operation.
    """

    if previous_mount_config is None:
        return dict(changed=False)
    
    if previous_backend_type is None or previous_backend_type != 'pki':
        try:
            raise Exception(f"The secret engine at '{engine_mount_point}' has backend '{previous_backend_type}' that is not a PKI secret engine")
        except Exception as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())
            return e
    
    result = disable_mount(module, client, engine_mount_point)

    if result is Exception:
        return result
    
    return dict(changed=True, prev_config=previous_mount_config)


def ensure_engine_present(
        module: HashiVaultModule,
        client: hvac.Client,
        engine_mount_point: str,
        previous_mount_config: dict | None,
        previous_backend_type: str | None,
        desired_mount_config: dict,
        replace_non_pki_secret_engine: bool) -> dict | Exception:
    """
    Ensure that the secret engine is present.

    Args:
        module (HashiVaultModule): The module using this function.
        client (Client): The Vault client to use.
        engine_mount_point (str): The path of the secret engine to manage.
        previous_mount_config (dict): The previous configuration of the secret engine.
        previous_backend_type (str): The backend type of the secret engine.
        desired_mount_config (dict): The desired configuration of the secret engine.
        replace_non_pki_secret_engine (bool): Whether to replace a non-PKI secret engine.
    
    Returns:
        dict: The result of the operation to be sent to Ansible.
    """

    if previous_mount_config is None:
        description = desired_mount_config.pop('description', None)
        
        result = enable_mount(
            module,
            client,
            'pki',
            engine_mount_point,
            description,
            desired_mount_config
        )

        if result is Exception:
            return result
        
        return dict(changed=True, config=dict(description=description, **desired_mount_config))
    
    if previous_backend_type is None or previous_backend_type != 'pki':
        if not replace_non_pki_secret_engine:
            try:
                raise Exception(f"The secret engine at '{engine_mount_point}' has backend '{previous_backend_type}' that is not a PKI secret engine")
            except Exception as e:
                module.fail_json(msg=to_native(e), exception=traceback.format_exc())
                return e

        result = disable_mount(module, client, engine_mount_point)

        if result is Exception:
            return result
        
        description = desired_mount_config.pop('description', None)
        
        result = enable_mount(
            module,
            client,
            'pki',
            engine_mount_point,
            description,
            desired_mount_config
        )

        if result is Exception:
            return result
        
        return dict(changed=True, config=dict(description=description, **desired_mount_config))
    
    mount_config_diff = compare_mount_config(previous_mount_config, desired_mount_config)

    if mount_config_diff:
        result = configure_mount(module, client, engine_mount_point, mount_config_diff)

        if result is Exception:
            return result
    
        return dict(
            changed=True,
            prev_config=dict(**previous_mount_config),
            config=dict(**desired_mount_config)
        )
    
    return dict(changed=False, config=dict(**previous_mount_config))


def run_module():
    argspec = HashiVaultModule.generate_argspec(
        **get_secret_engine_argspec()
    )

    module = HashiVaultModule(argument_spec=argspec, supports_check_mode=True)

    engine_mount_point: str = module.params.get('engine_mount_point')
    state: str = module.params.get('state')
    replace_non_pki_secret_engine: bool = module.params.get('replace_different_backend_type')

    desired_mount_config = dict()

    if module.params.get('description') is not None:
        desired_mount_config['description'] = module.params.get('description')

    if module.params.get('default_lease_ttl') is not None:
        desired_mount_config['default_lease_ttl'] = duration_str_to_seconds(module.params.get('default_lease_ttl'))
    
    if module.params.get('max_lease_ttl') is not None:
        desired_mount_config['max_lease_ttl'] = duration_str_to_seconds(module.params.get('max_lease_ttl'))
    
    if module.params.get('audit_non_hmac_request_keys') is not None:
        desired_mount_config['audit_non_hmac_request_keys'] = module.params.get('audit_non_hmac_request_keys')
    
    if module.params.get('audit_non_hmac_response_keys') is not None:
        desired_mount_config['audit_non_hmac_response_keys'] = module.params.get('audit_non_hmac_response_keys')

    if module.params.get('listing_visibility') is not None:
        desired_mount_config['listing_visibility'] = module.params.get('listing_visibility')
    
    if module.params.get('passthrough_request_headers') is not None:
        desired_mount_config['passthrough_request_headers'] = module.params.get('passthrough_request_headers')
    
    module.connection_options.process_connection_options()
    client_args = module.connection_options.get_hvac_connection_options()
    client = module.helper.get_vault_client(**client_args)

    try:
        module.authenticator.validate()
        module.authenticator.authenticate(client)
    except (NotImplementedError, HashiVaultValueError) as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())
        return
    
    previous_mount_config = get_formatted_mount_config(
        module,
        client,
        engine_mount_point
    )

    if previous_mount_config is Exception:
        return
    
    previous_backend_type = get_mount_backend_type(
        module,
        client,
        engine_mount_point
    )

    if previous_backend_type is Exception:
        return

    if state == 'absent':
        result = ensure_engine_absent(
            module,
            client,
            engine_mount_point,
            previous_mount_config,
            previous_backend_type
        )

        if result is Exception:
            return
    
    if state == 'present':
        result = ensure_engine_present(
            module,
            client,
            engine_mount_point,
            previous_mount_config,
            previous_backend_type,
            desired_mount_config,
            replace_non_pki_secret_engine
        )

        if result is Exception:
            return
        
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
