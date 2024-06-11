#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_kv1_secret_engine
version_added: 1.0.0
author:
  - Jim Tarpley
short_description: Configures a KV version 1 secret engine in HashiCorp Vault.
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - Creates a L(new KV version 1 secret engine,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/kv_v1.html),
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
options:
  max_versions:
    description: The maximum number of versions to keep for each secret.
    type: int
    required: false
  cas_required:
    description: Whether to require the use of a CAS (Check-And-Set) parameter for write operations.
    type: bool
    required: false
  delete_version_after:
    description: The duration after which a version is deleted.
    type: str
    required: false
"""

EXAMPLES = r"""
- name: Create a new KV version 2 secret engine
  trippsc2.hashi_vault.vault_kv2_secret_engine:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: secret
    state: present


- name: Remove a KV version 2 secret engine
  trippsc2.hashi_vault.vault_kv2_secret_engine:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: secret
    state: absent
"""

RETURN = r"""
"""


import traceback

import hvac
from hvac.exceptions import InvalidPath, Forbidden, UnexpectedError

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_module import HashiVaultModule
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultValueError

from ..module_utils._timeparse import duration_str_to_seconds
from ..module_utils._vault_secret_engine import (
    get_secret_engine_argspec,
    get_formatted_mount_config,
    compare_mount_config,
    disable_mount,
    enable_mount,
    configure_mount
)


def format_kv2_config_data(config_data: dict) -> dict:
    """
    Format the configuration data of a KV version 2 secret engine.

    Args:
        config_data (dict): The configuration data to format.
    
    Returns:
        dict: The formatted configuration data.
    """

    formatted_config_data: dict = {}

    for k, v in config_data.items():
        match k:
            case 'delete_version_after':
                formatted_config_data[k] = duration_str_to_seconds(v, 0)
            case _:
                formatted_config_data[k] = v
    
    return formatted_config_data


def get_formatted_kv2_config(module: HashiVaultModule, client: hvac.Client, mount_point: str) -> dict | Exception | None:
    """
    Read the configuration of a KV version 2 secret engine at a given path.

    Args:
        module (HashiVaultModule): The module using this function.
        client (Client): The Vault client to use.
        mount_point (str): The path of the secret engine to read.
    
    Returns:
        dict: The configuration of the KV version 2 secret engine at the given path.
    """

    try:
        config: dict = client.secrets.kv.v2.read_configuration(mount_point=mount_point)
    except InvalidPath:
        return None
    except UnexpectedError:
        return None
    except Forbidden as e:
        module.fail_json(msg=f"Forbidden: Permission Denied to path '{mount_point}'", exception=traceback.format_exc())
        return e
    except Exception as e:
        module.fail_json(msg=f"Error reading KV2 secret configuration '{mount_point}'", exception=traceback.format_exc())
        return e

    formatted_config: dict = format_kv2_config_data(config.get('data', dict()))
    
    return formatted_config


def compare_kv2_config(previous_config: dict, desired_config: dict) -> dict:
    """
    Compare the configuration of a KV version 2 secret engine.

    Args:
        previous_config (dict): The previous configuration of the KV version 2 secret engine.
        desired_config (dict): The desired configuration of the KV version 2 secret engine.
    
    Returns:
        dict: The differences between the previous and desired configurations.
    """

    config_diff: dict = {}

    for k, v in desired_config.items():
        if k not in previous_config:
            match k:
                case 'delete_version_after':
                    if v != 0:
                        config_diff[k] = v
                case 'cas_required':
                    if v:
                        config_diff[k] = v
                case 'max_versions':
                    if v != 0:
                        config_diff[k] = v
                case _:
                    config_diff[k] = v
        else:
            if v != previous_config[k]:
                config_diff[k] = v

    return config_diff


def configure_kv2_secret_engine(
        module: HashiVaultModule,
        client: hvac.Client,
        mount_point: str,
        config: dict) -> None | Exception:
    """
    Configure a KV version 2 secret engine.

    Args:
        module (HashiVaultModule): The module using this function.
        client (Client): The Vault client to use.
        mount_point (str): The path of the secret engine to configure.
        config (dict): The configuration to apply to the secret engine.
    """

    if module.check_mode:
        return None

    try:
        client.secrets.kv.v2.configure(
            mount_point=mount_point,
            **config
        )
    except Forbidden as e:
        module.fail_json(msg=f"Forbidden: Permission Denied to path '{mount_point}'", exception=traceback.format_exc())
        return e
    except Exception as e:
        module.fail_json(msg=f"Error configuring KV version 2 secret engine '{mount_point}'", exception=traceback.format_exc())
        return e


def ensure_engine_absent(
        module: HashiVaultModule,
        client: hvac.Client,
        engine_mount_point: str,
        previous_mount_config: dict | None,
        previous_kv2_config: dict | None) -> dict | Exception:
    """
    Ensure that the secret engine is absent.

    Args:
        module (HashiVaultModule): The module using this function.
        client (Client): The Vault client to use.
        engine_mount_point (str): The path of the secret engine to manage.
        previous_mount_config (dict): The previous configuration of the secret engine.
        previous_kv2_config (dict): The previous configuration of the KV version 2 secret engine.
    
    Returns:
        dict: The result of the operation to be sent to Ansible.
    """

    if previous_mount_config is None:
        return dict(changed=False)
    
    if previous_kv2_config is None:
        try:
            raise Exception(f"The secret engine at '{engine_mount_point}' is not a KV version 2 secret engine")
        except Exception as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())
            return e
    
    result = disable_mount(module, client, engine_mount_point)

    if result is Exception:
        return result
    
    return dict(changed=True, prev_config=dict(**previous_mount_config, **previous_kv2_config))


def ensure_engine_present(
        module: HashiVaultModule,
        client: hvac.Client,
        engine_mount_point: str,
        previous_mount_config: dict | None,
        previous_kv2_config: dict | None,
        desired_mount_config: dict,
        desired_kv2_config: dict,
        replace_non_kv2_secret_engine: bool) -> dict | Exception:
    """
    Ensure that the secret engine is present.

    Args:
        module (HashiVaultModule): The module using this function.
        client (Client): The Vault client to use.
        engine_mount_point (str): The path of the secret engine to manage.
        previous_mount_config (dict): The previous configuration of the secret engine.
        previous_kv2_config (dict): The previous configuration of the KV version 2 secret engine.
        desired_mount_config (dict): The desired configuration of the secret engine.
        desired_kv2_config (dict): The desired configuration of the KV version 2 secret engine.
        replace_non_kv2_secret_engine (bool): Whether to replace a non-KV version 2 secret engine.
    
    Returns:
        dict: The result of the operation to be sent to Ansible.
    """

    if previous_mount_config is None:
        description = desired_mount_config.pop('description', None)
        
        result = enable_mount(
            module,
            client,
            'kv-v2',
            engine_mount_point,
            description,
            desired_mount_config
        )

        if result is Exception:
            return result
        
        result = configure_kv2_secret_engine(
            module,
            client,
            engine_mount_point,
            desired_kv2_config
        )

        if result is Exception:
            return result
        
        return dict(changed=True, config=dict(description=description, **desired_mount_config, **desired_kv2_config))
    
    if previous_kv2_config is None:
        if not replace_non_kv2_secret_engine:
            try:
                raise Exception(f"The secret engine at '{engine_mount_point}' is not a KV version 2 secret engine")
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
            'kv-v2',
            engine_mount_point,
            description,
            desired_mount_config
        )

        if result is Exception:
            return result
        
        result = configure_kv2_secret_engine(
            module,
            client,
            engine_mount_point,
            desired_kv2_config
        )

        if result is Exception:
            return result
        
        return dict(changed=True, config=dict(description=description, **desired_mount_config, **desired_kv2_config))
    
    changed = False
    mount_config_diff = compare_mount_config(previous_mount_config, desired_mount_config)

    if mount_config_diff:
        changed = True
        result = configure_mount(module, client, engine_mount_point, mount_config_diff)

        if result is Exception:
            return result
    
    kv2_config_diff = compare_kv2_config(previous_kv2_config, desired_kv2_config)

    if kv2_config_diff:
        changed = True
        result = configure_kv2_secret_engine(module, client, engine_mount_point, kv2_config_diff)

        if result is Exception:
            return result
    
    if changed:
        return dict(
            changed=changed,
            prev_config=dict(**previous_mount_config, **previous_kv2_config),
            config=dict(**desired_mount_config, **desired_kv2_config)
        )
    
    return dict(changed=False, config=dict(**previous_mount_config, **previous_kv2_config))


def run_module():
    argspec = HashiVaultModule.generate_argspec(
        **get_secret_engine_argspec(),
        max_versions=dict(type='int', required=False, default=None),
        cas_required=dict(type='bool', required=False, default=None),
        delete_version_after=dict(type='str', required=False, default=None)
    )

    module = HashiVaultModule(argument_spec=argspec, supports_check_mode=True)

    engine_mount_point: str = module.params.get('engine_mount_point')
    state: str = module.params.get('state')
    replace_non_kv2_secret_engine: bool = module.params.get('replace_different_backend_type')

    desired_mount_config = dict()
    desired_kv2_config = dict()

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
    
    if module.params.get('max_versions') is not None:
        desired_kv2_config['max_versions'] = module.params.get('max_versions')
    
    if module.params.get('cas_required') is not None:
        desired_kv2_config['cas_required'] = module.params.get('cas_required')
    
    if module.params.get('delete_version_after') is not None:
        desired_kv2_config['delete_version_after'] = duration_str_to_seconds(module.params.get('delete_version_after'))
    
    module.connection_options.process_connection_options()
    client_args = module.connection_options.get_hvac_connection_options()
    client = module.helper.get_vault_client(**client_args)

    try:
        module.authenticator.validate()
        module.authenticator.authenticate(client)
    except (NotImplementedError, HashiVaultValueError) as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())
        return
    
    previous_mount_config = get_formatted_mount_config(module, client, engine_mount_point)

    if previous_mount_config is Exception:
        return
    
    previous_kv2_config = get_formatted_kv2_config(module, client, engine_mount_point)

    if previous_kv2_config is Exception:
        return
    
    if state == 'absent':
        result = ensure_engine_absent(
            module,
            client,
            engine_mount_point,
            previous_mount_config,
            previous_kv2_config
        )

        if result is Exception:
            return
    
    if state == 'present':
        result = ensure_engine_present(
            module,
            client,
            engine_mount_point,
            previous_mount_config,
            previous_kv2_config,
            desired_mount_config,
            desired_kv2_config,
            replace_non_kv2_secret_engine
        )
        
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
