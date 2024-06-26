#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_pki_root_ca_certificate
version_added: 1.2.0
author:
  - Jim Tarpley
short_description: Configures a PKI secret engine root CA certificate in HashiCorp Vault.
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - Ensures that a PKI secret engine root CA certificate is configured in HashiCorp Vault.
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
options:
  state:
    type: str
    required: false
    default: present
    choices:
      - present
      - absent
    description:
      - Whether the root CA certificate should exist or not.
  common_name:
    type: str
    required: false
    description:
      - The common name for the root CA certificate.
      - Required if `state` is `present`.
  export_private_key:
    type: bool
    required: false
    default: false
    description:
      - Whether to export the private key when creating the root certificate.
      - If set to `true`, the private key will be returned in the response without no_log masking.
  alt_names:
    type: list
    required: false
    elements: str
    description:
      - A list of Subject Alternative Names (SANs) to include in the certificate.
      - These can be host names or email addresses; they will be parsed into their respective fields.
  ip_sans:
    type: list
    required: false
    elements: str
    description:
      - A list of IP Address Subject Alternative Names.
  uri_sans:
    type: list
    required: false
    elements: str
    description:
      - A list of URI Subject Alternative Names.
  other_sans:
    type: list
    required: false
    elements: dict
    description:
      - A list of custom OID/UTF8-string SANs.
    suboptions:
      oid:
        type: str
        required: true
        description:
          - The OID for the custom SAN.
      type:
        type: str
        required: false
        default: utf8
        choices:
          - utf8
        description:
          - The type of the custom SAN.
      value:
        type: str
        required: true
        description:
          - The value of the custom SAN.
  ttl:
    type: str
    required: false
    description:
      - The requested Time-To-Live if the certificate must be generated.
      - This can be specified as a string duration with time suffix or as an integer number of seconds.
      - This cannot be larger than the engine's max (or, if not set, the system max).
  format:
    type: str
    required: false
    choices: 
      - pem
      - der
      - pem_bundle
    description:
      - Specifies the format for returned data.
      - If `pem_bundle`, the `certificate` field will contain the private key (if exported) and
        certificate, concatenated;
      - if the issuing CA is not a Vault-derived self-signed root, this will be included as well.
      - If not set, the default is `pem`.
  private_key_format:
    type: str
    choice:
      - der
      - pkcs8
    description:
      - Specifies the format for marshaling the private key.
      - Defaults to `der` which will return either base64-encoded DER or PEM-encoded DER, depending on
        the value of `format`.
      - The other option is `pkcs8` which will return the key marshalled as PEM-encoded PKCS8
  key_type:
    type: str
    required: false
    choices: 
      - rsa
      - ec
    description:
      - Specifies the desired key type.
  key_bits:
    type: int
    required: false
    description:
      - Specifies the number of bits to use
  max_path_length:
    type: int
    required: false
    description:
      - Specifies the maximum path length to encode in the generated certificate.
      - A limit of `-1` means no limit.
      - Unless the signing certificate has a maximum path length set, in which case the path length is set
        to one less than that of the signing certificate.
      - A limit of `0` means a literal path length of zero.
  exclude_cn_from_sans:
    type: bool
    required: false
    description:
      - If set, the given `common_name` will not be included in DNS or Email Subject Alternate Names (as
        appropriate).
      - Useful if the CN is not a hostname or email address, but is instead some human-readable
        identifier.
  permitted_dns_domains:
    type: list
    required: false
    elements: str
    description:
      - A list containing DNS domains for which certificates are allowed to be issued or signed by this CA
        certificate.
      - Note that subdomains are allowed, as per U(https://tools.ietf.org/html/rfc5280#section-4.2.1.10).
  ou:
    type: list
    required: false
    elements: str
    description:
      - Specifies the `OU` (OrganizationalUnit) values in the subject field of the resulting certificate.
  organization:
    type: list
    required: false
    elements: str
    description:
      - Specifies the `O` (Organization) values in the subject field of the resulting certificate.
  country:
    type: list
    required: false
    elements: str
    description:
      - Specifies the `C` (Country) values in the subject field of the resulting certificate.
  locality:
    type: list
    required: false
    elements: str
    description:
      - Specifies the `L` (Locality) values in the subject field of the resulting certificate.
  province:
    type: list
    required: false
    elements: str
    description:
      - Specifies the `ST` (Province) values in the subject field of the resulting certificate.
  street_address:
    type: list
    required: false
    elements: str
    description:
      - Specifies the Street Address values in the subject field of the resulting certificate.
  postal_code:
    type: list
    required: false
    elements: str
    description:
      - Specifies the Postal Code values in the subject field of the resulting certificate.
  serial_number:
    type: str
    required: false
    description:
      - Specifies the Serial Number, if any.
      - Otherwise Vault will generate a random serial for you.
      - If you want more than one, specify alternative names in the alt_names map using OID 2.5.4.5.
"""

EXAMPLES = r"""
- name: Ensure root CA certificate is configured
  trippsc2.hashi_vault.vault_pki_root_ca_certificate:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: pki
    common_name: my-root-ca
    state: present

- name: Ensure root CA certificate is not configured
  trippsc2.hashi_vault.vault_pki_root_ca_certificate:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: pki
    state: absent
"""

RETURN = r"""
certificate:
  description: The root CA certificate.
  type: str
  returned:
    - success
    - state is present
private_key:
  description: The private key for the root CA certificate.
  type: str
  returned:
    - changed
    - state is present
    - export_private_key is true
prev_certificate:
  description: The previous root CA certificate.
  type: str
  returned:
    - changed
    - state is absent
"""

import traceback

from ..module_utils._timeparse import duration_str_to_seconds
from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultPKIRootCACertificateModule(VaultModule):
    """
    Vault PKI Root CA Certificate Module
    """

    ARGSPEC = dict(
        engine_mount_point=dict(type='str', required=True),
        state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
        common_name=dict(type='str', required=False),
        export_private_key=dict(type='bool', required=False, default=False),
        alt_names=dict(type='list', required=False, elements='str'),
        ip_sans=dict(type='list', required=False, elements='str'),
        uri_sans=dict(type='list', required=False, elements='str'),
        other_sans=dict(
            type='list',
            required=False,
            elements='dict',
            options=dict(
                oid=dict(type='str', required=True),
                type=dict(type='str', required=False, default='utf8', choices=['utf8']),
                value=dict(type='str', required=True)
            )
        ),
        ttl=dict(type='str', required=False),
        format=dict(type='str', required=False, choices=['pem', 'der', 'pem_bundle']),
        private_key_format=dict(type='str', required=False, choices=['der', 'pkcs8']),
        key_type=dict(type='str', required=False, choices=['rsa', 'ec']),
        key_bits=dict(type='int', required=False),
        max_path_length=dict(type='int', required=False),
        exclude_cn_from_sans=dict(type='bool', required=False),
        permitted_dns_domains=dict(type='list', required=False, elements='str'),
        ou=dict(type='list', required=False, elements='str'),
        organization=dict(type='list', required=False, elements='str'),
        country=dict(type='list', required=False, elements='str'),
        locality=dict(type='list', required=False, elements='str'),
        province=dict(type='list', required=False, elements='str'),
        street_address=dict(type='list', required=False, elements='str'),
        postal_code=dict(type='list', required=False, elements='str'),
        serial_number=dict(type='str', required=False)        
    )

    DURATION_PARAMS = ['ttl']

    LIST_PARAMS_TO_JOIN = ['alt_names']


    def __init__(self, *args, **kwargs):
        
        argspec = self.ARGSPEC.copy()

        super(VaultPKIRootCACertificateModule, self).__init__(
            *args,
            argument_spec=argspec,
            supports_check_mode=True,
            required_if=[
                ('state', 'present', ['common_name'])
            ],
            **kwargs)


    def read_certificate_data(self) -> str | None:
        """
        Read the current root CA certificate data from the Vault server.

        Returns:
            str | None: The root CA certificate data, or None if no certificate exists.
        """

        engine_mount_point: str = self.params['engine_mount_point']

        try:
            response: str = self.client.secrets.pki.read_ca_certificate(mount_point=engine_mount_point)
        except Exception:
            self.handle_error(
                VaultModuleError(
                    message=f"Failed to read root CA certificate.",
                    exception=traceback.format_exc()
                )
            )
        
        if response == '':
            return None

        return response


    def other_sans_to_list_of_str(self, other_sans: list[dict]) -> list[str]:
        """
        Convert a list of other SANs in dictionary format to a list of strings.

        Args:
            other_sans (list[dict]): The list of other SANs in dictionary format.

        Returns:
            list[str]: The list of other SANs in string format.
        """

        converted = list()

        for san in other_sans:
            converted.append(f"{san['oid']};{san['type']}:{san['value']}")

        return converted


    def convert_list_to_comma_separated_string(self, data: list[str]) -> str:
        """
        Convert a list to a comma-separated string.

        Args:
            data (list[str]): The list of strings to convert.

        Returns:
            str: The comma-separated string.
        """

        return ','.join(data)


    def build_request_payload(self) -> dict:
        """
        Build the request payload for the module.

        Returns:
            dict: The request payload.
        """
        
        engine_mount_point: str = self.params['engine_mount_point']
        common_name: str = self.params['common_name']
        export_private_key: bool = self.params['export_private_key']

        type = 'exported' if export_private_key else 'internal'

        extra_params = dict()

        for key, value in self.params.items():
            if key not in self.ARGSPEC:
                continue
            
            if key in ['engine_mount_point', 'state', 'common_name', 'export_private_key']:
                continue

            if value is None:
                continue

            if key == 'other_sans':
                extra_params[key] = self.other_sans_to_list_of_str(value)

            if key in self.DURATION_PARAMS:
                extra_params[key] = duration_str_to_seconds(value)
            elif key in self.LIST_PARAMS_TO_JOIN:
                extra_params[key] = self.convert_list_to_comma_separated_string(value)

        payload = dict(
            type=type,
            mount_point=engine_mount_point,
            common_name=common_name,
            extra_params=extra_params
        )

        return payload


def ensure_certificate_absent(
        module: VaultPKIRootCACertificateModule,
        certificate_data: str | None) -> dict:
    """
    Ensure that the root CA certificate is absent.

    Args:
        module (VaultPKIRootCACertificateModule): The module object.
        certificate_data (str | None): The current root CA certificate data.

    Returns:
        dict: The result of the operation.
    """

    engine_mount_point: str = module.params['engine_mount_point']

    if certificate_data is None:
        return dict(changed=False)
    
    if not module.check_mode:
        try:
            response = module.client.secrets.pki.delete_root(mount_point=engine_mount_point)
        except Exception:
            module.handle_error(
                VaultModuleError(
                    message=f"Failed to delete root CA certificate.",
                    exception=traceback.format_exc()
                )
            )
        
        if response.get("warnings") is not None and len(response["warnings"]) > 0:
            warnings: list[str] = response["warnings"]

            for warning in warnings:
                # Skip the warning about deleting all keys and issuers
                if warning != "DELETE /root deletes all keys and issuers; prefer the new DELETE /key/:key_ref and DELETE /issuer/:issuer_ref for finer granularity, unless removal of all keys and issuers is desired.":
                    module.warn(warning)
    
    return dict(changed=True, prev_certificate=certificate_data)


def ensure_certificate_present(
        module: VaultPKIRootCACertificateModule,
        certificate_data: str | None) -> dict:
    """
    Ensure that the root CA certificate is present.

    Args:
        module (VaultPKIRootCACertificateModule): The module object.
        certificate_data (str | None): The current root CA certificate data.

    Returns:
        dict: The result of the operation.
    """
    if certificate_data is not None:
        return dict(changed=False)
    
    if module.check_mode:
        return dict(changed=True)

    payload = module.build_request_payload()

    try:
        response = module.client.secrets.pki.generate_root(**payload)
    except Exception:
        module.handle_error(
            VaultModuleError(
                message=f"Failed to generate root CA certificate.",
                exception=traceback.format_exc()
            )
        )
        
    if response.get("warnings") is not None and len(response["warnings"]) > 0:
        warnings: list[str] = response["warnings"]

        for warning in warnings:
            module.warn(warning)

    result = dict(
        changed=True,
        certificate=response["data"]["certificate"]
    )

    if "private_key" in response["data"]:
        result['private_key'] = response["data"]["private_key"]
    
    return result


def run_module():

    module = VaultPKIRootCACertificateModule()

    state: str = module.params['state']

    module.initialize_client()

    certificate_data = module.read_certificate_data()
    
    if state == 'present':
        result = ensure_certificate_present(module, certificate_data)
    else:
        result = ensure_certificate_absent(module, certificate_data)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
