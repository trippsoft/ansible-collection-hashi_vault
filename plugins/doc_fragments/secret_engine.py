#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
options:
  state:
    description: Whether the secret engine should be present or absent.
    type: str
    required: false
    default: present
    choices:
      - present
      - absent
  replace_different_backend_type:
    description: Whether to replace the secret engine if it has a different backend type.
    type: bool
    required: false
    default: false
  description:
    description: The description of the secret engine.
    type: str
    required: false
  default_lease_ttl:
    description: The default lease TTL of the secret engine.
    type: str
    required: false
  max_lease_ttl:
    description: The maximum lease TTL of the secret engine.
    type: str
    required: false
  audit_non_hmac_request_keys:
    description: The list of non-HMAC request keys to audit.
    type: list
    required: false
  audit_non_hmac_response_keys:
    description: The list of non-HMAC response keys to audit.
    type: list
    required: false
  listing_visibility:
    description: The listing visibility of the secret engine.
    type: str
    required: false
    choices:
      - normal
      - unauth
      - hidden
  passthrough_request_headers:
    description: The list of request headers to pass through.
    type: list
    required: false
'''
