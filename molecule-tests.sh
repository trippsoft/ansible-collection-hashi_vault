#! /bin/bash

set -e

molecule test -s vault_database_secret_engine
molecule test -s vault_database_static_role
molecule test -s vault_kv1_secret_engine
molecule test -s vault_kv2_secret_engine
molecule test -s vault_pki_role
molecule test -s vault_pki_root_ca_certificate
molecule test -s vault_pki_secret_engine
molecule test -s vault_pki_sign_verbatim
