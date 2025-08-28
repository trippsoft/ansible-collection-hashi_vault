<!-- BEGIN_ANSIBLE_DOCS -->

# Ansible Role: trippsc2.hashi_vault.install
Version: 1.10.4

This role installs and configures HashiCorp Vault.

## Requirements

| Platform | Versions |
| -------- | -------- |
| Debian | <ul><li>bookworm</li></ul> |
| EL | <ul><li>9</li><li>8</li></ul> |
| Fedora | <ul><li>all</li></ul> |
| Ubuntu | <ul><li>noble</li><li>jammy</li></ul> |

## Dependencies
| Role |
| ---- |
| trippsc2.hashicorp.repo |

| Collection |
| ---------- |
| ansible.posix |
| ansible.utils |
| community.general |
| trippsc2.hashicorp |

## Role Arguments
|Option|Description|Type|Required|Choices|Default|
|---|---|---|---|---|---|
| vault_configure_firewall | <p>Whether to configure the firewall.</p> | bool | no |  | True |
| vault_configure_logrotate | <p>Whether to configure log rotation.</p> | bool | no |  | True |
| vault_configure_selinux | <p>Whether to configure SELinux.</p> | bool | no |  | True |
| vault_firewall_type | <p>The type of firewall to configure.</p><p>On Ubuntu, this defaults to `ufw`.</p><p>On other systems, this defaults to `firewalld`.</p> | str | no | <ul><li>firewalld</li><li>ufw</li></ul> |  |
| vault_user | <p>The user account under which the HashiCorp Vault service will run.</p> | str | no |  | vault |
| vault_group | <p>The primary group of the user under which the HashiCorp Vault service will run.</p> | str | no |  | vault |
| vault_home_directory | <p>The home directory of the HashiCorp Vault service.</p> | path | no |  | /opt/vault |
| vault_config_directory | <p>The configuration directory of the HashiCorp Vault service.</p> | path | no |  | /etc/vault.d |
| vault_log_directory | <p>The log directory of the HashiCorp Vault service.</p> | path | no |  | /var/log/vault |
| vault_plugin_directory | <p>The directory where HashiCorp Vault plugins are stored.</p> | path | no |  | /usr/local/lib/vault/plugins |
| vault_http_proxy | <p>The HTTP proxy for the HashiCorp Vault service.</p> | str | no |  |  |
| vault_https_proxy | <p>The HTTPS proxy for the HashiCorp Vault service.</p> | str | no |  |  |
| vault_no_proxy | <p>The no proxy for the HashiCorp Vault service.</p> | str | no |  |  |
| vault_config_filename | <p>The configuration filename of the HashiCorp Vault service.</p> | path | no |  | vault.hcl |
| vault_logrotate_period | <p>The period for log rotation.</p> | str | no | <ul><li>daily</li><li>weekly</li><li>monthly</li></ul> | daily |
| vault_logrotate_retention | <p>The number of log files to retain.</p> | int | no |  | 14 |
| vault_selinux_outbound_udp_dns | <p>Whether to enable HashiCorp Vault to make outbound DNS UDP requests.</p> | bool | no |  | True |
| vault_selinux_outbound_http | <p>Whether to enable HashiCorp Vault to make outbound HTTP requests.</p> | bool | no |  | True |
| vault_default_lease_ttl | <p>The default lease time-to-live (TTL) for secrets.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#default_lease_ttl</p> | str | no |  | 768h |
| vault_max_lease_ttl | <p>The maximum lease time-to-live (TTL) for secrets.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#max_lease_ttl</p> | str | no |  | 768h |
| vault_default_max_request_duration | <p>The default maximum request duration.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#default_max_request_duration</p> | str | no |  | 90s |
| vault_raw_storage_endpoint_enabled | <p>Whether to enable the raw storage endpoint.</p><p>This is a sensitive operation and should only be enabled when necessary.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#raw_storage_endpoint</p> | bool | no |  | False |
| vault_introspection_endpoint_enabled | <p>Whether to enable the introspection endpoint.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#introspection_endpoint</p> | bool | no |  | False |
| vault_mlock_enabled | <p>Whether to enable memory locking.</p><p>If *vault_backend* is set to `raft`, this will be ignored and set to `false`.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#disable_mlock</p> | bool | no |  | True |
| vault_ui_enabled | <p>Whether to enable the Vault UI.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#ui</p> | bool | no |  | True |
| vault_response_header_hostname_enabled | <p>Whether to enable the response header hostname.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#response_header_hostname</p> | bool | no |  | False |
| vault_response_header_raft_node_id_enabled | <p>Whether to enable the response header Raft node ID.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#response_header_raft_node_id</p> | bool | no |  | False |
| vault_detect_deadlocks | <p>The type of deadlock detection to use for logging potential deadlocks.</p><p>This has a negative affect on performance.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#detect_deadlocks</p> | str | no |  |  |
| vault_post_unseal_trace_enabled | <p>Whether to enable tracing after unsealing.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#enable_post_unseal_trace</p> | bool | no |  | False |
| vault_post_unseal_trace_directory | <p>The directory where the trace files will be written.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#post_unseal_trace_directory</p> | path | no |  |  |
| vault_log_level | <p>The log level for the Vault service.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#log_level</p> | str | no | <ul><li>trace</li><li>debug</li><li>info</li><li>warn</li><li>error</li></ul> | info |
| vault_log_file | <p>The file where the Vault service will write logs.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#log_file</p> | path | no |  | /var/log/vault/vault.log |
| vault_log_format | <p>The log format for the Vault service.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#log_format</p> | str | no |  |  |
| vault_log_rotate_duration | <p>The duration after which the Vault service will rotate logs.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#log_rotate_duration</p> | str | no |  |  |
| vault_log_rotate_bytes | <p>The size in bytes after which the Vault service will rotate logs.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#log_rotate_bytes</p> | str | no |  |  |
| vault_log_rotate_max_files | <p>The maximum number of log files to keep.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#log_rotate_max_files</p> | int | no |  |  |
| vault_clustering_enabled | <p>Whether to enable clustering.</p><p>If *vault_backend* is set to `raft`, this will be ignored and set to `true`.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#disable_clustering</p> | bool | no |  | False |
| vault_cluster_name | <p>The name of the Vault cluster.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#cluster_name</p> | str | no |  |  |
| vault_api_protocol | <p>The protocol the Vault API will advertise to the cluster.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#api_addr</p> | str | no | <ul><li>http</li><li>https</li></ul> | https |
| vault_api_host | <p>The IP address or FQDN the Vault API will advertise to the cluster.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#api_addr</p> | str | no |  | {{ ansible_default_ipv4.address }} |
| vault_api_port | <p>The port on which the Vault API will listen.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#api_addr</p> | int | no |  | 8200 |
| vault_cluster_protocol | <p>The protocol over which the Vault cluster will communicate.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#cluster_addr</p> | str | no | <ul><li>http</li><li>https</li></ul> | https |
| vault_cluster_host | <p>The IP address or FQDN over which the Vault cluster will communicate.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#cluster_addr</p> | str | no |  | {{ ansible_default_ipv4.address }} |
| vault_cluster_port | <p>The port on which the Vault cluster will communicate.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#cluster_addr</p> | int | no |  | 8201 |
| vault_cache_enabled | <p>Whether to enable caching.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#disable_cache</p> | bool | no |  | True |
| vault_cache_size | <p>The size of the cache in bytes.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration#cache_size</p> | str | no |  | 131072 |
| vault_prometheus_retention_time | <p>The retention time for Prometheus metrics.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/telemetry#prometheus_retention_time</p> | str | no |  | 24h |
| vault_prometheus_disable_hostname | <p>Whether to disable the hostname in Prometheus metrics.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/telemetry#disable_hostname</p> | bool | no |  | True |
| vault_tcp_listeners | <p>The TCP listeners for the Vault service.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp</p> | list of dicts of 'vault_tcp_listeners' options | yes |  |  |
| vault_raft_node_id | <p>The node ID for the Vault service.</p><p>If *vault_backend* is set to `raft`, this is required.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#node_id</p> | str | no |  |  |
| vault_raft_performance_multiplier | <p>The performance multiplier for the Vault service.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#performance_multiplier</p> | int | no |  |  |
| vault_raft_trailing_logs | <p>The number of trailing logs to retain.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#trailing_logs</p> | int | no |  | 10000 |
| vault_raft_snapshot_threshold | <p>The number of log entries to trigger a snapshot.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#snapshot_threshold</p> | int | no |  | 8192 |
| vault_raft_snapshot_interval | <p>The interval at which to take snapshots in seconds.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#snapshot_interval</p> | int | no |  | 120 |
| vault_raft_max_entry_size | <p>The maximum entry size in bytes.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#max_entry_size</p> | int | no |  | 1048576 |
| vault_raft_autopilot_reconcile_interval | <p>The interval at which to reconcile the raft configuration.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#autopilot_reconcile_interval</p> | str | no |  | 10s |
| vault_raft_autopilot_update_interval | <p>The interval at which to update the raft configuration.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#autopilot_update_interval</p> | str | no |  | 2s |
| vault_raft_retry_auto_join | <p>The list of retry join commands with auto-join configuration for the raft cluster.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#retry_join-stanza</p> | list of dicts of 'vault_raft_retry_auto_join' options | no |  | [] |
| vault_raft_retry_join | <p>The list of retry joining commands for the raft cluster.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#retry_join-stanza</p> | list of dicts of 'vault_raft_retry_join' options | no |  | [] |

### Options for vault_tcp_listeners
|Option|Description|Type|Required|Choices|Default|
|---|---|---|---|---|---|
| address | <p>The IP address on which the Vault service will listen.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#address</p> | str | yes |  |  |
| port | <p>The port on which the Vault service will listen.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#address</p> | int | no |  | 8200 |
| cluster_address | <p>The IP address over which the Vault cluster will communicate.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#cluster_address</p> | str | no |  |  |
| cluster_port | <p>The port over which the Vault cluster will communicate.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#cluster_address</p> | int | no |  | 8201 |
| http_idle_timeout | <p>The idle timeout for HTTP connections.</p><p>If set to `0`, the timeout is disabled.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#http_idle_timeout</p> | str | no |  | 5m |
| http_read_header_timeout | <p>The timeout for reading the request header.</p><p>If set to `0`, the timeout is disabled.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#http_read_header_timeout</p> | str | no |  | 10s |
| http_read_timeout | <p>The timeout for reading the request body.</p><p>If set to `0`, the timeout is disabled.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#http_read_timeout</p> | str | no |  | 30s |
| http_write_timeout | <p>The timeout for writing the response.</p><p>If set to `0`, the timeout is disabled.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#http_write_timeout</p> | str | no |  | 0 |
| max_request_size | <p>The maximum request size in bytes.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#max_request_size</p> | str | no |  | 33554432 |
| max_request_duration | <p>The maximum request duration.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#max_request_duration</p> | str | no |  | 90s |
| redact_addresses | <p>Whether to react to the client address.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#react_addresses</p> | bool | no |  | False |
| redact_cluster_name | <p>Whether to redact the cluster name.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#redact_cluster_name</p> | bool | no |  | False |
| redact_version | <p>Whether to redact the version.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#redact_version</p> | bool | no |  | False |
| proxy_protocol_behavior | <p>The behavior for handling the PROXY protocol.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#proxy_protocol_behavior</p> | str | no | <ul><li>use_always</li><li>allow_authorized</li><li>deny_unauthorized</li></ul> |  |
| proxy_protocol_authorized_addrs | <p>The list of authorized addresses for the PROXY protocol.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#proxy_protocol_authorized_addrs</p> | list of 'str' | no |  |  |
| tls_enabled | <p>Whether to enable TLS.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#tls_disable</p> | bool | no |  | False |
| tls_cert_file | <p>The path to the certificate file.</p><p>If *tls_enabled* is set to `true`, this is required.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#tls_cert_file</p> | path | no |  |  |
| tls_key_file | <p>The path to the key file.</p><p>If *tls_enabled* is set to `true`, this is required.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#tls_key_file</p> | path | no |  |  |
| tls_min_version | <p>The minimum TLS version.</p><p>If *tls_enabled* is set to `false`, this is ignored.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#tls_min_version</p> | str | no | <ul><li>tls10</li><li>tls11</li><li>tls12</li><li>tls13</li></ul> | tls12 |
| tls_max_version | <p>The maximum TLS version.</p><p>If *tls_enabled* is set to `false`, this is ignored.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#tls_max_version</p> | str | no | <ul><li>tls10</li><li>tls11</li><li>tls12</li><li>tls13</li></ul> | tls13 |
| tls_cipher_suites | <p>The comma-delimited list of supported cipher suites.</p><p>If *tls_enabled* is set to `false`, this is ignored.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#tls_cipher_suites</p> | str | no |  |  |
| tls_client_certificate_mode | <p>The client certificate mode.</p><p>If *tls_enabled* is set to `false`, this is ignored.</p><p>If set to `required`, the client must present a certificate.</p><p>If set to `optional`, the client may present a certificate.</p><p>If set to `disabled`, the client must not present a certificate.</p> | str | no | <ul><li>disabled</li><li>optional</li><li>required</li></ul> | optional |
| tls_client_ca_file | <p>The path to the client CA file.</p><p>If *tls_enabled* is set to `false`, this is ignored.</p><p>If *tls_client_certificate_mode* is set to `required` or `optional`, this is required.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#tls_client_ca_file</p> | path | no |  |  |
| x_forwarded_for_authorized_addrs | <p>The list of authorized addresses for the X-Forwarded-For header.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#x_forwarded_for_authorized_addrs</p> | list of 'str' | no |  |  |
| x_forwarded_for_client_cert_header | <p>The header to use for the client certificate.</p><p>If *x_forwarded_for_authorized_addrs* is not provided, this is ignored.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#x_forwarded_for_client_cert_header</p> | str | no |  |  |
| x_forwarded_for_client_cert_header_decoders | <p>The list of decoders for the client certificate header.</p><p>If *x_forwarded_for_authorized_addrs* is not provided, this is ignored.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#x_forwarded_for_client_cert_header_decoders</p> | list of 'str' | no |  |  |
| x_forwarded_for_hop_skips | <p>The number of hops to skip in the X-Forwarded-For header.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#x_forwarded_for_hop_skips</p> | int | no |  | 0 |
| x_forwarded_for_reject_not_authorized | <p>Whether to reject requests that do not have an authorized address in the X-Forwarded-For header.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#x_forwarded_for_reject_not_authorized</p> | bool | no |  | False |
| x_forwarded_for_reject_not_present | <p>Whether to reject requests that do not have an X-Forwarded-For header.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#x_forwarded_for_reject_not_present</p> | bool | no |  | False |
| replication_status_endpoints_enabled | <p>Whether to enable replication status endpoints.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#disable_replication_status_endpoints</p> | bool | no |  | True |
| unauthenticated_metrics_access | <p>Whether to allow unauthenticated access to metrics.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#unauthenticated_metrics_access</p> | bool | no |  | False |
| unauthenticated_pprof_access | <p>Whether to allow unauthenticated access to pprof.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#unauthenticated_pprof_access</p> | bool | no |  | False |
| unauthenticated_in_flight_requests_access | <p>Whether to allow unauthenticated access to in-flight requests.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#unauthenticated_in_flight_requests_access</p> | bool | no |  | False |
| vault_backend | <p>The backend storage type for Vault.</p><p>Only `raft` is supported currently.</p> | str | no | <ul><li>raft</li></ul> | raft |

### Options for vault_raft_retry_auto_join
|Option|Description|Type|Required|Choices|Default|
|---|---|---|---|---|---|
| auto_join | <p>The auto-join configuration in go-discover syntax.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#auto_join</p> | str | yes |  |  |
| auto_join_scheme | <p>The protocol scheme for auto-join.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#auto_join_scheme</p> | str | no | <ul><li>http</li><li>https</li></ul> |  |
| auto_join_port | <p>The port for auto-join.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#auto_join_port</p> | int | no |  |  |

### Options for vault_raft_retry_join
|Option|Description|Type|Required|Choices|Default|
|---|---|---|---|---|---|
| leader_api_addr | <p>The leader API address for retry-join.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#leader_api_addr</p> | str | yes |  |  |
| leader_tls_server_name | <p>The leader TLS server name for retry-join.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#leader_tls_servername</p> | str | no |  |  |
| leader_ca_cert_file | <p>The leader CA certificate file for retry-join.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#leader_ca_cert_file</p> | str | yes |  |  |
| leader_client_cert_file | <p>The leader client certificate file for retry-join.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#leader_client_cert_file</p> | str | yes |  |  |
| leader_client_key_file | <p>The leader client key file for retry-join.</p><p>Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/raft#leader_client_key_file</p> | str | yes |  |  |


## License
MIT

## Author and Project Information
Jim Tarpley (@trippsc2)
<!-- END_ANSIBLE_DOCS -->
