# Security

Do not publish a deployment directory or runtime backup with this source tree.

The following target-machine files contain secrets or private state and must never be committed:

- `/etc/xray-qos-web/web.env`
- `/etc/xray-qos-web/install-result.env`
- `/etc/xray-qos/nodes.json`
- `/etc/x-ui/x-ui.db`
- TLS certificates and private keys
- generated Nginx configuration (it contains internal proxy tokens)
- `/etc/xray-audit/config.json` (real recipient and local settings)
- `/var/log/x-ui/access.log` and its rotated copies
- `/var/lib/xray-audit/` and `/var/lib/xray-audit-web/` (audit records, reports and receipts)
- `/var/lib/xray-qos-web/node-notes.sqlite3` (node annotations)
- staged deployment archives and application/runtime backups

Before reporting a vulnerability, remove server addresses, credentials, node UUIDs, public keys, short IDs, subscription URLs, and log IP addresses from reproductions.
