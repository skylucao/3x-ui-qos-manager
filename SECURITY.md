# Security

Do not publish a deployment directory or runtime backup with this source tree.

The following target-machine files contain secrets or private state and must never be committed:

- `/etc/xray-qos-web/web.env`
- `/etc/xray-qos-web/install-result.env`
- `/etc/xray-qos/nodes.json`
- `/etc/x-ui/x-ui.db`
- TLS certificates and private keys
- generated Nginx configuration (it contains internal proxy tokens)

Before reporting a vulnerability, remove server addresses, credentials, node UUIDs, public keys, short IDs, subscription URLs, and log IP addresses from reproductions.
