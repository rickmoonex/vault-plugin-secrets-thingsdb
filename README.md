# ThingsDB secrets engine for HashiCorp Vault

![GitHub Release](https://img.shields.io/github/v/release/rickmoonex/vault-plugin-secrets-thingsdb)

The ThingsDB secrets engine gives you the ability to dynamically create and revoke credentials for accessing ThingsDB.

## Installation

The setup guide assumes that you're familiar with operating a HashiCorp Vault cluster and how to enable plugins.

1. Clone this repo and build the plugin using `make build`. The binary will then be placed in `./vault/plugins`.
2. Move the binary into your Vault cluster's configured `plugin_directory`, specified in the server config:

    ```bash
    mv ./vault/plugins/vault-plugin-secrets-thingsdb <vault_plugin_dir>/vault-plugin-secrets-thingsdb
    ```

3. Enable mlock so the plugin can be safely enabled and disabled:

    ```bash
    setcap cap_ipc_lock=+ep <vault_plugin_dir>/vault-plugin-secrets-thingsdb
    ```

4. Calculate the SHA256 sum of the plugin and register it in Vault's plugin catalog.

    ```bash
    export SHA256=$(shasum -a 256 "<vault_plugin_dir>/vault-plugin-secrets-thingsdb" | cut -d' ' -f1)
    ```
    ```bash
    vault plugin register \
        -sha256="${SHA256}" \
        secret vault-plugin-secrets-thingsdb
    ```

5. Mount the secrets engine:

    ```
    vault secrets enable \
    -path=thingsdb \
    vault-plugin-secrets-thingsdb
    ```

## Usage

In order to use this secret engine we need to setup up some config so it can communicate with ThingDB. Make sure you use a token that has the permissions to create user/tokens, grant permissions, and delete users:

```bash
vault write hashicups/config \
hostname="localhost" \
port="9200" \
insecure=false \
token="<thingsdb_admin_token>"
```

After that you create a role within Vault that defines a specific ThingsDB target and grant mask as integer.
>For available targets and masks check the [ThingsDB Docs](https://docs.thingsdb.io/v1/thingsdb-api/grant/)

```bash
vault write thingsdb/role/<role_name> target="//stuff" mask="31"
```

You can now retrieve a ThingsDB token using this role. This will return you the access token and the username of the newly created user:

```bash
$ vault read thingsdb/creds/<role_name>

Key                Value
---                -----
lease_id           thingsdb/creds/<role_name>/<LEASE_ID>
lease_duration     768h
lease_renewable    true
token              <TOKEN>
token_id           f277c246-0c01-444c-8eb7-9ac5e2475cb7
user               <USERNAME>
```

The token is automatically revoked after the TTL has passed. If you want to manually revoke the token you can do so:

```bash
vault lease revoke thingsdb/creds/<role_name>/<LEASE_ID>
```