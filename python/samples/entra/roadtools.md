# Entra passkey → ROADtools → ROADrecon

This is a bash/WSL workflow for:

1. registering a Key Vault-backed passkey with a Temporary Access Pass (TAP);
2. authenticating with that passkey;
3. passing the resulting ESTS session to `roadtx`; and
4. gathering Entra ID data with `roadrecon`.

The commands use absolute paths stored in exported variables, so the current
working directory does not matter and the virtual environment can live anywhere.

## 0. Configure paths and identity

Change only the values that are specific to your machine or tenant. Keep this
block together and run it in the shell where the remaining commands will run.

```bash
umask 077

export RESEARCH_PASSKEYS_ROOT="$HOME/src/research-passkeys"
export ROADTOOLS_ROOT="$HOME/src/ROADtools"
export VENV_PATH="$HOME/.venv"

export TENANT_ID="YOUR-TENANT-ID"
export KEYVAULT_NAME="YOUR-KEYVAULT-NAME"
export UPN="user@example.com"

export CREDENTIAL_PATH="$HOME/passkey-credential.json"
export ROADTOOLS_TOKEN_PATH="$HOME/.roadtools_auth"
export ROADRECON_TOKEN_PATH="$HOME/.roadrecon_auth"
export ROADRECON_DATABASE_PATH="$HOME/roadrecon.db"

export REGISTER_SCRIPT="$RESEARCH_PASSKEYS_ROOT/python/samples/entra/register_entra_keyvault_passkey.py"
export LOGIN_SCRIPT="$RESEARCH_PASSKEYS_ROOT/python/samples/entra/invoke_entra_passkey_login.py"
export ROADTX_ADAPTER="$RESEARCH_PASSKEYS_ROOT/python/samples/entra/invoke_entra_passkey_roadtx.py"
export ROADTX_COMMAND="$VENV_PATH/bin/roadtx"
export ROADRECON_COMMAND="$VENV_PATH/bin/roadrecon"
export PYTHON_COMMAND="$VENV_PATH/bin/python"
```

For another virtual-environment location, change only `VENV_PATH`, for example:

```bash
export VENV_PATH="$HOME/venvs/research-passkeys"
```

All later commands use `VENV_PATH`; none depend on `$PWD`.

## 1. Create the environment and install the local packages

This is safe to repeat when the environment already exists.

```bash
python3 -m venv "$VENV_PATH"

"$PYTHON_COMMAND" -m pip install --upgrade pip setuptools wheel
"$PYTHON_COMMAND" -m pip install \
  -e "$ROADTOOLS_ROOT/roadlib" \
  -e "$ROADTOOLS_ROOT/roadtx" \
  -e "$ROADTOOLS_ROOT/roadrecon" \
  -e "$RESEARCH_PASSKEYS_ROOT/python/libraries/passkey"

"$PYTHON_COMMAND" -m pip check
"$ROADTX_COMMAND" --help >/dev/null
"$ROADRECON_COMMAND" --help >/dev/null
```

Firefox and Selenium Manager must also be available. Recent Selenium versions
will download/manage geckodriver automatically. If that is unavailable, pass an
explicit `--roadtx-driver-path` to the adapter in step 4.

## 2. Authenticate to Azure for Key Vault access

The Python Key Vault helper uses the Azure CLI token if no explicit Key Vault
token is supplied.

```bash
az login --tenant "$TENANT_ID"
az account show --query '{tenantId:tenantId,subscriptionId:id,user:user.name}' -o json
```

The signed-in identity needs Key Vault data-plane permissions to create and sign
with keys, such as the Key Vault Crypto Officer role or equivalent permissions.

## 3. Register the passkey using TAP

The command creates an EC P-256 key in Key Vault and saves the public credential
metadata locally. The private key is not exported.

```bash
read -rsp "Temporary Access Pass: " TAP
printf '\n'

"$PYTHON_COMMAND" "$REGISTER_SCRIPT" \
  --tenant-id "$TENANT_ID" \
  --keyvault-name "$KEYVAULT_NAME" \
  --user-principal-name "$UPN" \
  --display-name "ROADtools passkey" \
  --output-path "$CREDENTIAL_PATH" \
  tap \
  --tap "$TAP"

unset TAP
```

If the credential already exists, skip this step and point `CREDENTIAL_PATH` at
the existing JSON file.

## 4. Authenticate with the passkey and hand the cookie to roadtx

Use the adapter rather than copying the cookie through shell output. It keeps the
cookie in memory, invokes `roadtx interactiveauth --estscookie`, and writes the
resulting token file to `ROADTOOLS_TOKEN_PATH`.

The `aadgraph` resource is intentional: ROADrecon expects an access token whose
audience is `https://graph.windows.net`.

```bash
"$PYTHON_COMMAND" "$ROADTX_ADAPTER" \
  --credential-path "$CREDENTIAL_PATH" \
  --keyvault-tenant-id "$TENANT_ID" \
  --roadtx-command "$ROADTX_COMMAND" \
  --roadtx-resource aadgraph \
  --roadtx-tokenfile "$ROADTOOLS_TOKEN_PATH" \
  --roadtx-headless

# roadtx may preserve its own file mode; enforce private permissions afterward.
chmod 600 "$ROADTOOLS_TOKEN_PATH"
```

The validation was performed headless. For a visible browser, omit
`--roadtx-headless` (the default).

If Selenium Manager cannot find geckodriver, resolve or install it separately
and add this option:

```bash
  --roadtx-driver-path "/path/to/geckodriver"
```

The ESTS cookie is a bearer credential. Do not print it, put it in shell history,
or share process listings. Current `roadtx` receives it as a process argument.

## 5. Gather with roadrecon

Because step 4 requested `aadgraph`, the token file can be used directly:

```bash
"$ROADRECON_COMMAND" gather \
  --tokenfile "$ROADTOOLS_TOKEN_PATH" \
  --database "$ROADRECON_DATABASE_PATH" \
  --autotoken

chmod 600 "$ROADRECON_DATABASE_PATH"
```

`--autotoken` lets ROADrecon renew the access token from the refresh token when
needed. Add `--skip-azure` if you want to omit the slower Azure/PIM collection.

## Alternative: request Microsoft Graph first

If you want the normal Microsoft Graph v2 token instead, replace the resource
arguments in step 4 with:

```bash
  --roadtx-scope "https://graph.microsoft.com/.default"
```

Then exchange that refresh token for the AAD Graph audience before gathering:

```bash
cp "$ROADTOOLS_TOKEN_PATH" "$ROADRECON_TOKEN_PATH"

"$ROADRECON_COMMAND" auth \
  --refresh-token file \
  --tokenfile "$ROADRECON_TOKEN_PATH" \
  --client azcli \
  --resource aadgraph

"$ROADRECON_COMMAND" gather \
  --tokenfile "$ROADRECON_TOKEN_PATH" \
  --database "$ROADRECON_DATABASE_PATH" \
  --autotoken
```

## Troubleshooting

Run the passkey login script directly with `--debug` to see safe HTTP/page/cookie
diagnostics without printing cookie values:

```bash
"$PYTHON_COMMAND" "$LOGIN_SCRIPT" \
  --credential-path "$CREDENTIAL_PATH" \
  --keyvault-tenant-id "$TENANT_ID" \
  --debug
```

An `AADSTS50105` error means the selected first-party application is blocked by
tenant assignment policy. Grant the user or an appropriate group access to that
enterprise application, then retry. It is not a Key Vault signing error.
