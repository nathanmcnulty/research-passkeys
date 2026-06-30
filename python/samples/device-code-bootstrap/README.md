# Python device code bootstrap sample

This sample is a CA-friendly local bootstrap for delegated auth research. It intentionally comes **before** more brittle username+password or cookie-based automation.

It uses MSAL Python device code flow to:

- prompt the user to complete sign-in on another device or browser
- acquire a delegated Microsoft Graph token
- print basic identity and tenant details from the issued token

## Usage

1. Install dependencies:

   ```powershell
   pip install msal requests
   ```

2. Run the sample:

   ```powershell
   python .\device_code_bootstrap.py
   ```

Optional parameters:

- `--tenant-id`
- `--client-id`
- `--scope https://graph.microsoft.com/.default`

This sample is intentionally local/CLI-first. It is meant to establish a cleaner auth baseline before extending additional passkey research flows.
