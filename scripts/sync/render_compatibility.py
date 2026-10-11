#!/usr/bin/env python3
"""Render historical public entry points; protocol edits belong in canonical sources."""
import argparse
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = Path('compatibility/nathanmcnulty/Entra/passkeys')

def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f'Canonical source changed: expected one occurrence of {old!r}')
    return text.replace(old, new, 1)

def login(source, keyvault=False):
    text = replace_once(source, '[CmdletBinding()]\nparam (', '[CmdletBinding(PositionalBinding = $false)]\nparam (')
    text = replace_once(text, "[Alias('CredentialId')]", "[Alias('CredentialIdentifier')]")
    text = re.sub(r'\$CredentialIdentifier\b', '$CredentialId', text)
    names = ['KeyFilePath', 'UserPrincipalName', 'UserHandle', 'CredentialId', 'PrivateKey', 'RelyingParty', 'AuthUrl', 'UserAgent', 'Proxy']
    if keyvault:
        names = ['CredentialFromPipeline'] + names + ['KeyVaultName','KeyVaultKeyName','KeyVaultAccessToken','KeyVaultClientId','KeyVaultClientSecret','KeyVaultTenantId','PassThru']
    # Only the top-level parameter block is adapted; no helper/HTTP/signing code is rendered.
    start = text.index('param (')
    end = text.index('#region Helper Functions')
    block = text[start:end]
    for position, name in enumerate(names):
        pattern = r'\[Parameter\(([^\n]*)\)\](?P<between>\s*(?:\[Alias\([^\n]*\)\]\s*)?(?:\[[^\n]*\])?\$' + name + r'\b)'
        block, count = re.subn(pattern, lambda m: '[Parameter(Position = '+str(position)+', '+m.group(1)+')]'+m.group('between'), block)
        if count != 1:
            raise ValueError(f'Canonical parameter changed: {name}')
    text = text[:start]+block+text[end:]
    # Preserve the explicitly opted-in personal-repo session alias and output label.
    text = replace_once(text, '$global:ESTSCookie = $ests.Value\n', '$global:ESTSCookie = $ests.Value\n            $global:ESTSAUTH = $ests.Value # Legacy alias, only when explicitly requested\n')
    text = replace_once(text, "TokenVariable         = if ($PersistSessionToGlobalScope) { 'ESTSCookie' }", "TokenVariable         = if ($PersistSessionToGlobalScope) { 'ESTSAUTH' }")
    return text

def render(root=ROOT):
    action = (root/'github/action-passkey-login/PasskeyLogin.ps1').read_text(encoding='utf-8')
    outputs = {OUTPUT/'PasskeyLogin.ps1':login(action), OUTPUT/'keyvault/PasskeyLogin.ps1':login(action, True)}
    # Research names are adapted only in help/example/output strings; behavior stays canonical.
    renames = {'Initialize-EntraPasskeyKeyVault':'Initialize-PasskeyKeyVault', 'Register-EntraSoftwarePasskey':'New-KeyVaultPasskey', 'Invoke-EntraPasskeyLogin':'PasskeyLogin'}
    for canonical, public in [('Initialize-EntraPasskeyKeyVault.ps1','Initialize-PasskeyKeyVault.ps1'),('Register-EntraSoftwarePasskey.ps1','New-KeyVaultPasskey.ps1')]:
        text = (root/'powershell/scripts/entra/reference'/canonical).read_text(encoding='utf-8')
        for old,new in renames.items(): text=text.replace(old,new)
        outputs[OUTPUT/'keyvault'/public]=text
    return {path:text.encode('utf-8') for path,text in outputs.items()}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='Check committed generated files without writing')
    args=parser.parse_args()
    outputs=render()
    stale=[]
    for path,data in outputs.items():
        target=ROOT/path
        if args.check:
            if not target.is_file() or target.read_bytes()!=data:stale.append(str(path))
        else:
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(data)
    if stale:parser.exit(1,'Stale generated files:\n'+'\n'.join(stale)+'\n')
    print(f'{len(outputs)} compatibility entry points '+('verified' if args.check else 'rendered'))

if __name__=='__main__':main()
