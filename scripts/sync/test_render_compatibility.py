import unittest
import hashlib
from pathlib import Path
import render_compatibility as renderer

class CompatibilityRendering(unittest.TestCase):
    def test_generated_files_match_sources(self):
        for path,data in renderer.render().items():
            self.assertEqual((renderer.ROOT/path).read_bytes(),data,str(path))

    def test_initial_login_outputs_match_reviewed_personal_head(self):
        # Golden hashes for initial canonical migration (personal draft 956075f).
        # Future intentional implementation updates must review new golden values.
        expected = {'compatibility/nathanmcnulty/Entra/passkeys/PasskeyLogin.ps1': '95648a98005bc2f355f3114e9bf6faa25c06a4c5804ff51c399219a130763660', 'compatibility/nathanmcnulty/Entra/passkeys/keyvault/PasskeyLogin.ps1': '80027c6a876e7f0e96d6aa041a61b66941a1ab87d69b8df4151cf66892167119'}
        for path,digest in expected.items():
            self.assertEqual(hashlib.sha256(renderer.render()[Path(path)]).hexdigest(),digest)

    def test_helper_region_is_identical_to_action(self):
        source=(renderer.ROOT/'github/action-passkey-login/PasskeyLogin.ps1').read_text()
        def helpers(text):return text[text.index('#region Helper Functions'):text.index('#endregion',text.index('#region Helper Functions'))]
        for keyvault in [False,True]:self.assertEqual(helpers(source),helpers(renderer.login(source,keyvault)))

    def test_refuses_unexpected_parameter_layout(self):
        source=(renderer.ROOT/'github/action-passkey-login/PasskeyLogin.ps1').read_text()
        with self.assertRaises(ValueError):renderer.login(source.replace('[CmdletBinding()]','[CmdletBinding(DefaultParameterSetName="changed")]'))
        with self.assertRaises(ValueError):renderer.login(source.replace('$KeyFilePath,','$ChangedPath,'))

    def test_research_name_adaptation_does_not_restore_legacy_bstr(self):
        data=renderer.render()[renderer.OUTPUT/'keyvault/New-KeyVaultPasskey.ps1'].decode()
        self.assertNotIn('PtrToStringAuto',data)
        self.assertIn('[System.Net.NetworkCredential]::new',data)
        self.assertIn('New-KeyVaultPasskey.ps1',data)

if __name__=='__main__':unittest.main()
