# function-app

This folder is for Function App-specific samples and templates.

The current sample is:

- `powershell\keyvault-passkey-http`: PowerShell HTTP-triggered Functions + Bicep + Key Vault for Entra TAP/ESTSAUTH registration, Entra login, and Okta IDX/MyAccount examples
- `python\keyvault-passkey-http`: Python HTTP-triggered Functions + Bicep + Key Vault for Entra TAP/ESTSAUTH registration, Entra login, and Okta IDX/MyAccount examples

The goal is to keep Functions as a host surface, not as the owner of shared business logic:

- shared auth, Key Vault, and metadata helpers should live elsewhere
- Functions should provide trigger bindings, configuration, and deployment shape

Both samples persist successful Entra and Okta registrations in an Azure Table-backed passkey catalog and expose matching `GET /api/passkeys` lookup routes. The shared record contract and the broker/direct-access design are documented in `contracts/passkey-catalog-record.schema.json` and `docs/architecture/passkey-catalog.md`.

The Entra ESTSAUTH surface intentionally has two routes: `RegisterEntraPasskeyViaEstsAuth` is the synchronous compatibility route, while webhook callers should use `QueueEntraPasskeyRegistrationViaEstsAuth` at `/api/entra/passkeys/register/estsauth/queue` to return immediately and let the queue-triggered worker perform the registration.

## Development validation deployments

The normal `development` profile remains public-networked and does not create a VNet. For a validation deployment that needs predictable outbound visibility, use a dedicated Flex Consumption subnet in the existing VNet that owns the NAT Gateway. Azure NAT Gateways cannot span VNets, so the helper integrates both apps with that existing subnet instead of creating a second VNet/NAT pair. It does not create another NAT Gateway, VM, or public IP. The existing VNet/subnet must be in the same subscription and Azure region as the new Function Apps.

For the current validation subscription, the verified network names are `nat-phish` and `vm-phish-vnet` in `rg-phish` (`vm-phish-net` does not exist). The original `snet-func-kvpk-armxxd6b` is a valid delegated `/27` subnet and remains attached to the existing Function App. Two dedicated `/26` subnets were added for these disposable deployments: `snet-func-kvpk-entra` (`10.0.1.64/26`) and `snet-func-kvpk-okta` (`10.0.1.128/26`). Both are delegated to `Microsoft.App/environments` and attached to the same `nat-phish` gateway.

Find the existing gateway and one of its subnet IDs first:

```powershell
az network nat gateway list --resource-group rg-phish --output table
az network nat gateway show --resource-group rg-phish --name <existing-nat-name> --query "subnets[].id" --output tsv
```

Use a dedicated subnet that is valid for Flex Consumption VNet integration; do not point a Function App at a VM/private-endpoint subnet. Then deploy the two samples into separate disposable resource groups:

The `rg-phish-entra` and `rg-phish-okta` names are only isolation labels; each sample contains both the Entra and Okta route families. Exercise whichever provider routes you need in each runtime.

```powershell
pwsh -NoProfile -File ./scripts/deployment/Deploy-FunctionSample.ps1 `
  -TemplateId powershell-keyvault-passkey-http `
  -ResourceGroupName rg-phish-entra `
  -Location westus2 `
  -DeploymentProfile development `
  -ExistingNatGatewayName <existing-nat-name> `
  -ExistingNatGatewayResourceGroupName rg-phish `
  -ExistingVirtualNetworkName <existing-vnet-name> `
  -ExistingVirtualNetworkResourceGroupName rg-phish `
  -ExistingFunctionSubnetName <existing-flex-subnet-name> `
  -GrantCurrentUserDevelopmentAccess `
  -EnableDevelopmentSecretExport `
  -PassThru

pwsh -NoProfile -File ./scripts/deployment/Deploy-FunctionSample.ps1 `
  -TemplateId python-keyvault-passkey-http `
  -ResourceGroupName rg-phish-okta `
  -Location westus2 `
  -DeploymentProfile development `
  -ExistingNatGatewayName <existing-nat-name> `
  -ExistingNatGatewayResourceGroupName rg-phish `
  -ExistingVirtualNetworkName <existing-vnet-name> `
  -ExistingVirtualNetworkResourceGroupName rg-phish `
  -ExistingFunctionSubnetName <existing-flex-subnet-name> `
  -OktaDomain <your-org.okta.com> `
  -GrantCurrentUserDevelopmentAccess `
  -EnableDevelopmentSecretExport `
  -PassThru
```

`-ExistingNatGatewayName` is a preflight check: the helper verifies that the named NAT is already attached to the supplied subnet, then passes only the existing VNet/subnet to Bicep. It fails rather than trying to attach a shared NAT to a newly-created VNet. Use `-EnableVirtualNetworkIntegration` instead when testing a new, NAT-free VNet. After ARM deployment, the helper polls the required RBAC assignments and (for development grants) a storage data-plane read for up to 10 minutes before uploading code; adjust `-PermissionPropagationTimeoutSeconds` and `-PermissionPollIntervalSeconds` when needed. The development profile still leaves Storage and Key Vault publicly reachable for direct inspection and keeps the development-only access controls; production defaults are unchanged.

The helper validates that the referenced gateway exists and is in the requested region before deployment. It also runs Bicep what-if, deploys the Function code unless `-SkipCodeDeploy` is specified, and verifies the deployed storage resources and app settings. Delete only the disposable groups when finished:

```powershell
az group delete --name rg-phish-entra --yes --no-wait
az group delete --name rg-phish-okta --yes --no-wait
```

Those deletes remove the new Function Apps and their resource-group-local resources but do not remove the existing VNet, subnet, or NAT Gateway in `rg-phish`.
