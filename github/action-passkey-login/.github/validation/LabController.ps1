#Requires -Version 7.6
# Trusted controller functions. Importing this file does not contact any service.
function Assert-LabInputs {
    param([string]$Repository, [string]$Event, [string]$Ref, [string]$Candidate, [string]$Source, [string]$PullRequest, [string]$Controller)
    if ($Repository -cne 'nathanmcnulty/action-passkey-login' -or $Event -cne 'workflow_dispatch' -or $Ref -cne 'refs/heads/main') {
        throw 'Only an explicit dispatch on the trusted repository main is admitted.'
    }
    foreach ($sha in @($Candidate, $Source, $Controller)) {
        if ($sha -cnotmatch '\A[0-9a-f]{40}\z' -or $sha -match '\A0+\z') { throw 'A full nonzero lowercase commit SHA is required.' }
    }
    if ($PullRequest -cnotmatch '\A[1-9][0-9]{0,8}\z') { throw 'A positive pull request number is required.' }
}

function Read-LabApi {
    param([Parameter(Mandatory)][string]$Path)
    # Admit only the ten GET route shapes used below. Match the raw path without
    # decoding or normalization: percent escapes, traversal, host substitutions,
    # extra query parameters, case variants and terminal newlines are not routes.
    # The compare separator is literal three dots, not a traversal component.
    $sha = '(?!0{40}(?:[^0-9a-f]|\z))[0-9a-f]{40}'
    $routes = @(
        '/repos/nathanmcnulty/action-passkey-login/git/ref/heads/main'
        '/repos/nathanmcnulty/action-passkey-login/pulls/[1-9][0-9]{0,8}'
        "/repos/nathanmcnulty/research-passkeys/compare/$sha\.\.\.main"
        "/repos/nathanmcnulty/research-passkeys/git/trees/$sha\?recursive=1"
        "/repos/nathanmcnulty/action-passkey-login/git/commits/$sha"
        "/repos/nathanmcnulty/action-passkey-login/git/trees/$sha\?recursive=1"
        "/repos/nathanmcnulty/action-passkey-login/actions/workflows/ci\.yml/runs\?head_sha=$sha&event=push&per_page=1"
        "/repos/nathanmcnulty/research-passkeys/actions/workflows/passkey-ci\.yml/runs\?head_sha=$sha&event=push&per_page=1"
        '/repos/nathanmcnulty/action-passkey-login/environments/passkey-validation'
        '/repos/nathanmcnulty/action-passkey-login/environments/passkey-validation/deployment-branch-policies\?per_page=100'
    )
    if (-not ($routes | Where-Object { $Path -cmatch ('\A' + $_ + '\z') })) {
        throw 'Unexpected API target.'
    }
    try {
        Invoke-RestMethod -Uri ('https://api.github.com' + $Path) -Headers @{
            Authorization = "Bearer $env:GH_TOKEN"
            Accept = 'application/vnd.github+json'
            'X-GitHub-Api-Version' = '2022-11-28'
        } -MaximumRedirection 0 -ConnectionTimeoutSeconds 20 -OperationTimeoutSeconds 30 -Verbose:$false -Debug:$false -ErrorAction Stop
    } catch { throw 'GitHub admission read failed; no candidate admitted.' }
}

function Assert-LabEnvironment {
    param($Environment, $Policies)
    if ($Environment.protection_rules -isnot [array]) { throw 'Protection rules must be an array.' }
    $reviewers = @($Environment.protection_rules | Where-Object { $_.type -is [string] -and $_.type -ceq 'required_reviewers' })
    if ($Environment.name -isnot [string] -or $Environment.name -cne 'passkey-validation' -or $reviewers.Count -ne 1 -or
        $reviewers[0].reviewers -isnot [array] -or @($reviewers[0].reviewers).Count -lt 1) {
        throw 'The named environment must already exist with required reviewers.'
    }
    foreach ($reviewer in @($reviewers[0].reviewers)) {
        if ($null -eq $reviewer -or $reviewer.type -isnot [string] -or $reviewer.type -cnotin @('User', 'Team') -or
            $null -eq $reviewer.reviewer -or ($reviewer.reviewer.id -isnot [int] -and $reviewer.reviewer.id -isnot [long]) -or $reviewer.reviewer.id -le 0) {
            throw 'Required reviewers must identify actual users or teams.'
        }
    }
    if ($Environment.deployment_branch_policy.custom_branch_policies -isnot [bool] -or
        $Environment.deployment_branch_policy.protected_branches -isnot [bool] -or
        $Environment.deployment_branch_policy.custom_branch_policies -ne $true -or $Environment.deployment_branch_policy.protected_branches -ne $false) {
        throw 'Explicit selected-branch environment policy is required.'
    }
    $branches = @($Policies.branch_policies)
    if (($Policies.total_count -isnot [int] -and $Policies.total_count -isnot [long]) -or
        $Policies.total_count -ne 1 -or $Policies.branch_policies -isnot [array] -or $branches.Count -ne 1 -or
        $branches[0].name -isnot [string] -or $branches[0].type -isnot [string] -or
        $branches[0].name -cne 'main' -or $branches[0].type -cne 'branch') {
        throw 'The environment must admit only the main branch, not tags or patterns.'
    }
    # The API may omit this property on some GitHub plans. Setup review must verify
    # bypass is disabled where supported; a visible enabled bypass always fails.
    $hasBypass = if ($Environment -is [System.Collections.IDictionary]) { $Environment.Contains('can_admins_bypass') } else { $null -ne $Environment.PSObject.Properties['can_admins_bypass'] }
    if ($hasBypass -and ($Environment.can_admins_bypass -isnot [bool] -or $Environment.can_admins_bypass -eq $true)) {
        throw 'Disable environment administrator bypass; malformed policy is not accepted.'
    }
}

function Assert-LabCi {
    param($Runs, [string]$Repository, [string]$Sha, [string]$Workflow)
    $items = @($Runs.workflow_runs)
    if ($items.Count -ne 1) { throw 'No exact-head offline CI evidence.' }
    $run = $items[0]
    if ($run.head_sha -cne $Sha -or $run.path -cne $Workflow -or $run.event -cne 'push' -or
        $run.head_repository.full_name -cne $Repository -or $run.status -cne 'completed' -or $run.conclusion -cne 'success') {
        throw 'Latest exact-head offline run/attempt must have completed successfully.'
    }
    if ([string]$run.id -notmatch '\A[1-9][0-9]*\z' -or [string]$run.run_attempt -notmatch '\A[1-9][0-9]*\z') { throw 'Missing CI run identity.' }
    return @{ RunId = [long]$run.id; Attempt = [int]$run.run_attempt }
}

function Invoke-LabAdmission {
    param([string]$Candidate, [string]$Source, [string]$PullRequest, [string]$Controller)
    Assert-LabInputs $env:GITHUB_REPOSITORY $env:GITHUB_EVENT_NAME $env:GITHUB_REF $Candidate $Source $PullRequest $Controller
    if ($env:GITHUB_SHA -cne $Controller) { throw 'Controller must match the dispatched main revision.' }
    if ($env:GITHUB_RUN_ATTEMPT -cne '1') { throw 'Reruns are not admitted; use a fresh reviewed dispatch.' }
    if ($env:GITHUB_WORKFLOW_REF -cne 'nathanmcnulty/action-passkey-login/.github/workflows/validate-lab-cookie.yml@refs/heads/main') {
        throw 'Unexpected controller workflow identity.'
    }
    $repo = '/repos/nathanmcnulty/action-passkey-login'
    $canonical = '/repos/nathanmcnulty/research-passkeys'
    $main = Read-LabApi "$repo/git/ref/heads/main"
    if ($main.object.sha -cne $Controller) { throw 'Main changed; use a fresh reviewed dispatch.' }
    $pr = Read-LabApi "$repo/pulls/$PullRequest"
    if ($pr.state -cne 'open' -or $pr.head.sha -cne $Candidate -or
        $pr.head.repo.full_name -cne 'nathanmcnulty/action-passkey-login' -or
        $pr.base.repo.full_name -cne 'nathanmcnulty/action-passkey-login' -or $pr.base.ref -cne 'main') {
        throw 'Candidate is not the current same-repository PR head targeting main.'
    }
    $ancestry = Read-LabApi "$canonical/compare/${Source}...main"
    if ($ancestry.status -notin @('ahead', 'identical') -or $ancestry.merge_base_commit.sha -cne $Source) {
        throw 'Source revision must already belong to canonical main.'
    }
    $sourceTree = Read-LabApi "$canonical/git/trees/${Source}?recursive=1"
    $candidateCommit = Read-LabApi "$repo/git/commits/$Candidate"
    $candidateTree = Read-LabApi "$repo/git/trees/${Candidate}?recursive=1"
    if ($sourceTree.truncated -or $candidateTree.truncated) { throw 'Incomplete source inventory.' }
    $subtree = @($sourceTree.tree | Where-Object { $_.path -ceq 'github/action-passkey-login' -and $_.type -ceq 'tree' })
    if ($subtree.Count -ne 1 -or $subtree[0].sha -cne $candidateCommit.tree.sha) { throw 'Candidate root is not the exact canonical Action subtree.' }
    $actionCi = @($candidateTree.tree | Where-Object { $_.path -ceq '.github/workflows/ci.yml' -and $_.type -ceq 'blob' })
    $sourceCi = @($sourceTree.tree | Where-Object { $_.path -ceq '.github/workflows/passkey-ci.yml' -and $_.type -ceq 'blob' })
    if ($actionCi.Count -ne 1 -or $actionCi[0].sha -cne 'ca67148179b12d1f465b49a082ceb7a708984c83' -or
        $sourceCi.Count -ne 1 -or $sourceCi[0].sha -cne '8b53d7b6cbee6d9d1225521b0067fc702a25ab0a') {
        throw 'Offline workflow changed; a separate controller review is required.'
    }
    # per_page=1 deliberately rejects an older success when the latest run is pending/failed.
    $runs = Read-LabApi "$repo/actions/workflows/ci.yml/runs?head_sha=$Candidate&event=push&per_page=1"
    $actionEvidence = Assert-LabCi $runs 'nathanmcnulty/action-passkey-login' $Candidate '.github/workflows/ci.yml'
    $sourceRuns = Read-LabApi "$canonical/actions/workflows/passkey-ci.yml/runs?head_sha=$Source&event=push&per_page=1"
    $sourceEvidence = Assert-LabCi $sourceRuns 'nathanmcnulty/research-passkeys' $Source '.github/workflows/passkey-ci.yml'
    $environment = Read-LabApi "$repo/environments/passkey-validation"
    $policies = Read-LabApi "$repo/environments/passkey-validation/deployment-branch-policies?per_page=100"
    Assert-LabEnvironment $environment $policies
    return [ordered]@{
        CandidateSha = $Candidate; SourceSha = $Source; ControllerSha = $Controller
        ActionCi = $actionEvidence; CanonicalCi = $sourceEvidence
        Scenario = 'ReviewedSourceSessionReuse'; IndependentReadback = 'RequiredNotYetRun'
    }
}

function Assert-LabCookieContract {
    param([string]$Authenticated, [string]$Cookie, [string]$CookieName, [string]$Method, [string]$RequestedUpn, [string]$ReturnedUpn)
    if ($Authenticated -cne 'true' -or [string]::IsNullOrWhiteSpace($Cookie) -or
        $CookieName -cnotin @('ESTSAUTH', 'ESTSAUTHPERSISTENT') -or $Method -cne 'Local Private Key' -or
        [string]::IsNullOrWhiteSpace($RequestedUpn) -or $ReturnedUpn -cne $RequestedUpn) {
        throw 'Cookie output contract failed; sensitive values suppressed.'
    }
    # ReturnedUpn is input-derived: equality is only plumbing, not identity proof.
}
