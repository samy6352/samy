<#
.SYNOPSIS
    Azure Virtual Desktop (AVD) cost assessment - AVD components only.
.DESCRIPTION
    Reviews one subscription at a time (entered interactively, or passed via -SubscriptionIds)
    and assesses ONLY AVD-related cost components using Azure Resource Graph (read-only):
      - Host pools, session hosts, scaling plans, application groups, workspaces
      - Session host VMs (size generation, power state, Windows licensing / Hybrid Benefit, OS disk type)
      - Disks, snapshots, NIC public IPs and storage accounts (FSLogix profile storage) in AVD resource groups
      - Azure Advisor cost recommendations that hit session hosts or AVD resource groups
    Produces one Excel workbook (or CSV files if ImportExcel is not available).
    Requires only Reader on the subscriptions. Nothing is modified in Azure.
.PARAMETER SubscriptionIds
    Optional. Subscription IDs or names to review (skips the interactive prompt for those).
.PARAMETER TenantId
    Optional. Tenant to sign in to (useful for guest / multi-tenant accounts).
.PARAMETER OutputPath
    Optional. Folder for the report. Defaults to .\AVD-Assessment-Output next to the script.
.PARAMETER All
    Optional. Review every accessible enabled subscription, one after another, without prompting.
.PARAMETER NoOpen
    Optional. Do not open the report when finished.
.EXAMPLE
    .\AVD-CostAssessment.ps1
.EXAMPLE
    .\AVD-CostAssessment.ps1 -SubscriptionIds 00000000-0000-0000-0000-000000000000
.NOTES
    Findings are point-in-time configuration checks, not usage metrics. Validate licensing
    entitlement and workload patterns before acting on any finding.
#>

[CmdletBinding()]
param (
    [string[]]$SubscriptionIds,
    [string]$TenantId,
    [string]$OutputPath,
    [switch]$All,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'
if (-not $OutputPath) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputPath = Join-Path $base 'AVD-Assessment-Output'
}

# ---------------------------------------------------------------- helpers

function Initialize-Modules {
    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) { Register-PSRepository -Default -ErrorAction SilentlyContinue }
    foreach ($m in 'Az.Accounts', 'Az.ResourceGraph') {
        if (-not (Get-Module -ListAvailable -Name $m)) {
            Write-Host "Installing required module $m (current user, one-time)..." -ForegroundColor Yellow
            try { Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop }
            catch { throw "Could not install $m. Run: Install-Module $m -Scope CurrentUser  ($($_.Exception.Message))" }
        }
        Import-Module $m -ErrorAction Stop
    }
    $script:UseExcel = $false
    try {
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            Write-Host "Installing ImportExcel for the Excel report (one-time)..." -ForegroundColor Yellow
            Install-Module -Name ImportExcel -Scope CurrentUser -Force -ErrorAction Stop
        }
        Import-Module ImportExcel -ErrorAction Stop
        $script:UseExcel = $true
    }
    catch {
        Write-Host "ImportExcel unavailable - the report will be written as CSV files instead." -ForegroundColor Yellow
    }
}

function Connect-IfNeeded {
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if ($ctx -and $ctx.Account -and (-not $TenantId -or $ctx.Tenant.Id -eq $TenantId)) {
        Write-Host "Signed in as $($ctx.Account.Id)" -ForegroundColor DarkGray
        return
    }
    Write-Host "Signing in to Azure..." -ForegroundColor Cyan
    $cp = @{ WarningAction = 'SilentlyContinue' }
    if ($TenantId) { $cp.Tenant = $TenantId }
    $cloudShell = ($env:ACC_ENV -eq 'AzureCloudShell') -or ($env:CLOUD_SHELL -eq 'true')
    try {
        if ($cloudShell) { Connect-AzAccount -Identity @cp | Out-Null } else { Connect-AzAccount @cp | Out-Null }
    }
    catch {
        Write-Host "Browser sign-in failed; falling back to device code sign-in." -ForegroundColor Yellow
        Connect-AzAccount -UseDeviceAuthentication @cp | Out-Null
    }
}

function Get-AccessibleSubscriptions {
    $p = @{ WarningAction = 'SilentlyContinue' }
    if ($TenantId) { $p.TenantId = $TenantId }
    @(Get-AzSubscription @p | Where-Object { $_.State -eq 'Enabled' } | Sort-Object Name)
}

function Show-SubscriptionList {
    param($Subs)
    Write-Host "`nSubscriptions you can access:" -ForegroundColor Cyan
    for ($n = 0; $n -lt $Subs.Count; $n++) {
        Write-Host ("  [{0,2}] {1}  ({2})" -f ($n + 1), $Subs[$n].Name, $Subs[$n].Id)
    }
}
function Resolve-Subscription {
    param([string]$InputText)
    $t = $InputText.Trim()
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }
    $subs = $script:AllSubs
    $num = 0
    if ([int]::TryParse($t, [ref]$num) -and $num -ge 1 -and $num -le $subs.Count) { return $subs[$num - 1] }
    $hit = $subs | Where-Object { $_.Id -eq $t -or $_.Name -eq $t } | Select-Object -First 1
    if (-not $hit) {
        $m = @($subs | Where-Object { $_.Name -like "*$t*" })
        if ($m.Count -eq 1) { $hit = $m[0] }
        elseif ($m.Count -gt 1) { Write-Host "  '$t' matches $($m.Count) subscriptions - enter its number or ID from the list." -ForegroundColor Yellow }
    }
    return $hit
}
function Invoke-Arg {
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$SubscriptionId
    )
    $all = @()
    $page = Search-AzGraph -Query $Query -Subscription $SubscriptionId -First 1000 -ErrorAction Stop
    $all += @($page)
    while ($page -and $page.SkipToken) {
        $page = Search-AzGraph -Query $Query -Subscription $SubscriptionId -SkipToken $page.SkipToken -First 1000 -ErrorAction Stop
        $all += @($page)
    }
    return , @($all | Where-Object { $_ })
}

function Get-DateSafe {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return [datetime]::Parse($Text, [System.Globalization.CultureInfo]::InvariantCulture) } catch { return $null }
}

function Get-ScalingFloorPct {
    param([string]$SchedulesJson)
    $vals = @()
    foreach ($s in (ConvertFrom-JsonSafe $SchedulesJson)) {
        foreach ($n in 'rampUpMinimumHostsPct', 'rampDownMinimumHostsPct') {
            if ($null -ne $s.$n) { $vals += [int]$s.$n }
        }
    }
    if ($vals.Count -eq 0) { return 0 }
    return ($vals | Measure-Object -Minimum).Minimum
}

# One-time (per run) lookup of existing reservations and savings plans. Both can fail for lack of
# permissions; the assessment then reports coverage as unknown instead of assuming zero.
function Get-CommitmentContext {
    $ctx = [PSCustomObject]@{
        Reservations = @(); ReservationsKnown = $false
        SavingsPlans = @(); SavingsPlansKnown = $false
    }
    try {
        $path = '/providers/Microsoft.Capacity/reservations?api-version=2022-11-01'
        $all = @()
        while ($path) {
            $resp = Invoke-AzRestMethod -Method GET -Path $path -ErrorAction Stop
            if ($resp.StatusCode -ne 200) { throw "HTTP $($resp.StatusCode) - Reservation Reader or billing access is required" }
            $body = $resp.Content | ConvertFrom-Json
            $all += @($body.value)
            $path = $null
            if ($body.nextLink) { $path = ([uri]$body.nextLink).PathAndQuery }
        }
        $ctx.Reservations = @($all | Where-Object { $_.properties.reservedResourceType -eq 'VirtualMachines' -and $_.properties.displayProvisioningState -eq 'Succeeded' } | ForEach-Object {
                [PSCustomObject]@{
                    name = $_.name; location = ([string]$_.location).ToLower(); skuName = $_.sku.name
                    quantity = [int]$_.properties.quantity; scopeType = $_.properties.appliedScopeType
                    scopes = (@($_.properties.appliedScopes) -join ','); expiry = [string]$_.properties.expiryDate
                }
            })
        $ctx.ReservationsKnown = $true
    }
    catch { Write-Host "  Note: existing reservations could not be read ($($_.Exception.Message.Split("`n")[0])). Coverage will be shown as unknown." -ForegroundColor DarkYellow }    try {
        $resp = Invoke-AzRestMethod -Method GET -Path '/providers/Microsoft.BillingBenefits/savingsPlans?api-version=2022-11-01' -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            $plans = @(($resp.Content | ConvertFrom-Json).value)
            $ctx.SavingsPlans = @($plans | Where-Object { $_.properties.displayProvisioningState -eq 'Succeeded' -or $_.properties.provisioningState -eq 'Succeeded' })
            $ctx.SavingsPlansKnown = $true
        }
        else { Write-Host "  Note: savings plans could not be read (HTTP $($resp.StatusCode)). Coverage will be shown as unknown." -ForegroundColor DarkYellow }
    }
    catch { Write-Host "  Note: savings plans could not be read. Coverage will be shown as unknown." -ForegroundColor DarkYellow }
    return $ctx
}

# Public Azure Retail Prices API (no auth). Linux compute rate = the part a reservation / savings plan discounts.
$script:PriceCache = @{}
function Get-VmRetailPrice {
    param([string]$Size, [string]$Region)
    $key = "$Size|$Region".ToLower()
    if ($script:PriceCache.ContainsKey($key)) { return $script:PriceCache[$key] }
    $out = $null
    try {
        $base = 'https://prices.azure.com/api/retail/prices?api-version=2023-01-01-preview&$filter='
        $f = "serviceName eq 'Virtual Machines' and armRegionName eq '$Region' and armSkuName eq '$Size' and priceType eq '{0}'"
        $isStd = { $_.productName -notmatch 'Windows' -and $_.skuName -notmatch 'Spot|Low Priority' -and $_.meterName -notmatch 'Spot|Low Priority' }
        $cons = @((Invoke-RestMethod -Uri ($base + [uri]::EscapeDataString(($f -f 'Consumption'))) -TimeoutSec 30).Items | Where-Object $isStd) | Select-Object -First 1
        $res = @((Invoke-RestMethod -Uri ($base + [uri]::EscapeDataString(($f -f 'Reservation'))) -TimeoutSec 30).Items | Where-Object $isStd)
        if ($cons -and $cons.unitPrice -gt 0) {
            $payg = [double]$cons.unitPrice
            $ri1 = $res | Where-Object { $_.reservationTerm -eq '1 Year' } | Select-Object -First 1
            $ri3 = $res | Where-Object { $_.reservationTerm -eq '3 Years' } | Select-Object -First 1
            $sp1 = @($cons.savingsPlan) | Where-Object { $_.term -eq '1 Year' } | Select-Object -First 1
            $sp3 = @($cons.savingsPlan) | Where-Object { $_.term -eq '3 Years' } | Select-Object -First 1
            $out = [PSCustomObject]@{
                Payg   = $payg
                Ri1    = $(if ($ri1) { [double]$ri1.unitPrice / 8760 } else { $null })
                Ri3    = $(if ($ri3) { [double]$ri3.unitPrice / (8760 * 3) } else { $null })
                Sp1Pct = $(if ($sp1) { [math]::Round((1 - [double]$sp1.unitPrice / $payg) * 100, 0) } else { $null })
                Sp3Pct = $(if ($sp3) { [math]::Round((1 - [double]$sp3.unitPrice / $payg) * 100, 0) } else { $null })
            }
        }
    }
    catch { }
    $script:PriceCache[$key] = $out
    return $out
}

function Test-InAvdRg {
    param([hashtable]$Rgs, [string]$ResourceId)
    $k = Get-RgKey $ResourceId
    return [bool]($k -and $Rgs.ContainsKey($k))
}

function Get-RgKey {
    param([string]$ResourceId)
    if ($ResourceId -match '^(/subscriptions/[^/]+/resourcegroups/[^/]+)') { return $Matches[1].ToLower() }
    return $null
}

function ConvertFrom-JsonSafe {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    try { return @($Text | ConvertFrom-Json) } catch { return @() }
}

# ---------------------------------------------------------------- queries (AVD scope only)

$script:Queries = [ordered]@{
    HostPools    = @'
resources
| where type =~ 'microsoft.desktopvirtualization/hostpools'
| project id=tolower(id), name, resourceGroup, location, subscriptionId,
    hostPoolType=tostring(properties.hostPoolType),
    loadBalancerType=tostring(properties.loadBalancerType),
    maxSessionLimit=toint(properties.maxSessionLimit),
    preferredAppGroupType=tostring(properties.preferredAppGroupType),
    startVMOnConnect=tobool(properties.startVMOnConnect),
    personalAssignment=tostring(properties.personalDesktopAssignmentType),
    validationEnvironment=tobool(properties.validationEnvironment),
    appGroupCount=array_length(properties.applicationGroupReferences)
'@
    SessionHosts = @'
desktopvirtualizationresources
| where type =~ 'microsoft.desktopvirtualization/hostpools/sessionhosts'
| extend hostPoolName = tostring(split(name,'/')[0])
| project id=tolower(id), name, hostPoolName, resourceGroup, subscriptionId,
    hostPoolId=tolower(strcat('/subscriptions/',subscriptionId,'/resourcegroups/',resourceGroup,'/providers/microsoft.desktopvirtualization/hostpools/',hostPoolName)),
    vmId=tolower(tostring(properties.resourceId)),
    status=tostring(properties.status),
    sessions=toint(properties.sessions),
    assignedUser=tostring(properties.assignedUser),
    lastHeartBeat=tostring(properties.lastHeartBeat),
    allowNewSession=tobool(properties.allowNewSession),
    osVersion=tostring(properties.osVersion),
    agentVersion=tostring(properties.agentVersion)
'@
    ScalingPlans = @'
resources
| where type =~ 'microsoft.desktopvirtualization/scalingplans'
| project id=tolower(id), name, resourceGroup, subscriptionId,
    planHostPoolType=tostring(properties.hostPoolType),
    refs=tostring(properties.hostPoolReferences),
    schedules=tostring(properties.schedules)
'@
    AppGroups    = @'
resources
| where type =~ 'microsoft.desktopvirtualization/applicationgroups'
| project id=tolower(id), name, resourceGroup, subscriptionId,
    appGroupType=tostring(properties.applicationGroupType),
    hostPoolId=tolower(tostring(properties.hostPoolArmPath)),
    workspaceId=tolower(tostring(properties.workspaceArmPath))
'@
    Workspaces   = @'
resources
| where type =~ 'microsoft.desktopvirtualization/workspaces'
| project id=tolower(id), name, resourceGroup, subscriptionId,
    appGroupRefs=tostring(properties.applicationGroupReferences)
'@
    VMs          = @'
resources
| where type =~ 'microsoft.compute/virtualmachines'
| project id=tolower(id), name, resourceGroup, location, subscriptionId,
    vmSize=tostring(properties.hardwareProfile.vmSize),
    licenseType=tostring(properties.licenseType),
    osType=tostring(properties.storageProfile.osDisk.osType),
    osDiskSku=tostring(properties.storageProfile.osDisk.managedDisk.storageAccountType),
    osDiskEphemeral=isnotempty(tostring(properties.storageProfile.osDisk.diffDiskSettings.option)),
    dataDiskCount=array_length(properties.storageProfile.dataDisks),
    powerState=tostring(properties.extended.instanceView.powerState.code),
    priority=tostring(properties.priority),
    imageSku=tostring(properties.storageProfile.imageReference.sku)
'@
    Disks        = @'
resources
| where type =~ 'microsoft.compute/disks'
| project id=tolower(id), name, resourceGroup, location, subscriptionId,
    sku=tostring(sku.name), sizeGB=toint(properties.diskSizeGB),
    state=tostring(properties.diskState), managedBy=tolower(tostring(managedBy)),
    created=tostring(properties.timeCreated)
'@
    Snapshots    = @'
resources
| where type =~ 'microsoft.compute/snapshots'
| project id=tolower(id), name, resourceGroup, location, subscriptionId,
    sku=tostring(sku.name), sizeGB=toint(properties.diskSizeGB),
    created=tostring(properties.timeCreated)
'@
    Nics         = @'
resources
| where type =~ 'microsoft.network/networkinterfaces'
| project id=tolower(id), name, resourceGroup, subscriptionId,
    vmId=tolower(tostring(properties.virtualMachine.id)),
    hasPublicIp=tostring(properties.ipConfigurations) contains 'publicIPAddress'
'@
    Storage      = @'
resources
| where type =~ 'microsoft.storage/storageaccounts'
| project id=tolower(id), name, resourceGroup, location, subscriptionId,
    kind, skuName=tostring(sku.name), accessTier=tostring(properties.accessTier)
'@
    Advisor      = @'
advisorresources
| where type =~ 'microsoft.advisor/recommendations'
| project id=tolower(id), subscriptionId,
    category=tostring(properties.category),
    impact=tostring(properties.impact),
    impactedType=tostring(properties.impactedField),
    impactedName=tostring(properties.impactedValue),
    lastUpdated=tostring(properties.lastUpdated),
    resourceId=tolower(tostring(properties.resourceMetadata.resourceId)),
    problem=tostring(properties.shortDescription.problem),
    solution=tostring(properties.shortDescription.solution),
    annualSavings=todouble(properties.extendedProperties.annualSavingsAmount),
    currency=tostring(properties.extendedProperties.savingsCurrency)
'@
}

# ---------------------------------------------------------------- assessment

# Full Advisor list for the subscription (all categories), tagged by AVD relevance
function New-AdvisorRows {
    param($Recs, [string]$SubName, [hashtable]$SessionVmIds = @{}, [hashtable]$AvdRgs = @{})
    $rows = foreach ($r in @($Recs)) {
        if (-not $r) { continue }
        $rid = [string]$r.resourceId
        $rel = 'Other'
        if ($rid -and $SessionVmIds.ContainsKey($rid)) { $rel = 'AVD session host' }
        elseif ($rid -and (Test-InAvdRg $AvdRgs $rid)) { $rel = 'AVD resource group' }
        elseif ($rid -match '^/subscriptions/[^/]+$') { $rel = 'Subscription-wide' }
        [PSCustomObject]@{
            Subscription = $SubName; Category = $r.category; Impact = $r.impact; AvdRelevance = $rel
            ResourceType = $r.impactedType; Resource = $r.impactedName; Problem = $r.problem; Solution = $r.solution
            EstAnnualSavings = $(if ($r.annualSavings) { [math]::Round($r.annualSavings, 0) } else { $null }); Currency = $r.currency
            LastUpdated = $r.lastUpdated; ResourceId = $rid
        }
    }
    $rank = @{ 'AVD session host' = 0; 'AVD resource group' = 1; 'Subscription-wide' = 2; 'Other' = 3 }
    return @($rows | Sort-Object { $rank[$_.AvdRelevance] }, Category, Impact)
}

function Invoke-AvdAssessment {
    param([Parameter(Mandatory)]$Subscription)

    $subId = $Subscription.Id
    $subName = $Subscription.Name
    $findings = New-Object System.Collections.Generic.List[object]

    function Add-Finding {
        param($Category, $Severity, $Resource, $ResourceGroup, $Finding, $Recommendation, $Savings = $null, $Source = 'AVD check')
        $findings.Add([PSCustomObject]@{
                Subscription       = $subName
                SubscriptionId     = $subId
                Category           = $Category
                Severity           = $Severity
                Resource           = $Resource
                ResourceGroup      = $ResourceGroup
                Finding            = $Finding
                Recommendation     = $Recommendation
                EstAnnualSavings   = $Savings
                Source             = $Source
            })
    }

    Write-Host "`n=== Reviewing: $subName ($subId) ===" -ForegroundColor Cyan

    $data = @{}
    foreach ($key in $script:Queries.Keys) {
        Write-Progress -Activity "Assessing $subName" -Status "Querying $key"
        try { $data[$key] = Invoke-Arg -Query $script:Queries[$key] -SubscriptionId $subId }
        catch {
            Write-Host "  WARNING: $key query failed: $($_.Exception.Message)" -ForegroundColor Yellow
            $data[$key] = @()
        }
    }

    Write-Progress -Activity "Assessing $subName" -Completed
    $hostPools = @($data.HostPools)
    $sessionHosts = @($data.SessionHosts)
    $scalingPlans = @($data.ScalingPlans)
    $appGroups = @($data.AppGroups)
    $workspaces = @($data.Workspaces)

    if ($hostPools.Count -eq 0 -and $sessionHosts.Count -eq 0) {
        Write-Host "  No AVD host pools or session hosts found in this subscription." -ForegroundColor Yellow
        return [PSCustomObject]@{
            Subscription = $subName; SubscriptionId = $subId; Findings = @(); HostPools = @(); SessionHosts = @()
            ScalingPlans = @(); Storage = @(); Commitments = @(); AdvisorAll = (New-AdvisorRows -Recs $data.Advisor -SubName $subName); Counts = [PSCustomObject]@{ HostPools = 0; SessionHosts = 0; ScalingPlans = 0 }
        }
    }

    # Lookups
    $vmById = @{}; foreach ($v in $data.VMs) { $vmById[$v.id] = $v }
    $poolById = @{}; foreach ($p in $hostPools) { $poolById[$p.id] = $p }
    $hostsByPool = @{}
    foreach ($h in $sessionHosts) {
        if (-not $hostsByPool.ContainsKey($h.hostPoolId)) { $hostsByPool[$h.hostPoolId] = @() }
        $hostsByPool[$h.hostPoolId] += $h
    }
    $sessionVmIds = @{}; foreach ($h in $sessionHosts) { if ($h.vmId) { $sessionVmIds[$h.vmId] = $true } }

    # Scaling plan -> host pool map
    $scalingByPool = @{}
    foreach ($sp in $scalingPlans) {
        foreach ($r in (ConvertFrom-JsonSafe $sp.refs)) {
            $path = ([string]$r.hostPoolArmPath).ToLower()
            if ($path) {
                if (-not $scalingByPool.ContainsKey($path)) { $scalingByPool[$path] = @() }
                $scalingByPool[$path] += [PSCustomObject]@{ Plan = $sp.name; Enabled = [bool]$r.scalingPlanEnabled; FloorPct = (Get-ScalingFloorPct $sp.schedules) }
            }
        }
        if ((ConvertFrom-JsonSafe $sp.refs).Count -eq 0) {
            Add-Finding 'Scaling plan' 'Low' $sp.name $sp.resourceGroup 'Scaling plan is not assigned to any host pool.' 'Assign it to a host pool or delete it.'
        }
    }

    # AVD resource-group scope (used for disks, snapshots, storage, advisor)
    $avdRgs = @{}
    foreach ($x in @($hostPools) + @($appGroups) + @($workspaces) + @($scalingPlans) + @($sessionHosts)) {
        $k = Get-RgKey $x.id; if ($k) { $avdRgs[$k] = $true }
    }
    foreach ($vid in $sessionVmIds.Keys) { $k = Get-RgKey $vid; if ($k) { $avdRgs[$k] = $true } }

    # ---- Host pool checks
    foreach ($p in $hostPools) {
        $hosts = @($hostsByPool[$p.id])
        $hosts = @($hosts | Where-Object { $_ })
        $plans = @($scalingByPool[$p.id])
        $plans = @($plans | Where-Object { $_ })
        $enabledPlan = @($plans | Where-Object { $_.Enabled })
        $isPooled = ($p.hostPoolType -eq 'Pooled')

        if ($hosts.Count -eq 0) {
            Add-Finding 'Host pool' 'Low' $p.name $p.resourceGroup 'Host pool has no session hosts registered.' 'Remove the host pool and its application groups if no longer needed.'
            continue
        }
        if ($plans.Count -gt 0 -and $enabledPlan.Count -eq 0) {
            Add-Finding 'Scaling' 'High' $p.name $p.resourceGroup "Scaling plan '$($plans[0].Plan)' is assigned but disabled, so hosts are not scaled." 'Enable the scaling plan on this host pool.'
        }
        elseif ($plans.Count -eq 0) {
            $sev = if ($isPooled) { 'High' } else { 'Medium' }
            $why = if ($isPooled) { 'Pooled host pool has no scaling plan; session hosts typically run 24x7.' } else { 'Personal host pool has no scaling plan; idle dedicated desktops can keep running.' }
            Add-Finding 'Scaling' $sev $p.name $p.resourceGroup "$why ($($hosts.Count) session host(s))." 'Create and assign an autoscale scaling plan (ramp-up / peak / ramp-down / off-peak) so hosts deallocate when idle.'
        }
        if ($isPooled -and $p.loadBalancerType -eq 'BreadthFirst') {
            Add-Finding 'Scaling' 'Medium' $p.name $p.resourceGroup 'Pooled host pool uses BreadthFirst load balancing, which spreads users and keeps more hosts powered on.' 'Consider DepthFirst with a sensible max session limit so autoscale can consolidate users and shut down hosts.'
        }
        if ($isPooled -and $p.maxSessionLimit -gt 0 -and $p.maxSessionLimit -le 4) {
            Add-Finding 'Density' 'Low' $p.name $p.resourceGroup "Max session limit is $($p.maxSessionLimit) on a pooled host pool." 'Review user density against VM size and workload profile; low limits increase host count.'
        }
        if (-not $isPooled -and -not $p.startVMOnConnect) {
            Add-Finding 'Scaling' 'Medium' $p.name $p.resourceGroup 'Personal host pool does not have Start VM on Connect enabled.' 'Enable Start VM on Connect so dedicated VMs can stay deallocated until users sign in.'
        }
        if ($p.appGroupCount -eq 0) {
            Add-Finding 'Hygiene' 'Low' $p.name $p.resourceGroup 'Host pool has no application groups, so users cannot reach it.' 'Attach an application group or retire the host pool and its VMs.'
        }
        $sizes = @($hosts | ForEach-Object { $vmById[$_.vmId] } | Where-Object { $_ } | Select-Object -ExpandProperty vmSize -Unique)
        if ($sizes.Count -gt 1) {
            Add-Finding 'Right-sizing' 'Low' $p.name $p.resourceGroup "Host pool mixes $($sizes.Count) VM sizes: $($sizes -join ', ')." 'Standardise on one right-sized SKU per pool for predictable density and reservation coverage.'
        }
    }

    # ---- Session host / VM checks
    $commitGroups = @{}
    $poolFloor = @{}
    foreach ($p in $hostPools) {
        $pl = @($scalingByPool[$p.id] | Where-Object { $_ -and $_.Enabled })
        $cnt = @($hostsByPool[$p.id] | Where-Object { $_ }).Count
        $poolFloor[$p.id] = if ($pl.Count -gt 0 -and $p.hostPoolType -eq 'Pooled') { [int][math]::Floor($cnt * ($pl | Measure-Object FloorPct -Minimum).Minimum / 100) } else { 0 }
    }
    foreach ($h in $sessionHosts) {
        $pool = $poolById[$h.hostPoolId]
        $poolType = if ($pool) { $pool.hostPoolType } else { '' }
        $hostLabel = $h.name
        $vm = $vmById[$h.vmId]

        if (-not $vm) {
            if ($h.vmId -and $h.vmId -like "/subscriptions/$($subId.ToLower())/*") {
                Add-Finding 'Hygiene' 'Medium' $hostLabel $h.resourceGroup 'Session host is registered but its VM no longer exists.' 'Remove the stale session host registration from the host pool.'
            }
            continue
        }

        $ps = ($vm.powerState -replace '^PowerState/', '')

        if ($ps -eq 'stopped') {
            Add-Finding 'Compute' 'High' $vm.name $vm.resourceGroup 'VM is Stopped but NOT deallocated, so compute is still billed.' 'Deallocate the VM (or let autoscale do it).'
        }
        if ($ps -eq 'running') {
            if ($h.status -eq 'Available' -and $h.sessions -eq 0) {
                Add-Finding 'Compute' 'Medium' $vm.name $vm.resourceGroup "Session host is running with 0 sessions (pool type: $poolType)." 'Confirm it is idle outside business hours; autoscale or schedule shutdown to deallocate.'
            }
            elseif ($h.status -in 'Unavailable', 'NeedsAssistance', 'Shutdown', 'UpgradeFailed', 'NoHeartbeat') {
                Add-Finding 'Compute' 'High' $vm.name $vm.resourceGroup "VM is running but session host status is '$($h.status)', so you pay for a host that cannot serve users." 'Fix the agent/domain-join issue, or deallocate/delete the host.'
            }
            $hbDate = Get-DateSafe $h.lastHeartBeat
            if ($hbDate -and $hbDate -lt (Get-Date).AddDays(-30)) {
                Add-Finding 'Compute' 'High' $vm.name $vm.resourceGroup "VM is running but the AVD agent last reported on $($hbDate.ToString('yyyy-MM-dd'))." 'Investigate or deallocate; this host is not serving users.'
            }
        }
        if ($poolType -eq 'Personal' -and [string]::IsNullOrWhiteSpace($h.assignedUser)) {
            $sev = if ($ps -eq 'running') { 'High' } else { 'Medium' }
            Add-Finding 'Compute' $sev $vm.name $vm.resourceGroup "Personal session host has no assigned user (power state: $ps)." 'Reclaim: delete the VM and disks, or keep it deallocated until needed.'
        }
        if ($vm.osType -eq 'Windows' -and ([string]::IsNullOrWhiteSpace($vm.licenseType) -or $vm.licenseType -eq 'None')) {
            Add-Finding 'Licensing' 'High' $vm.name $vm.resourceGroup 'Windows VM has no licenseType set, so Windows is billed on top of compute.' 'If eligible (Windows 10/11 per-user rights via Microsoft 365/Windows E3/E5, or RDS CAL with SA), set licenseType (Windows_Client / Windows_Server). Verify entitlement first.'
        }
        if ($vm.vmSize -match '_v[1-3]$' -or $vm.vmSize -match '^Standard_(A|DS|D|GS|G)\d+(_v2)?$') {
            Add-Finding 'Right-sizing' 'Medium' $vm.name $vm.resourceGroup "Older VM generation in use ($($vm.vmSize))." 'Test a newer generation (e.g. Dasv5/Dasv6/Dsv5) for better price-performance.'
        }
        if ($vm.osDiskSku -like 'Premium*' -and -not $vm.osDiskEphemeral) {
            $note = if ($poolType -eq 'Pooled') { 'Pooled hosts are stateless; use an ephemeral OS disk or Standard SSD.' } else { 'Consider Standard SSD for lighter workloads.' }
            Add-Finding 'Storage' 'Medium' $vm.name $vm.resourceGroup "OS disk is $($vm.osDiskSku)." $note
        }
        if ($vm.priority -ne 'Spot') {
            $gk = "$($vm.vmSize)|$($vm.location)"
            if (-not $commitGroups.ContainsKey($gk)) {
                $commitGroups[$gk] = [PSCustomObject]@{ Size = $vm.vmSize; Region = $vm.location; Total = 0; Fixed = 0; Variable = 0; Windows = 0 }
            }
            $g = $commitGroups[$gk]
            $g.Total++
            if ($vm.osType -eq 'Windows') { $g.Windows++ }
            $enabledPlans = @($scalingByPool[$h.hostPoolId] | Where-Object { $_ -and $_.Enabled })
            if ($enabledPlans.Count -gt 0) {
                if ($poolType -eq 'Pooled' -and $poolFloor[$h.hostPoolId] -gt 0) { $poolFloor[$h.hostPoolId]--; $g.Fixed++ } else { $g.Variable++ }
            }
            elseif ($ps -eq 'running' -and -not ($poolType -eq 'Personal' -and $pool -and $pool.startVMOnConnect)) { $g.Fixed++ }
            else { $g.Variable++ }
        }
    }

    # ---- Reservation / savings plan analysis (compute)
    $commitOut = @()
    $cc = $script:Commit
    foreach ($g in ($commitGroups.Values | Sort-Object Total -Descending)) {
        $region = ([string]$g.Region).ToLower().Replace(' ', '')
        $existing = 0
        if ($cc -and $cc.ReservationsKnown) {
            foreach ($rv in $cc.Reservations) {
                $applies = ($rv.scopeType -eq 'Shared') -or ($rv.scopes -like "*$subId*")
                $exp = Get-DateSafe $rv.expiry
                $live = -not ($exp -and $exp -lt (Get-Date))
                if ($applies -and $live -and $rv.skuName -eq $g.Size -and ([string]$rv.location).Replace(' ', '') -eq $region) { $existing += [int]$rv.quantity }
            }
        }
        $gap = [math]::Max(0, $g.Fixed - $existing)
        $price = Get-VmRetailPrice -Size $g.Size -Region $region
        $sav1 = $null; $sav3 = $null
        if ($price -and $gap -gt 0) {
            if ($price.Ri1) { $sav1 = [math]::Round($gap * 8760 * ($price.Payg - $price.Ri1), 0) }
            if ($price.Ri3) { $sav3 = [math]::Round($gap * 8760 * ($price.Payg - $price.Ri3), 0) }
        }
        $label = "$($g.Size) in $($g.Region)"
        if ($gap -gt 0) {
            $sev = if ($gap -ge 3 -or ($sav1 -and $sav1 -ge 5000)) { 'High' } else { 'Medium' }
            $est = if ($sav1) { " Est. saving about $([string]::Format('{0:N0}', $sav1)) USD/yr (1-year) or $([string]::Format('{0:N0}', $sav3)) USD/yr (3-year) at list price." } else { '' }
            $cov = if ($cc.ReservationsKnown) { "$existing existing reservation(s) cover this size/region" } else { 'existing reservation coverage could not be read' }
            Add-Finding 'Commitment' $sev $label '' "$($g.Fixed) always-on / baseline host(s) run on pay-as-you-go; $cov.$est" "Buy a $($gap)-instance 1- or 3-year Reserved VM Instance for the baseline (instance size flexibility applies within the family). Windows licensing is billed separately; use Hybrid Benefit where eligible." $sav1 'RI analysis'
        }
        if ($g.Variable -gt 0) {
            $spTxt = if ($price -and $price.Sp1Pct) { " Savings plan discount for this size is about $($price.Sp1Pct)% (1-year) / $($price.Sp3Pct)% (3-year) at list price." } else { '' }
            $sev = if ($g.Variable -ge 3) { 'Medium' } else { 'Low' }
            Add-Finding 'Commitment' $sev $label '' "$($g.Variable) host(s) have variable demand (autoscaled, on-demand or personal).$spTxt" 'Cover steady spend with reservations and use a Compute Savings Plan only for the hourly spend you are sure to consume across pools; do not size either commitment to peak.' $null 'Savings plan analysis'
        }
        $commitOut += [PSCustomObject]@{
            Subscription = $subName; VmSize = $g.Size; Region = $g.Region; TotalHosts = $g.Total
            BaselineHosts = $g.Fixed; VariableHosts = $g.Variable; WindowsHosts = $g.Windows
            ExistingReservations = $(if ($cc.ReservationsKnown) { $existing } else { 'unknown' })
            ReservationGap = $gap
            PaygHourlyUSD = $(if ($price) { [math]::Round($price.Payg, 4) } else { $null })
            Ri1yHourlyUSD = $(if ($price -and $price.Ri1) { [math]::Round($price.Ri1, 4) } else { $null })
            Ri3yHourlyUSD = $(if ($price -and $price.Ri3) { [math]::Round($price.Ri3, 4) } else { $null })
            SavingsPlan1yPct = $(if ($price) { $price.Sp1Pct } else { $null })
            SavingsPlan3yPct = $(if ($price) { $price.Sp3Pct } else { $null })
            Est1yAnnualSavingsUSD = $sav1; Est3yAnnualSavingsUSD = $sav3
        }
    }
    if ($cc -and $cc.SavingsPlansKnown -and $cc.SavingsPlans.Count -gt 0) {
        $hr = 0
        foreach ($sp in $cc.SavingsPlans) { if ($sp.properties.commitment.amount) { $hr += [double]$sp.properties.commitment.amount } }
        Add-Finding 'Commitment' 'Info' 'Existing savings plans' '' "$($cc.SavingsPlans.Count) active savings plan(s) visible to you, totalling about $([string]::Format('{0:N2}', $hr)) per hour. Scope may include non-AVD workloads." 'Check utilisation in Cost Management before adding more commitment; savings plans are consumed by any eligible compute in scope.' $null 'Savings plan analysis'
    }
    elseif ($cc -and -not $cc.SavingsPlansKnown) {
        Add-Finding 'Commitment' 'Info' 'Existing savings plans' '' 'Existing savings plans could not be read with this identity, so coverage is unknown.' 'Check Cost Management > Reservations / Savings plans (or ask a billing owner) before buying new commitments.' $null 'Savings plan analysis'
    }

    # ---- Network: public IPs on session hosts
    foreach ($n in $data.Nics) {
        if ($n.hasPublicIp -and $n.vmId -and $sessionVmIds.ContainsKey($n.vmId)) {
            $vmName = ($n.vmId -split '/')[-1]
            Add-Finding 'Network' 'Medium' $vmName $n.resourceGroup 'Session host NIC has a public IP address (cost and exposure).' 'Remove the public IP; AVD uses reverse connect and does not need inbound public access.'
        }
    }

    # ---- Disks in AVD resource groups
    foreach ($d in $data.Disks) {
        $rgk = Get-RgKey $d.id
        if (-not $avdRgs.ContainsKey($rgk)) { continue }
        if ($d.state -eq 'Unattached' -and -not $d.managedBy) {
            $sev = if ($d.sku -like 'Premium*' -or $d.sizeGB -ge 256) { 'High' } else { 'Medium' }
            Add-Finding 'Storage' $sev $d.name $d.resourceGroup "Unattached $($d.sku) disk, $($d.sizeGB) GB, in an AVD resource group." 'Snapshot if needed, then delete.'
        }
    }
    foreach ($s in $data.Snapshots) {
        $rgk = Get-RgKey $s.id
        if (-not $avdRgs.ContainsKey($rgk)) { continue }
        $cd = Get-DateSafe $s.created
        if ($cd -and $cd -lt (Get-Date).AddDays(-30)) {
            Add-Finding 'Storage' 'Low' $s.name $s.resourceGroup "Snapshot older than 30 days ($($s.sizeGB) GB, created $($cd.ToString('yyyy-MM-dd')))." 'Delete obsolete snapshots, e.g. left over from image builds.'
        }
    }

    # ---- Storage accounts in AVD resource groups (FSLogix / MSIX)
    $storageInScope = @()
    foreach ($sa in $data.Storage) {
        $rgk = Get-RgKey $sa.id
        if (-not $avdRgs.ContainsKey($rgk)) { continue }
        $storageInScope += $sa
        $likely = ($sa.name -match 'fslogix|profile|avd|wvd|msix')
        if ($sa.kind -eq 'FileStorage' -or $sa.skuName -like 'Premium*') {
            Add-Finding 'Storage' 'Medium' $sa.name $sa.resourceGroup "Premium file storage ($($sa.skuName))$(if($likely){' - likely FSLogix profiles'}). Premium is billed on provisioned size." 'Compare provisioned vs used capacity; right-size the share or use standard/pay-as-you-go tiers if IOPS needs allow.'
        }
        if ($sa.skuName -match 'GRS|GZRS') {
            Add-Finding 'Storage' 'Medium' $sa.name $sa.resourceGroup "Geo-redundant storage ($($sa.skuName))$(if($likely){' for profile data'})." 'Use LRS/ZRS where cross-region replication of profile data is not required.'
        }
    }

    # ---- Advisor cost recommendations touching AVD scope
    foreach ($a in $data.Advisor) {
        if (-not $a.resourceId -or $a.category -ne 'Cost') { continue }
        if ($a.resourceId -match '^/subscriptions/[^/]+$' -and $a.problem -match 'reserv|savings plan') {
            $sv = if ($a.annualSavings) { [math]::Round($a.annualSavings, 0) } else { $null }
            Add-Finding 'Advisor' 'Info' 'Subscription-wide' '' "$($a.problem) [not AVD-specific; covers all VMs in the subscription]" $a.solution $sv 'Azure Advisor'
            continue
        }
        $linked = $sessionVmIds.ContainsKey($a.resourceId)
        $inRg = Test-InAvdRg $avdRgs $a.resourceId
        if (-not ($linked -or $inRg)) { continue }
        $sev = switch ($a.impact) { 'High' { 'High' } 'Medium' { 'Medium' } default { 'Low' } }
        $savings = if ($a.annualSavings) { [math]::Round($a.annualSavings, 0) } else { $null }
        $scope = if ($linked) { 'session host' } else { 'AVD resource group' }
        Add-Finding 'Advisor' $sev (($a.resourceId -split '/')[-1]) ((($a.resourceId -split '/')[4])) "$($a.problem) [$scope]" $a.solution $savings 'Azure Advisor'
    }

    $advisorAll = New-AdvisorRows -Recs $data.Advisor -SubName $subName -SessionVmIds $sessionVmIds -AvdRgs $avdRgs

    # ---- Output objects
    $hostPoolOut = $hostPools | ForEach-Object {
        $hosts = @($hostsByPool[$_.id] | Where-Object { $_ })
        $plans = @($scalingByPool[$_.id] | Where-Object { $_ })
        [PSCustomObject]@{
            Subscription = $subName; HostPool = $_.name; ResourceGroup = $_.resourceGroup; Location = $_.location
            Type = $_.hostPoolType; LoadBalancer = $_.loadBalancerType; MaxSessions = $_.maxSessionLimit
            StartVMOnConnect = $_.startVMOnConnect; SessionHosts = $hosts.Count
            ScalingPlan = (($plans | ForEach-Object { "$($_.Plan) (enabled=$($_.Enabled))" }) -join '; ')
        }
    }
    $hostOut = $sessionHosts | ForEach-Object {
        $vm = $vmById[$_.vmId]
        [PSCustomObject]@{
            Subscription = $subName; HostPool = $_.hostPoolName; SessionHost = $_.name; Status = $_.status
            Sessions = $_.sessions; AssignedUser = $_.assignedUser; LastHeartBeat = $_.lastHeartBeat
            VmSize = $(if ($vm) { $vm.vmSize } else { '' })
            PowerState = $(if ($vm) { ($vm.powerState -replace '^PowerState/', '') } else { '' })
            LicenseType = $(if ($vm) { $vm.licenseType } else { '' })
            OsDisk = $(if ($vm) { $vm.osDiskSku } else { '' })
            OsVersion = $_.osVersion; AgentVersion = $_.agentVersion
        }
    }
    $planOut = $scalingPlans | ForEach-Object {
        [PSCustomObject]@{ Subscription = $subName; ScalingPlan = $_.name; ResourceGroup = $_.resourceGroup; HostPoolType = $_.planHostPoolType; AssignedPools = (ConvertFrom-JsonSafe $_.refs).Count }
    }
    $storageOut = $storageInScope | ForEach-Object {
        [PSCustomObject]@{ Subscription = $subName; StorageAccount = $_.name; ResourceGroup = $_.resourceGroup; Kind = $_.kind; Sku = $_.skuName; AccessTier = $_.accessTier }
    }

    return [PSCustomObject]@{
        Subscription = $subName; SubscriptionId = $subId
        Findings     = $findings.ToArray()
        HostPools    = @($hostPoolOut); SessionHosts = @($hostOut); ScalingPlans = @($planOut); Storage = @($storageOut); Commitments = @($commitOut); AdvisorAll = $advisorAll
        Counts       = [PSCustomObject]@{ HostPools = $hostPools.Count; SessionHosts = $sessionHosts.Count; ScalingPlans = $scalingPlans.Count }
    }
}

function Show-SubscriptionResult {
    param($Result)
    $f = @($Result.Findings)
    $adv = @($Result.AdvisorAll)
    Write-Host "`n--- $($Result.Subscription): $($Result.Counts.HostPools) host pool(s), $($Result.Counts.SessionHosts) session host(s), $($Result.Counts.ScalingPlans) scaling plan(s) ---" -ForegroundColor Green
    if ($adv.Count -gt 0) {
        $bycat = ($adv | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', '
        Write-Host "Advisor: $($adv.Count) recommendation(s) in the subscription ($bycat) - see the 'Advisor' sheet." -ForegroundColor Gray
    }
    if ($f.Count -eq 0) { Write-Host "No findings." -ForegroundColor Green; return }
    foreach ($sev in 'High', 'Medium', 'Low', 'Info') {
        $n = @($f | Where-Object Severity -eq $sev).Count
        $color = switch ($sev) { 'High' { 'Red' } 'Medium' { 'Yellow' } 'Low' { 'Gray' } default { 'Cyan' } }
        Write-Host ("  {0,-7} {1}" -f $sev, $n) -ForegroundColor $color
    }
    Write-Host "`nTop findings:" -ForegroundColor Cyan
    $order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    $f | Sort-Object { $order[$_.Severity] }, Category | Select-Object -First 15 Severity, Category, Resource, Finding |
        Format-Table -AutoSize -Wrap | Out-String | Write-Host
}

function Export-Report {
    param([object[]]$Results)
    $stamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
    $order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }

    $findings = @($Results | ForEach-Object { $_.Findings }) | Sort-Object { $order[$_.Severity] }, Subscription, Category
    $summary = foreach ($r in $Results) {
        $f = @($r.Findings)
        [PSCustomObject]@{
            Subscription = $r.Subscription; SubscriptionId = $r.SubscriptionId
            HostPools = $r.Counts.HostPools; SessionHosts = $r.Counts.SessionHosts; ScalingPlans = $r.Counts.ScalingPlans
            High = @($f | Where-Object Severity -eq 'High').Count
            Medium = @($f | Where-Object Severity -eq 'Medium').Count
            Low = @($f | Where-Object Severity -eq 'Low').Count
            Info = @($f | Where-Object Severity -eq 'Info').Count
            AdvisorAnnualSavings = ($f | Where-Object { $_.EstAnnualSavings } | Measure-Object EstAnnualSavings -Sum).Sum
        }
    }
    $sheets = [ordered]@{
        Summary      = @($summary)
        Findings     = @($findings)
        Advisor      = @($Results | ForEach-Object { $_.AdvisorAll })
        HostPools    = @($Results | ForEach-Object { $_.HostPools })
        SessionHosts = @($Results | ForEach-Object { $_.SessionHosts })
        ScalingPlans = @($Results | ForEach-Object { $_.ScalingPlans })
        Commitments  = @($Results | ForEach-Object { $_.Commitments })
        Storage      = @($Results | ForEach-Object { $_.Storage })
    }

    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }

    if ($script:UseExcel) {
        $file = Join-Path $OutputPath "AVD-CostAssessment-$stamp.xlsx"
        foreach ($name in $sheets.Keys) {
            $rows = @($sheets[$name] | Where-Object { $_ })
            if ($rows.Count -gt 0) {
                $rows | Export-Excel -Path $file -WorksheetName $name -TableName "t$name" -TableStyle Medium2 -AutoSize -FreezeTopRow
            }
        }
        Write-Host "`nReport: $file" -ForegroundColor Green
        $script:ReportPath = $file
    }
    else {
        foreach ($name in $sheets.Keys) {
            $rows = @($sheets[$name] | Where-Object { $_ })
            if ($rows.Count -gt 0) {
                $file = Join-Path $OutputPath "AVD-CostAssessment-$stamp-$name.csv"
                $rows | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
            }
        }
        Write-Host "`nCSV reports written to: $OutputPath" -ForegroundColor Green
        $script:ReportPath = $OutputPath
    }
}

# ---------------------------------------------------------------- main

Write-Host "Azure Virtual Desktop (AVD) cost assessment - AVD components only, read-only" -ForegroundColor Cyan
Initialize-Modules
Connect-IfNeeded
$script:Commit = Get-CommitmentContext

$script:AllSubs = Get-AccessibleSubscriptions
if ($script:AllSubs.Count -eq 0) { throw "No enabled subscriptions are accessible with this account." }

$script:results = @()
$script:reviewed = @{}
$script:ReportPath = $null

function Invoke-OneSubscription {
    param([string]$Text)
    $sub = Resolve-Subscription $Text
    if (-not $sub) {
        Write-Host "  '$Text' was not recognised. Enter a number, ID or name from the list (or ? to show it again)." -ForegroundColor Red
        return
    }
    if ($script:reviewed.ContainsKey($sub.Id)) {
        Write-Host "  '$($sub.Name)' was already reviewed in this run." -ForegroundColor Yellow
        return
    }
    $script:reviewed[$sub.Id] = $true
    try {
        $r = Invoke-AvdAssessment -Subscription $sub
        $script:results += $r
        Show-SubscriptionResult -Result $r
    }
    catch {
        Write-Host "  Assessment failed for '$($sub.Name)': $($_.Exception.Message)" -ForegroundColor Red
    }
}

if ($All) {
    foreach ($s in $script:AllSubs) { Invoke-OneSubscription -Text $s.Id }
}
else {
    foreach ($s in @($SubscriptionIds | Where-Object { $_ })) { Invoke-OneSubscription -Text $s }
    if ($script:results.Count -eq 0 -and -not $SubscriptionIds) { Show-SubscriptionList -Subs $script:AllSubs }
    if (-not $SubscriptionIds) {
        while ($true) {
            $prompt = if ($script:results.Count -eq 0) { "`nSubscription to review - number, ID or name ('?' = list, blank = finish)" } else { "`nNext subscription to review ('?' = list, blank = finish and build report)" }
            $in = Read-Host $prompt
            if ([string]::IsNullOrWhiteSpace($in)) { break }
            if ($in.Trim() -eq '?') { Show-SubscriptionList -Subs $script:AllSubs; continue }
            foreach ($piece in ($in -split ',')) { if ($piece.Trim()) { Invoke-OneSubscription -Text $piece } }
        }
    }
}

if ($script:results.Count -gt 0) {
    Export-Report -Results $script:results
    $allFindings = @($script:results | ForEach-Object { $_.Findings })
    $sav = ($allFindings | Where-Object { $_.EstAnnualSavings } | Measure-Object EstAnnualSavings -Sum).Sum
    Write-Host ("`nDone: {0} subscription(s), {1} finding(s) ({2} high)." -f $script:results.Count, $allFindings.Count, @($allFindings | Where-Object Severity -eq 'High').Count) -ForegroundColor Green
    if ($sav) { Write-Host ("Azure Advisor estimated annual savings in AVD scope: {0:N0}" -f $sav) -ForegroundColor Green }
    Write-Host "Start with the 'Findings' sheet, sorted High to Low. Validate each item before changing anything." -ForegroundColor Gray
    if (-not $NoOpen -and $script:ReportPath -and -not (($env:ACC_ENV -eq 'AzureCloudShell') -or ($env:CLOUD_SHELL -eq 'true'))) {
        try { Invoke-Item $script:ReportPath } catch { }
    }
}
else {
    Write-Host "No subscriptions were reviewed." -ForegroundColor Yellow
}









