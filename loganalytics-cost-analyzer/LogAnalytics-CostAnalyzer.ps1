<#
.SYNOPSIS
  Interactive Log Analytics cost-optimisation analyser.
.DESCRIPTION
  Signs in to Azure, lets you pick a subscription, then analyses every Log Analytics
  workspace in it: billable ingestion by table, daily trend, top resources, retention,
  table plans, daily cap, commitment-tier fit - and prints prioritised recommendations.
  Read-only: nothing in Azure is modified. Results are also exported to CSV.
.PARAMETER Days
  Look-back window in days (default 30).
.PARAMETER PricePerGB
  Pay-as-you-go ingestion price per GB used for estimates (default 2.76 USD; check your region/currency).
.PARAMETER OutputFolder
  Where CSV reports are written (default .\LA-CostReport-<timestamp>).
.NOTES
  Requires: PowerShell 5.1+/7+, Az.Accounts module (Install-Module Az.Accounts).
  Needs Reader on the subscription and Log Analytics Reader on the workspaces.
  Prices are approximate list prices and for guidance only.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 90)][int]$Days = 30,
    [double]$PricePerGB = 2.76,
    [string]$OutputFolder = (Join-Path $PWD ("LA-CostReport-{0:yyyyMMdd-HHmmss}" -f (Get-Date)))
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Approximate commitment tier daily prices (USD) - used only for comparison.
$CommitmentTiers = @(
    @{ GB = 100;  Price = 196 }, @{ GB = 200;  Price = 368 }, @{ GB = 300;  Price = 540 },
    @{ GB = 400;  Price = 704 }, @{ GB = 500;  Price = 865 }, @{ GB = 1000; Price = 1700 },
    @{ GB = 2000; Price = 3320 }, @{ GB = 5000; Price = 8050 }
)
# Tables that are typically verbose and good candidates for Basic/Auxiliary plan or filtering.
$BasicCandidates = 'ContainerLog', 'ContainerLogV2', 'AppTraces', 'AppDependencies', 'AzureDiagnostics',
    'StorageBlobLogs', 'AzureNetworkAnalytics_CL', 'AZFWNetworkRule', 'AZFWApplicationRule', 'AZFWDnsQuery',
    'AppServiceHTTPLogs', 'AGWAccessLogs', 'AzureMetrics', 'Syslog', 'W3CIISLog', 'Perf', 'VMConnection',
    'InsightsMetrics', 'NTAIpDetails', 'NTANetAnalytics'

function Write-Header($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

function Get-PlainToken($resource) {
    $tok = (Get-AzAccessToken -ResourceUrl $resource).Token
    if ($tok -is [securestring]) {
        $tok = [System.Net.NetworkCredential]::new('', $tok).Password
    }
    $tok
}

function Invoke-Arm($path) {
    $r = Invoke-AzRestMethod -Path $path -Method GET
    if ($r.StatusCode -ge 300) { throw "ARM call failed ($($r.StatusCode)): $($r.Content)" }
    $r.Content | ConvertFrom-Json
}

function Invoke-LAQuery($customerId, $query, $token) {
    $body = @{ query = $query; timespan = "P$($Days)D" } | ConvertTo-Json
    $res = Invoke-RestMethod -Method Post -Uri "https://api.loganalytics.io/v1/workspaces/$customerId/query" `
        -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $body
    $t = $res.tables[0]
    foreach ($row in $t.rows) {
        $o = [ordered]@{}
        for ($i = 0; $i -lt $t.columns.Count; $i++) { $o[$t.columns[$i].name] = $row[$i] }
        [pscustomobject]$o
    }
}

# ---------- 1. Login ----------
Write-Header 'Azure sign-in'
if (-not (Get-Module -ListAvailable Az.Accounts)) {
    throw 'Az.Accounts module not found. Run: Install-Module Az.Accounts -Scope CurrentUser'
}
Import-Module Az.Accounts -ErrorAction Stop
if (-not (Get-AzContext)) {
    Connect-AzAccount | Out-Null
}
else {
    $ctx = Get-AzContext
    Write-Host "Signed in as $($ctx.Account.Id)"
    if ((Read-Host 'Use this account? (Y/n)') -match '^n') { Connect-AzAccount -Force | Out-Null }
}

# ---------- 2. Pick subscription ----------
Write-Header 'Select subscription'
$subs = @(Get-AzSubscription | Where-Object State -eq 'Enabled' | Sort-Object Name)
if (-not $subs) { throw 'No enabled subscriptions found for this account.' }
for ($i = 0; $i -lt $subs.Count; $i++) { '{0,3}. {1}  ({2})' -f ($i + 1), $subs[$i].Name, $subs[$i].Id }
$selectedSubs = $null
do {
    $ans = (Read-Host "Enter number(s) e.g. 2 or 1,3,5 - or A for all (1-$($subs.Count))").Trim()
    if ($ans -match '^[aA]$') { $selectedSubs = $subs }
    elseif ($ans -match '^\d+(\s*,\s*\d+)*$') {
        $idx = $ans -split '\s*,\s*' | ForEach-Object { [int]$_ } | Select-Object -Unique
        if (-not ($idx | Where-Object { $_ -lt 1 -or $_ -gt $subs.Count })) { $selectedSubs = @($idx | ForEach-Object { $subs[$_ - 1] }) }
    }
} until ($selectedSubs)
Write-Host ("Analysing {0} subscription(s). All costs are in USD." -f @($selectedSubs).Count) -ForegroundColor Green

New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$summary = New-Object System.Collections.Generic.List[object]
$allTables = New-Object System.Collections.Generic.List[object]
$allRecs = New-Object System.Collections.Generic.List[object]

foreach ($sub in $selectedSubs) {
Write-Header "Subscription: $($sub.Name)"
Set-AzContext -SubscriptionId $sub.Id -TenantId $sub.TenantId | Out-Null

# ---------- 3. Discover workspaces ----------
$workspaces = @((Invoke-Arm "/subscriptions/$($sub.Id)/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01").value)
if (-not $workspaces) { Write-Host 'No Log Analytics workspaces in this subscription.'; continue }
Write-Host "Found $($workspaces.Count) workspace(s)."
$laToken = Get-PlainToken 'https://api.loganalytics.io'

foreach ($ws in $workspaces) {
    $rg = ($ws.id -split '/')[4]
    $p = $ws.properties
    Write-Header "Workspace: $($ws.name)  [RG: $rg, $($ws.location)]"
    $recs = New-Object System.Collections.Generic.List[object]
    $add = { param($sev, $msg) $recs.Add([pscustomobject]@{ Subscription = $sub.Name; Workspace = $ws.name; Severity = $sev; Recommendation = $msg }) }

    $cap = $p.workspaceCapping.dailyQuotaGb
    $capText = if ($null -eq $cap -or $cap -lt 0) { 'None' } else { "$cap GB/day" }
    $skuName = $p.sku.name
    $commit = $p.sku.capacityReservationLevel
    Write-Host ("SKU: {0}{1} | Default retention: {2}d | Daily cap: {3}" -f $skuName, $(if ($commit) { " ($commit GB/day commitment)" }), $p.retentionInDays, $capText)

    try {
        # Ingestion by table
        $byTable = @(Invoke-LAQuery $p.customerId @"
Usage | where TimeGenerated > ago($($Days)d) | where IsBillable == true
| summarize IngestedGB = round(sum(Quantity)/1000.0, 3) by DataType
| extend PctOfTotal = round(100.0 * IngestedGB / toscalar(Usage | where TimeGenerated > ago($($Days)d) | where IsBillable == true | summarize sum(Quantity)/1000.0), 1)
| order by IngestedGB desc
"@ $laToken)

        $totalGB = [math]::Round((($byTable | Measure-Object IngestedGB -Sum).Sum), 2)
        $avgDay = [math]::Round($totalGB / $Days, 2)
        $payg = [math]::Round($totalGB * $PricePerGB, 2)
        Write-Host ("Billable ingestion: {0} GB over {1}d (avg {2} GB/day) ~ est. {3:N2} USD at PAYG" -f $totalGB, $Days, $avgDay, $payg) -ForegroundColor Yellow

        if ($byTable) {
            Write-Host "`nTop tables by billable ingestion:"
            $byTable | Select-Object -First 10 | Format-Table DataType, IngestedGB, PctOfTotal -AutoSize | Out-String | Write-Host
        }

        # Daily trend (peak vs average)
        $daily = @(Invoke-LAQuery $p.customerId @"
Usage | where TimeGenerated > ago($($Days)d) | where IsBillable == true
| summarize GB = round(sum(Quantity)/1000.0, 2) by Day = bin(TimeGenerated, 1d) | order by Day asc
"@ $laToken)
        $peak = $daily | Sort-Object GB -Descending | Select-Object -First 1
        if ($peak) { Write-Host ("Peak day: {0:yyyy-MM-dd} = {1} GB (avg {2} GB)" -f [datetime]$peak.Day, $peak.GB, $avgDay) }

        # Top resources (last 7 days to limit query cost)
        $topRes = @(Invoke-LAQuery $p.customerId @"
union withsource=T *
| where TimeGenerated > ago(7d) | where _IsBillable == true
| summarize GB = round(sum(_BilledSize)/1000000000.0, 3) by Resource = tolower(_ResourceId), T
| where isnotempty(Resource)
| top 10 by GB desc
"@ $laToken)
        if ($topRes) {
            Write-Host "Top 10 resources by billable ingestion (last 7d):"
            $topRes | Format-Table GB, T, Resource -AutoSize | Out-String | Write-Host
        }

        # Table settings (retention / plan)
        $tblSettings = @{}
        try {
            foreach ($t in (Invoke-Arm "$($ws.id)/tables?api-version=2022-10-01").value) { $tblSettings[$t.name] = $t.properties }
        } catch { Write-Warning "Could not read table settings: $($_.Exception.Message)" }

        foreach ($r in $byTable) {
            $ts = $tblSettings[$r.DataType]
            $row = [pscustomobject]@{
                Subscription = $sub.Name; Workspace = $ws.name; Table = $r.DataType; IngestedGB = $r.IngestedGB; PctOfTotal = $r.PctOfTotal
                EstCostUSD = [math]::Round($r.IngestedGB * $PricePerGB, 2)
                Plan = $ts.plan; RetentionDays = $ts.retentionInDays; TotalRetentionDays = $ts.totalRetentionInDays
            }
            $allTables.Add($row)
        }

        # ---------- Recommendations ----------
        if ($totalGB -eq 0) {
            & $add 'Medium' "No billable ingestion in $Days days - workspace looks idle. Consider deleting it (check linked solutions first)."
        }
        else {
            # Commitment tier
            if (-not $commit) {
                $paygDaily = $avgDay * $PricePerGB
                $best = $CommitmentTiers | Where-Object { $_.GB -le $avgDay } | Select-Object -Last 1
                if ($best) {
                    $over = [math]::Max(0, $avgDay - $best.GB)
                    $tierDaily = $best.Price + $over * ($best.Price / $best.GB)
                    if ($tierDaily -lt $paygDaily) {
                        $save = [math]::Round(($paygDaily - $tierDaily) * 30, 0)
                        & $add 'High' ("Avg {0} GB/day fits the {1} GB/day commitment tier: est. saving ~{2} USD/month vs pay-as-you-go." -f $avgDay, $best.GB, $save)
                    }
                }
                elseif ($avgDay -ge 85) {
                    & $add 'Low' "Avg $avgDay GB/day is close to the 100 GB/day commitment tier - re-check as volume grows."
                }
            }
            elseif ($avgDay -lt $commit * 0.7) {
                & $add 'Medium' "Commitment tier is $commit GB/day but avg ingestion is only $avgDay GB/day - you pay for unused capacity; consider a lower tier."
            }

            # Concentration
            $top = $byTable | Select-Object -First 1
            if ($top.PctOfTotal -ge 50) {
                & $add 'High' "$($top.DataType) is $($top.PctOfTotal)% of ingestion ($($top.IngestedGB) GB). Review sources, filter with DCR transformations, or lower verbosity."
            }

            # Per-table checks
            foreach ($r in ($byTable | Where-Object { $_.PctOfTotal -ge 5 })) {
                $ts = $tblSettings[$r.DataType]
                $isCandidate = $BasicCandidates -contains $r.DataType -or $r.DataType -like '*_CL'
                if ($isCandidate -and $ts.plan -eq 'Analytics') {
                    & $add 'High' "$($r.DataType) ($($r.IngestedGB) GB, $($r.PctOfTotal)%) is on the Analytics plan. If rarely queried, move to Basic/Auxiliary plan (where supported) or use a DCR transformation to drop noise."
                }
                if ($ts -and $ts.retentionInDays -gt 90 -and $ts.plan -eq 'Analytics') {
                    & $add 'Medium' "$($r.DataType) keeps $($ts.retentionInDays) days interactive retention; use 90 days (free tier of retention) + long-term archive instead."
                }
            }
            if ($byTable.DataType -contains 'AzureDiagnostics') {
                & $add 'Medium' 'AzureDiagnostics in use: switch diagnostic settings to resource-specific tables (cheaper to query, allows per-table plans/retention).'
            }
            if ($byTable.DataType -contains 'AzureMetrics') {
                & $add 'Low' 'AzureMetrics is ingested as logs - metrics are free in Azure Monitor Metrics; remove the AllMetrics category from diagnostic settings unless needed.'
            }
            if (($byTable | Where-Object DataType -in 'SecurityEvent', 'WindowsEvent')) {
                & $add 'Low' 'Windows security events present: consider Common/Minimal event sets or XPath filtering via DCR to cut volume.'
            }

            # Spikes
            if ($peak -and $avgDay -gt 0 -and $peak.GB -gt 3 * $avgDay) {
                & $add 'Medium' ("Peak day ({0:yyyy-MM-dd}, {1} GB) is >3x average - investigate a runaway source or misconfigured logging." -f [datetime]$peak.Day, $peak.GB)
            }

            # Daily cap
            if ($capText -eq 'None') {
                & $add 'Low' 'No daily cap set. Consider a cap on non-production workspaces to prevent surprise bills (note: data is dropped once the cap is hit).'
            }
        }

        # Workspace-level retention
        if ($p.retentionInDays -gt 90) {
            & $add 'Medium' "Workspace default retention is $($p.retentionInDays) days (first 90 days are free). Reduce, or use table-level archive for older data."
        }

        $summary.Add([pscustomobject]@{
                Subscription = $sub.Name; Workspace = $ws.name; ResourceGroup = $rg; Location = $ws.location; Sku = $skuName
                CommitmentGBPerDay = $commit; RetentionDays = $p.retentionInDays; DailyCap = $capText
                BillableGB = $totalGB; AvgGBPerDay = $avgDay; PeakGB = $peak.GB; EstPaygCostUSD = $payg
                TopTable = $byTable[0].DataType
            })
    }
    catch {
        Write-Warning "Analysis failed for $($ws.name): $($_.Exception.Message)"
        & $add 'Info' "Analysis failed (check Log Analytics Reader permission / network access): $($_.Exception.Message)"
    }

    if ($recs.Count) {
        Write-Host "Recommendations:" -ForegroundColor Magenta
        $order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
        foreach ($r in ($recs | Sort-Object { $order[$_.Severity] })) {
            $c = switch ($r.Severity) { 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'Gray' } }
            Write-Host ("  [{0}] {1}" -f $r.Severity, $r.Recommendation) -ForegroundColor $c
        }
        $recs | ForEach-Object { $allRecs.Add($_) }
    }
}

}

# ---------- 4. Overall summary and export ----------
Write-Header 'Overall summary (USD)'
$summary | Sort-Object BillableGB -Descending |
    Format-Table Subscription, Workspace, Sku, CommitmentGBPerDay, RetentionDays, BillableGB, AvgGBPerDay, EstPaygCostUSD, TopTable -AutoSize

$summary   | Export-Csv (Join-Path $OutputFolder 'workspaces.csv') -NoTypeInformation
$allTables | Export-Csv (Join-Path $OutputFolder 'tables.csv') -NoTypeInformation
$allRecs   | Export-Csv (Join-Path $OutputFolder 'recommendations.csv') -NoTypeInformation

# ---------- 5. HTML report ----------
$totalCost = [math]::Round((($summary | Measure-Object EstPaygCostUSD -Sum).Sum), 2)
$totalGB = [math]::Round((($summary | Measure-Object BillableGB -Sum).Sum), 2)
$highCount = @($allRecs | Where-Object Severity -eq 'High').Count
$sevOrder = @{ High = 0; Medium = 1; Low = 2; Info = 3 }

function ConvertTo-Frag($data, $props) {
    $h = @($data) | Select-Object $props | ConvertTo-Html -Fragment | Out-String
    $h = $h -replace '<td>High</td>', '<td class="sev-high">High</td>' -replace '<td>Medium</td>', '<td class="sev-med">Medium</td>' `
        -replace '<td>Low</td>', '<td class="sev-low">Low</td>'
    $h
}

$sections = New-Object System.Text.StringBuilder
$sections.AppendLine('<h2>Workspaces</h2>') | Out-Null
$sections.AppendLine((ConvertTo-Frag ($summary | Sort-Object BillableGB -Descending) 'Subscription', 'Workspace', 'Sku', 'CommitmentGBPerDay', 'RetentionDays', 'DailyCap', 'BillableGB', 'AvgGBPerDay', 'PeakGB', 'EstPaygCostUSD', 'TopTable')) | Out-Null
$sections.AppendLine('<h2>Recommendations</h2>') | Out-Null
if ($allRecs.Count) {
    $sections.AppendLine((ConvertTo-Frag ($allRecs | Sort-Object { $sevOrder[$_.Severity] }, Subscription, Workspace) 'Severity', 'Subscription', 'Workspace', 'Recommendation')) | Out-Null
}
else { $sections.AppendLine('<p>No recommendations.</p>') | Out-Null }
$sections.AppendLine('<h2>Top tables by ingestion (per workspace)</h2>') | Out-Null
foreach ($g in ($allTables | Group-Object Subscription, Workspace)) {
    $first = $g.Group[0]
    $sections.AppendLine("<h3>$([System.Net.WebUtility]::HtmlEncode($first.Workspace)) <small>($([System.Net.WebUtility]::HtmlEncode($first.Subscription)))</small></h3>") | Out-Null
    $sections.AppendLine((ConvertTo-Frag ($g.Group | Select-Object -First 15) 'Table', 'IngestedGB', 'PctOfTotal', 'EstCostUSD', 'Plan', 'RetentionDays', 'TotalRetentionDays')) | Out-Null
}

$html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Log Analytics Cost Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}
h1{margin-bottom:4px} h2{border-bottom:2px solid #0078d4;padding-bottom:4px;margin-top:32px} h3{margin-bottom:4px}
small{color:#666;font-weight:normal}
.kpis{display:flex;gap:16px;margin:16px 0}
.kpi{background:#f3f6fa;border-left:4px solid #0078d4;padding:10px 16px;min-width:140px}
.kpi b{display:block;font-size:22px}
table{border-collapse:collapse;width:100%;font-size:13px;margin-bottom:12px}
th{background:#0078d4;color:#fff;text-align:left;padding:6px 8px} td{padding:5px 8px;border-bottom:1px solid #e1e1e1}
tr:nth-child(even) td{background:#fafafa}
.sev-high{color:#fff;background:#d13438!important;font-weight:600} .sev-med{background:#ffd966!important;font-weight:600} .sev-low{background:#e1e1e1!important}
</style></head><body>
<h1>Log Analytics Cost Optimisation Report</h1>
<div>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') | Window: last $Days days | Currency: USD | PAYG price used: $PricePerGB USD/GB</div>
<div class="kpis">
<div class="kpi"><b>$(@($selectedSubs).Count)</b>subscriptions</div>
<div class="kpi"><b>$($summary.Count)</b>workspaces</div>
<div class="kpi"><b>$totalGB GB</b>billable ingestion</div>
<div class="kpi"><b>$('{0:N2}' -f $totalCost) USD</b>est. PAYG cost</div>
<div class="kpi"><b>$highCount</b>high-priority findings</div>
</div>
$($sections.ToString())
<p><small>Estimates use approximate list prices and are indicative only. Validate in Azure Cost Management before acting.</small></p>
</body></html>
"@
$htmlPath = Join-Path $OutputFolder 'report.html'
$html | Set-Content -Path $htmlPath -Encoding UTF8
Write-Host "Reports saved to: $OutputFolder" -ForegroundColor Green
Write-Host "HTML report: $htmlPath" -ForegroundColor Green
if ($env:OS -eq 'Windows_NT') { Start-Process $htmlPath }
