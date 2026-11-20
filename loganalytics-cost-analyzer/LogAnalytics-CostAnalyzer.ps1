<#
.SYNOPSIS
  Log Analytics Cost Intelligence - interactive, read-only Azure Monitor cost optimisation analyser.
.DESCRIPTION
  Signs in to Azure, lets you pick subscriptions, then analyses every Log Analytics workspace:
  ingestion by table / resource, trend and spikes, pricing-tier fit (PAYG vs commitment tiers using
  your real daily volumes), Basic/Auxiliary plan eligibility (live from Microsoft's table matrix),
  collection-tuning tips per table, retention/archive economics, legacy SKUs and governance gaps.
  Every finding carries an estimated monthly saving (USD) and a ready-to-run remediation command.
  Nothing in Azure is modified. Output: console dashboard + HTML report + CSV + JSON.
.PARAMETER Days
  Look-back window (7, 14, 30, 60, 90). Prompted if omitted.
.PARAMETER PricePerGB
  Customer's pay-as-you-go Analytics ingestion price per GB in USD (default 2.76). Prompted if omitted.
.PARAMETER MinMonthlyCostUSD
  Workspaces/tables below this monthly cost are not flagged (default 10).
.PARAMETER SubscriptionId
  One or more subscription IDs/names - skips the interactive picker.
.PARAMETER AllSubscriptions
  Analyse every enabled subscription without prompting.
.PARAMETER SkipResourceBreakdown
  Skip the per-resource ingestion query (faster on very large workspaces).
.PARAMETER OutputFolder
  Report folder (default .\LA-CostReport-<timestamp>).
.PARAMETER NoOpen
  Do not open the HTML report when finished.
.NOTES
  Requires Az.Accounts (Install-Module Az.Accounts). Needs Reader on the subscription and
  Log Analytics Reader on the workspaces. Prices are approximate list prices scaled to -PricePerGB.
#>
[CmdletBinding()]
param(
    [ValidateSet(0, 7, 14, 30, 60, 90)][int]$Days = 0,
    [double]$PricePerGB = 0,
    [double]$MinMonthlyCostUSD = 10,
    [string[]]$SubscriptionId,
    [switch]$AllSubscriptions,
    [switch]$SkipResourceBreakdown,
    [string]$OutputFolder = (Join-Path $PWD ("LA-CostReport-{0:yyyyMMdd-HHmmss}" -f (Get-Date))),
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$script:Version = '2.0'
$script:StepErrors = New-Object System.Collections.Generic.List[string]
$script:UiWidth = 98
try { $script:UiWidth = [math]::Max(80, [math]::Min(110, [Console]::WindowWidth - 2)) } catch {}

# ---------- Pricing model (approximate list prices; scaled to the customer's PAYG rate) ----------
$ListPaygPerGB = 2.30
$CommitmentTiers = @(@{ L = 100; D = 0.15 }, @{ L = 200; D = 0.20 }, @{ L = 300; D = 0.22 }, @{ L = 400; D = 0.23 }, @{ L = 500; D = 0.25 }, @{ L = 1000; D = 0.26 }, @{ L = 2000; D = 0.28 }, @{ L = 5000; D = 0.30 })
$BasicListPerGB = 0.50; $AuxListPerGB = 0.05; $RetentionListPerGBMonth = 0.10; $ArchiveListPerGBMonth = 0.02

# Per-table collection-tuning playbook: regex, tip, typical reduction achievable
$TablePlaybook = @(
    @{ M = '^Perf$'; Pct = 0.5; Tip = 'Raise counter sample interval (e.g. 60s to 300s) and drop unused counters in the DCR.' }
    @{ M = '^InsightsMetrics$'; Pct = 0.4; Tip = 'Disable unused VM Insights / Prometheus namespaces and lengthen the collection interval.' }
    @{ M = '^Syslog$'; Pct = 0.4; Tip = 'Collect only needed facilities and raise the minimum severity (drop debug/info) in the DCR.' }
    @{ M = '^(SecurityEvent|WindowsEvent)$'; Pct = 0.4; Tip = 'Use the Common/Minimal event set or XPath filters; drop noisy event IDs via a DCR transformation.' }
    @{ M = '^Event$'; Pct = 0.5; Tip = 'Collect only Error/Warning levels via XPath in the DCR; drop Information events.' }
    @{ M = '^AzureDiagnostics$'; Pct = 0.3; Tip = 'Switch diagnostic settings to resource-specific tables, then drop verbose categories you never query.' }
    @{ M = '^AzureMetrics$'; Pct = 0.9; Tip = 'Remove "AllMetrics" from diagnostic settings - platform metrics are free in Azure Monitor Metrics.' }
    @{ M = '^ContainerLog(V2)?$'; Pct = 0.4; Tip = 'Exclude system namespaces, turn off stdout/stderr where unused, and use the ContainerLogV2 Basic plan.' }
    @{ M = '^(ContainerInventory|KubePodInventory|KubeEvents|KubeNodeInventory|KubeServices)$'; Pct = 0.4; Tip = 'Apply the Container Insights cost-optimisation preset (5-min interval, namespace filters).' }
    @{ M = '^AppTraces$'; Pct = 0.4; Tip = 'Raise minimum log level (Information to Warning) and enable SDK sampling.' }
    @{ M = '^App(Dependencies|Requests|PerformanceCounters|Metrics|Events|PageViews)$'; Pct = 0.3; Tip = 'Enable adaptive/fixed-rate sampling and disable tracking of chatty dependencies.' }
    @{ M = '^StorageBlobLogs$|^Storage(File|Queue|Table)Logs$'; Pct = 0.4; Tip = 'Log only write/delete operations (skip reads) in the storage diagnostic setting; consider Basic plan.' }
    @{ M = '^(AZFW|AzureFirewall)'; Pct = 0.3; Tip = 'Use resource-specific firewall tables, then Basic plan for network/application rule logs.' }
    @{ M = '^(AGW|AppGW|FrontDoor|AzureFrontDoor)'; Pct = 0.3; Tip = 'Use resource-specific tables and log only access logs you actually analyse; Basic plan for access logs.' }
    @{ M = '^W3CIISLog$'; Pct = 0.4; Tip = 'Filter static assets and health-probe requests with a DCR transformation.' }
    @{ M = '^(VMConnection|VMProcess|VMBoundPort|ServiceMap.*)$'; Pct = 0.5; Tip = 'Disable the VM Insights Map/dependency data collection if it is not used.' }
    @{ M = '^Heartbeat$'; Pct = 0.3; Tip = 'Check for duplicate agents (legacy MMA plus AMA) reporting the same machines.' }
    @{ M = '^(AzureNetworkAnalytics_CL|NTANetAnalytics|NTAIpDetails|NTATopologyDetails)$'; Pct = 0.5; Tip = 'Traffic Analytics: use 60-minute processing interval and limit to critical NSGs/VNets.' }
    @{ M = '^ContainerApp(Console|System)Logs'; Pct = 0.4; Tip = 'Reduce application log verbosity; send console logs to a Basic-plan table.' }
    @{ M = '^(AADNonInteractiveUserSignInLogs|AADServicePrincipalSignInLogs|AADManagedIdentitySignInLogs)$'; Pct = 0.0; Tip = 'High-volume sign-in logs: use Basic/Auxiliary plan if only used for investigation/compliance.' }
)
$LegacySkus = 'PerNode', 'Standalone', 'Premium', 'Standard'
$AiFreeRetentionTables = '^App(Requests|Dependencies|Traces|Exceptions|Metrics|Events|PageViews|PerformanceCounters|BrowserTimings|AvailabilityResults|SystemEvents)$'

# ---------- UI helpers ----------
function Write-Line([string]$Text = '', [string]$Fg = 'Gray') { Write-Host $Text -ForegroundColor $Fg }
function Write-Rule([string]$Title = '', [string]$Fg = 'DarkCyan') {
    $w = $script:UiWidth
    if ($Title) { $t = " $Title "; Write-Host (('─' * 3) + $t + ('─' * [math]::Max(3, $w - $t.Length - 3))) -ForegroundColor $Fg }
    else { Write-Host ('─' * $w) -ForegroundColor $Fg }
}
function Write-Box([string]$Title, [string[]]$Lines, [string]$Fg = 'Cyan') {
    $w = $script:UiWidth - 2
    Write-Host ('╭─ ' + $Title + ' ' + ('─' * [math]::Max(1, $w - $Title.Length - 4)) + '╮') -ForegroundColor $Fg
    foreach ($l in $Lines) { $t = $l; if ($t.Length -gt $w - 2) { $t = $t.Substring(0, $w - 2) }; Write-Host ('│ ' + $t.PadRight($w - 2) + ' │') -ForegroundColor $Fg }
    Write-Host ('╰' + ('─' * $w) + '╯') -ForegroundColor $Fg
}
function New-Bar([double]$Pct, [int]$Width = 22) {
    $f = [int][math]::Round([math]::Max(0, [math]::Min(100, $Pct)) / 100 * $Width)
    ('█' * $f) + ('░' * ($Width - $f))
}
function New-Spark([double[]]$Values, [int]$Max = 56) {
    if (-not $Values -or $Values.Count -eq 0) { return '' }
    $v = @($Values)
    if ($v.Count -gt $Max) {
        $size = [math]::Ceiling($v.Count / $Max); $b = @()
        for ($i = 0; $i -lt $v.Count; $i += $size) { $b += ($v[$i..([math]::Min($i + $size - 1, $v.Count - 1))] | Measure-Object -Sum).Sum }
        $v = $b
    }
    $chars = [char[]]'▁▂▃▄▅▆▇█'
    $m = ($v | Measure-Object -Maximum).Maximum
    if ($m -le 0) { return ('▁' * $v.Count) }
    -join ($v | ForEach-Object { $chars[[math]::Min(7, [int][math]::Floor($_ / $m * 7.999))] })
}
function Format-Usd([double]$v) { if ($v -ge 100) { '${0:N0}' -f $v } else { '${0:N2}' -f $v } }
function Get-SevColor([string]$s) { switch ($s) { 'High' { 'Red' } 'Medium' { 'Yellow' } 'Low' { 'Cyan' } default { 'DarkGray' } } }

function Show-Banner {
    $inner = 74
    $rows = @(
        '  LOG ANALYTICS  COST INTELLIGENCE',
        '  Find waste  |  Right-size pricing  |  Cut your Azure Monitor bill',
        ('  Professional edition  v' + $script:Version)
    )
    Write-Host
    Write-Host ('  ╔' + ('═' * $inner) + '╗') -ForegroundColor Cyan
    $colors = 'White', 'Cyan', 'DarkCyan'
    for ($i = 0; $i -lt $rows.Count; $i++) {
        Write-Host '  ║' -ForegroundColor Cyan -NoNewline
        Write-Host $rows[$i].PadRight($inner) -ForegroundColor $colors[$i] -NoNewline
        Write-Host '║' -ForegroundColor Cyan
        Start-Sleep -Milliseconds 60
    }
    Write-Host ('  ╚' + ('═' * $inner) + '╝') -ForegroundColor Cyan
    Write-Host '  Read-only analysis - nothing in your Azure environment is changed' -ForegroundColor DarkGray
    Write-Host
}

function Invoke-Step([string]$Label, [scriptblock]$Block) {
    Write-Host ('  ▸ {0,-48}' -f $Label) -NoNewline -ForegroundColor Gray
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = & $Block
        Write-Host ('✔ {0:N1}s' -f $sw.Elapsed.TotalSeconds) -ForegroundColor Green
        if ($null -ne $r) { $r }
    }
    catch {
        Write-Host '✖ skipped' -ForegroundColor Yellow
        $script:StepErrors.Add("$Label - $($_.Exception.Message)")
    }
}

function Write-ProgressBar([int]$Done, [int]$Total, [string]$Label) {
    $pct = if ($Total) { 100.0 * $Done / $Total } else { 100 }
    Write-Host ('  [{0}] {1}/{2}  {3}' -f (New-Bar $pct 30), $Done, $Total, $Label) -ForegroundColor DarkCyan
}

# Arrow-key picker: filter-as-you-type, Space toggles (multi), Enter confirms, Esc cancels.
function Select-Interactive {
    param([object[]]$Items, [scriptblock]$Label = { "$_" }, [string]$Title = 'Select', [switch]$Multi, [int]$PageSize = 14, [int]$StartIndex = 0)
    if ([Console]::IsInputRedirected) {
        for ($i = 0; $i -lt $Items.Count; $i++) { '{0,3}. {1}' -f ($i + 1), ($Items[$i] | ForEach-Object { & $Label }) }
        $a = Read-Host "$Title - number(s), comma separated"
        return @($a -split '[,\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { $Items[[int]$_ - 1] })
    }
    $labels = @($Items | ForEach-Object { [string](& $Label $_) })
    $filter = ''; $view = @(0..($Items.Count - 1)); $cur = [math]::Min($StartIndex, $Items.Count - 1); $off = 0
    $sel = New-Object 'System.Collections.Generic.HashSet[int]'
    $h = $PageSize + 4
    1..$h | ForEach-Object { Write-Host }
    $top = [Console]::CursorTop - $h
    $w = $script:UiWidth
    $oldVis = $true; try { $oldVis = [Console]::CursorVisible; [Console]::CursorVisible = $false } catch {}
    $result = $null
    $put = {
        param($text, $fg, $bg)
        [Console]::SetCursorPosition(0, $top + $script:pickRow)
        $t = if ($text.Length -gt $w) { $text.Substring(0, $w) } else { $text.PadRight($w) }
        if ($bg) { Write-Host $t -ForegroundColor $fg -BackgroundColor $bg -NoNewline } else { Write-Host $t -ForegroundColor $fg -NoNewline }
        $script:pickRow++
    }
    try {
        while ($true) {
            if ($cur -lt $off) { $off = $cur }
            if ($cur -ge $off + $PageSize) { $off = $cur - $PageSize + 1 }
            $script:pickRow = 0
            & $put "  $Title" 'Cyan' $null
            & $put ("  Filter: {0}|" -f $filter) 'White' $null
            $hint = if ($Multi) { 'Up/Down move   Space select   Ctrl+A all   Enter confirm   Esc cancel' } else { 'Up/Down move   Enter choose   Esc cancel' }
            & $put ("  $hint" + $(if ($Multi) { "   [{0} selected]" -f $sel.Count } else { '' })) 'DarkGray' $null
            for ($i = 0; $i -lt $PageSize; $i++) {
                $vi = $off + $i
                if ($vi -lt $view.Count) {
                    $idx = $view[$vi]
                    $mark = if ($Multi) { if ($sel.Contains($idx)) { '◉' } else { '○' } } else { ' ' }
                    $text = ('  {0} {1} {2}' -f $(if ($vi -eq $cur) { '❯' } else { ' ' }), $mark, $labels[$idx])
                    if ($vi -eq $cur) { & $put $text 'Black' 'Cyan' }
                    elseif ($sel.Contains($idx)) { & $put $text 'Green' $null }
                    else { & $put $text 'Gray' $null }
                }
                else { & $put '' 'Gray' $null }
            }
            & $put ("  {0}-{1} of {2}{3}" -f $(if ($view.Count) { $off + 1 } else { 0 }), [math]::Min($off + $PageSize, $view.Count), $view.Count, $(if ($filter) { ' (filtered)' } else { '' })) 'DarkGray' $null
            $k = [Console]::ReadKey($true)
            $isText = $k.KeyChar -and -not [char]::IsControl($k.KeyChar) -and $k.Key -ne 'Spacebar'
            switch ($k.Key) {
                'UpArrow' { if ($cur -gt 0) { $cur-- } }
                'DownArrow' { if ($cur -lt $view.Count - 1) { $cur++ } }
                'PageUp' { $cur = [math]::Max(0, $cur - $PageSize) }
                'PageDown' { $cur = [math]::Min([math]::Max(0, $view.Count - 1), $cur + $PageSize) }
                'Home' { $cur = 0 }
                'End' { $cur = [math]::Max(0, $view.Count - 1) }
                'Spacebar' {
                    if ($Multi -and $view.Count) { $idx = $view[$cur]; if (-not $sel.Remove($idx)) { [void]$sel.Add($idx) }; if ($cur -lt $view.Count - 1) { $cur++ } }
                    else { $filter += ' '; $refilter = $true }
                }
                'Enter' {
                    if ($view.Count -gt 0) {
                        if ($Multi) { if ($sel.Count -eq 0) { [void]$sel.Add($view[$cur]) }; $result = @($sel | Sort-Object | ForEach-Object { $Items[$_] }) }
                        else { $result = @($Items[$view[$cur]]) }
                    }
                }
                'Escape' { if ($filter) { $filter = ''; $refilter = $true } else { $result = @() } }
                'Backspace' { if ($filter.Length) { $filter = $filter.Substring(0, $filter.Length - 1); $refilter = $true } }
                default {
                    if ($Multi -and $k.Key -eq 'A' -and ($k.Modifiers -band [ConsoleModifiers]::Control)) { foreach ($i in $view) { [void]$sel.Add($i) } }
                    elseif ($isText) { $filter += $k.KeyChar; $refilter = $true }
                }
            }
            if ($null -ne $result) { break }
            if ($refilter) {
                $refilter = $false
                $view = @(0..($Items.Count - 1) | Where-Object { -not $filter -or $labels[$_] -like "*$filter*" })
                $cur = 0; $off = 0
            }
        }
    }
    finally {
        for ($i = 0; $i -lt $h; $i++) { [Console]::SetCursorPosition(0, $top + $i); Write-Host (' ' * $w) -NoNewline }
        [Console]::SetCursorPosition(0, $top)
        try { [Console]::CursorVisible = $oldVis } catch {}
    }
    $result
}

function Get-PlainToken($resource) {
    $tok = (Get-AzAccessToken -ResourceUrl $resource).Token
    if ($tok -is [securestring]) { $tok = [System.Net.NetworkCredential]::new('', $tok).Password }
    $tok
}
function Invoke-Arm($path) {
    $r = Invoke-AzRestMethod -Path $path -Method GET
    if ($r.StatusCode -ge 300) { throw "ARM call failed ($($r.StatusCode)): $($r.Content)" }
    $r.Content | ConvertFrom-Json
}
function Invoke-LAQuery($customerId, $query, $token, [int]$Window) {
    $body = @{ query = $query; timespan = "P$($Window)D" } | ConvertTo-Json
    for ($try = 0; $try -lt 3; $try++) {
        try {
            $res = Invoke-RestMethod -Method Post -Uri "https://api.loganalytics.io/v1/workspaces/$customerId/query" -TimeoutSec 180 `
                -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $body
            break
        }
        catch {
            $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch {}
            if ($try -lt 2 -and ($code -eq 429 -or $code -ge 500 -or $code -eq 0)) { Start-Sleep -Seconds (3 * ($try + 1)); continue }
            throw
        }
    }
    $t = $res.tables[0]
    foreach ($row in $t.rows) {
        $o = [ordered]@{}
        for ($i = 0; $i -lt $t.columns.Count; $i++) { $o[$t.columns[$i].name] = $row[$i] }
        [pscustomobject]$o
    }
}
function Get-TableFeatureMatrix {
    $basic = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $aux = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $src = 'live (Microsoft docs)'
    try {
        $u = 'https://raw.githubusercontent.com/MicrosoftDocs/azure-monitor-docs/main/articles/azure-monitor/reference/tables-features.md'
        $md = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 25 -Uri $u).Content
        foreach ($ln in ($md -split "`n")) {
            if ($ln -match '^\[(?<n>[A-Za-z0-9_]+)\]\([^)]*\)\|(?<b>[^|]*)\|(?<a>[^|]*)\|') {
                if ($Matches['b'].Trim()) { [void]$basic.Add($Matches['n']) }
                if ($Matches['a'].Trim()) { [void]$aux.Add($Matches['n']) }
            }
        }
        if ($basic.Count -lt 50) { throw 'matrix parse looked incomplete' }
    }
    catch {
        $src = 'built-in (offline)'
        'ContainerLogV2', 'ContainerLog', 'AppTraces', 'StorageBlobLogs', 'AZFWNetworkRule', 'AZFWApplicationRule', 'AZFWDnsQuery', 'AGWAccessLogs',
        'AppServiceHTTPLogs', 'ContainerAppConsoleLogs', 'ContainerAppSystemLogs', 'AADNonInteractiveUserSignInLogs', 'AADManagedIdentitySignInLogs' | ForEach-Object { [void]$basic.Add($_) }
    }
    @{ Basic = $basic; Aux = $aux; Source = $src }
}
function Get-ShortResource([string]$id) {
    if (-not $id) { return '(no resource id)' }
    $p = $id.Trim('/') -split '/'
    if ($p.Count -ge 8) { return ('{0} ({1}/{2})' -f $p[-1], $p[6].Replace('microsoft.', ''), $p[7]) }
    $id
}


# ---------- Analysis engine ----------
function New-Finding {
    param([string]$Ws, [string]$Sub, [string]$Sev, [string]$Cat, [string]$Title, [string]$Detail, [double]$Saving = 0,
        [string]$Action = '', [string]$Effort = 'Low', [string]$Table = '', [bool]$Count = $true)
    [pscustomobject]@{
        Subscription = $Sub; Workspace = $Ws; Severity = $Sev; Category = $Cat; Table = $Table; Title = $Title; Detail = $Detail
        EstMonthlySavingUSD = [math]::Round($Saving, 2); Effort = $Effort; Action = $Action; CountInTotal = $Count
    }
}
function Get-SeverityBySaving([double]$s, [double]$hi = 100, [double]$med = 25) { if ($s -ge $hi) { 'High' } elseif ($s -ge $med) { 'Medium' } else { 'Low' } }
function Get-TierWindowCost([double[]]$Daily, [int]$Level) {
    $d = 0.15; foreach ($t in $CommitmentTiers) { if ($t.L -eq $Level) { $d = $t.D } }
    $rate = $script:Price * (1 - $d); $sum = 0.0
    foreach ($g in $Daily) { $sum += [math]::Max($Level, $g) * $rate }
    $sum
}

function Invoke-WorkspaceAnalysis {
    param($ws, $sub, [int]$Index, [int]$Total)
    $rg = ($ws.id -split '/')[4]; $p = $ws.properties; $wsKey = "$($ws.name) [$rg]"
    $findings = New-Object System.Collections.Generic.List[object]
    $F = { param([string]$Sev, [string]$Cat, [string]$Title, [string]$Detail, [double]$Saving, [string]$Action, [string]$Effort, [string]$Table, [bool]$Count)
        $findings.Add((New-Finding -Ws $wsKey -Sub $sub.Name -Sev $Sev -Cat $Cat -Title $Title -Detail $Detail -Saving $Saving -Action $Action -Effort $Effort -Table $Table -Count $Count)) }

    Write-Host
    Write-Rule ("[{0}/{1}] {2}  ·  {3}  ·  {4}" -f $Index, $Total, $ws.name, $rg, $ws.location) 'Cyan'
    $token = Get-PlainToken 'https://api.loganalytics.io'
    $win = $Days + 1
    $startExpr = "startofday(now()-$($Days - 1)d)"

    $tblRaw = @(Invoke-Step 'Reading table plans and retention' { (Invoke-Arm "$($ws.id)/tables?api-version=2022-10-01").value })
    $tbl = @{}; foreach ($t in $tblRaw) { if ($t.name) { $tbl[$t.name] = $t.properties } }
    $nonAnalytics = @($tbl.Keys | Where-Object { $tbl[$_].plan -in 'Basic', 'Auxiliary' })
    $nonAClause = if ($nonAnalytics.Count) { "| where DataType !in (" + (($nonAnalytics | ForEach-Object { "'$_'" }) -join ',') + ")" } else { '' }

    $byTable = @(Invoke-Step 'Measuring billable ingestion by table' {
            Invoke-LAQuery $p.customerId "let s = $startExpr; Usage | where TimeGenerated >= s | where IsBillable == true | summarize GB = sum(Quantity)/1000.0 by DataType | order by GB desc" $token $win
        })
    $dailyRows = @(Invoke-Step 'Building daily ingestion trend' {
            Invoke-LAQuery $p.customerId "let s = $startExpr; Usage | where TimeGenerated >= s | where IsBillable == true $nonAClause | summarize GB = sum(Quantity)/1000.0 by Day = format_datetime(startofday(TimeGenerated), 'yyyy-MM-dd')" $token $win
        })
    $topRes = @()
    if (-not $SkipResourceBreakdown) {
        $topRes = @(Invoke-Step 'Ranking top ingesting resources (7d)' {
                Invoke-LAQuery $p.customerId "union withsource=T * | where TimeGenerated > ago(7d) | where _IsBillable == true | extend Res = iff(isnotempty(_ResourceId), tolower(_ResourceId), tostring(column_ifexists('Computer',''))) | summarize GB = sum(_BilledSize)/1000000000.0, Tables = make_set(T, 3) by Res | where isnotempty(Res) | top 8 by GB desc" $token 8
            })
    }

    # ----- daily series (UTC calendar days, zero-filled) -----
    $map = @{}; foreach ($r in $dailyRows) { $map[[string]$r.Day] = [double]$r.GB }
    $dArr = New-Object 'double[]' $Days; $dayLabels = @()
    for ($i = 0; $i -lt $Days; $i++) {
        $d = (Get-Date).ToUniversalTime().Date.AddDays($i - ($Days - 1)).ToString('yyyy-MM-dd'); $dayLabels += $d
        if ($map.ContainsKey($d)) { $dArr[$i] = $map[$d] }
    }

    # ----- totals / plan-aware cost model -----
    $basicPrice = $BasicListPerGB * $script:Scale; $auxPrice = $AuxListPerGB * $script:Scale
    $anaGB = 0.0; $basicGB = 0.0; $auxGB = 0.0
    foreach ($r in $byTable) {
        $pl = $tbl[$r.DataType].plan
        if ($pl -eq 'Basic') { $basicGB += $r.GB } elseif ($pl -eq 'Auxiliary') { $auxGB += $r.GB } else { $anaGB += $r.GB }
    }
    $totalGB = $anaGB + $basicGB + $auxGB
    $commit = [int]($p.sku.capacityReservationLevel)
    $clustered = [bool]$p.features.clusterResourceId
    $paygWin = ($dArr | Measure-Object -Sum).Sum * $script:Price
    $curWin = if ($commit -gt 0) { Get-TierWindowCost $dArr $commit } else { $paygWin }
    $scale30 = 30.0 / $Days
    $monthly = [math]::Round(($curWin + $basicGB * $basicPrice + $auxGB * $auxPrice) * $scale30, 2)
    $effRate = if ($anaGB -gt 0) { $curWin / $anaGB } else { $script:Price }
    $avgDay = [math]::Round($totalGB / $Days, 3)
    $peakIdx = 0; for ($i = 0; $i -lt $Days; $i++) { if ($dArr[$i] -gt $dArr[$peakIdx]) { $peakIdx = $i } }
    $peakGB = [math]::Round($dArr[$peakIdx], 3); $peakDay = if ($peakGB -gt 0) { $dayLabels[$peakIdx] } else { 'n/a' }
    $created = $null; if ($p.createdDate) { try { $created = [datetime]$p.createdDate } catch {} }
    $ageDays = if ($created) { [int]((Get-Date).ToUniversalTime() - $created.ToUniversalTime()).TotalDays } else { 999 }
    $cap = $p.workspaceCapping.dailyQuotaGb; $capText = if ($null -eq $cap -or [double]$cap -lt 0) { 'None' } else { "$cap GB/day" }
    $material = $monthly -ge $MinMonthlyCostUSD

    # ----- table rows -----
    $tableRows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $byTable) {
        $ts = $tbl[$r.DataType]; $pl = if ($ts.plan) { [string]$ts.plan } else { 'Analytics' }
        $rate = switch ($pl) { 'Basic' { $basicPrice } 'Auxiliary' { $auxPrice } default { $effRate } }
        $tableRows.Add([pscustomobject]@{
                Subscription = $sub.Name; Workspace = $wsKey; Table = $r.DataType; IngestedGB = [math]::Round($r.GB, 3)
                PctOfTotal = if ($totalGB) { [math]::Round(100 * $r.GB / $totalGB, 1) } else { 0 }
                EstMonthlyUSD = [math]::Round($r.GB * $rate * $scale30, 2); Plan = $pl
                RetentionDays = $ts.retentionInDays; TotalRetentionDays = $ts.totalRetentionInDays
                BasicEligible = $FeatureMatrix.Basic.Contains($r.DataType); AuxEligible = $FeatureMatrix.Aux.Contains($r.DataType)
            })
    }

    # ================= RECOMMENDATION ENGINE =================
    if ($totalGB -le 0) {
        if ($ageDays -lt $Days) { & $F 'Info' 'Hygiene' 'New workspace - no billable ingestion yet' "Workspace is only $ageDays day(s) old. Re-check after it has collected data." 0 '' 'Low' '' $false }
        else { & $F 'Medium' 'Hygiene' 'Idle workspace' "No billable ingestion in $Days days. Verify nothing depends on it (Sentinel, alerts, diagnostic settings), then delete or consolidate." 0 "az monitor log-analytics workspace delete -g $rg -n $($ws.name) --yes   # only after validation" 'Low' '' $false }
    }
    elseif (-not $material) {
        & $F 'Info' 'Hygiene' 'Spend below materiality threshold' ("Estimated ~{0} per month is under the {1} threshold - not worth optimising (change with -MinMonthlyCostUSD)." -f (Format-Usd $monthly), (Format-Usd $MinMonthlyCostUSD)) 0 '' 'Low' '' $false
    }
    else {
        if ($LegacySkus -contains $p.sku.name) {
            & $F 'Medium' 'Pricing' "Legacy pricing tier ($($p.sku.name))" 'Legacy tiers do not support Basic/Auxiliary plans or commitment tiers. Migrate to Pay-as-you-go (PerGB2018) and validate cost impact first.' 0 "az monitor log-analytics workspace update -g $rg -n $($ws.name) --sku PerGB2018" 'Low' '' $false
        }

        # --- Table-level analysis ---
        $reducedGB = 0.0
        foreach ($tr in $tableRows) {
            $name = $tr.Table; $ts = $tbl[$name]; $gb30 = $tr.IngestedGB * $scale30
            $isAna = $tr.Plan -eq 'Analytics'
            if ($isAna -and $tr.EstMonthlyUSD -ge [math]::Max(1, $MinMonthlyCostUSD / 2)) {
                $subtype = [string]$ts.schema.tableSubType
                $basicOk = $tr.BasicEligible -or ($name -like '*_CL' -and $subtype -ne 'Classic')
                $basicSave = if ($basicOk) { $gb30 * ($effRate - $basicPrice) } else { 0 }
                $pb = $TablePlaybook | Where-Object { $name -match $_.M } | Select-Object -First 1
                $tipSave = 0; $tipText = ''
                if ($pb) { $tipSave = $tr.EstMonthlyUSD * $pb.Pct; $tipText = $pb.Tip }
                elseif ($tr.PctOfTotal -ge 25) { $tipSave = $tr.EstMonthlyUSD * 0.15; $tipText = 'Dominant table: add a DCR transformation (source | where ... | project-away unused columns) to drop low-value rows/columns.' }
                $countBasic = $basicSave -ge $tipSave
                if ($basicSave -ge 5 -and $countBasic) { $reducedGB += $tr.IngestedGB }
                elseif ($tipSave -ge 3) { $reducedGB += $tr.IngestedGB * $(if ($pb) { $pb.Pct } else { 0.15 }) }
                if ($basicSave -ge 5) {
                    $aux = if ($tr.AuxEligible) { ' Auxiliary plan is cheaper still for audit/compliance data you rarely query.' } else { '' }
                    & $F (Get-SeverityBySaving $basicSave) 'Table plan' "$name -> Basic plan" ("{0} GB/month on the Analytics plan (~{1}/month). Basic ingestion is ~{2}/GB vs ~{3}/GB. Trade-offs: 30-day interactive retention, no alerts/export, limited KQL, per-GB query charge - use for troubleshooting/verbose data.{4}" -f [math]::Round($gb30, 1), (Format-Usd $tr.EstMonthlyUSD), (Format-Usd $basicPrice), (Format-Usd $effRate), $aux) $basicSave "az monitor log-analytics workspace table update -g $rg --workspace-name $($ws.name) -n $name --plan Basic" 'Medium' $name $countBasic
                }
                if ($tipSave -ge 3) {
                    & $F (Get-SeverityBySaving $tipSave) 'Collection' "$name - reduce collected volume" ("{0}% of ingestion (~{1}/month). {2} Typical reduction ~{3}%." -f $tr.PctOfTotal, (Format-Usd $tr.EstMonthlyUSD), $tipText, [int](100 * $(if ($pb) { $pb.Pct } else { 0.15 }))) $tipSave 'Edit the Data Collection Rule / diagnostic setting (portal: Monitor > Data Collection Rules). Test the transformation in the DCR editor before saving.' 'Medium' $name (-not $countBasic)
                }
            }
            # Retention economics (billed beyond free window; App Insights tables get 90 days free)
            $ret = [int]$ts.retentionInDays
            $free = if ($name -match $AiFreeRetentionTables) { 90 } else { 31 }
            if ($ret -gt $free -and $tr.Plan -ne 'Basic') {
                $extraMonths = ($ret - $free) / 30.0
                $retCost = $gb30 * $extraMonths * $RetentionListPerGBMonth * $script:Scale
                if ($retCost -ge 2) {
                    if ($ret -gt 90) {
                        $arch = $gb30 * (($ret - 90) / 30.0) * ($RetentionListPerGBMonth - $ArchiveListPerGBMonth) * $script:Scale
                        & $F 'Medium' 'Retention' "$name - $ret days interactive retention" ("Retention beyond {0} days costs ~{1}/month. Keep 90 days interactive and move older data to low-cost long-term retention (archive)." -f $free, (Format-Usd $retCost)) $arch "az monitor log-analytics workspace table update -g $rg --workspace-name $($ws.name) -n $name --retention-time 90 --total-retention-time $ret" 'Low' $name $true
                    }
                    else {
                        & $F 'Low' 'Retention' "$name - $ret days retention" ("Days {0}-{1} cost ~{2}/month. Confirm the business/regulatory need; otherwise reduce to the free {0} days." -f $free, $ret, (Format-Usd $retCost)) $retCost "az monitor log-analytics workspace table update -g $rg --workspace-name $($ws.name) -n $name --retention-time $free" 'Low' $name $false
                    }
                }
            }
        }

        # --- Pricing tier fit: evaluated on real daily volumes AFTER the table optimisations above ---
        if ($clustered) {
            & $F 'Info' 'Pricing' 'Workspace is linked to a dedicated cluster' 'Commitment is managed at the cluster level - review cluster commitment vs combined ingestion.' 0 '' 'Low' '' $false
        }
        elseif ($anaGB -gt 0) {
            $fRed = [math]::Min(0.95, $reducedGB / $anaGB)
            $dRed = @($dArr | ForEach-Object { $_ * (1 - $fRed) })
            $paygRed = ($dRed | Measure-Object -Sum).Sum * $script:Price
            $curRed = if ($commit -gt 0) { Get-TierWindowCost $dRed $commit } else { $paygRed }
            $best = @{ L = 0; C = $paygRed }
            foreach ($t in $CommitmentTiers) { $c = Get-TierWindowCost $dRed $t.L; if ($c -lt $best.C) { $best = @{ L = $t.L; C = $c } } }
            $saving = ($curRed - $best.C) * $scale30
            $avgRed = [math]::Round(($dRed | Measure-Object -Sum).Sum / $Days, 1)
            $basis = if ($fRed -gt 0) { "Based on your daily volumes after the table optimisations above (~$avgRed GB/day analytics)" } else { "Based on your actual daily volumes (avg $avgRed GB/day analytics)" }
            if ($best.L -ne $commit -and $saving -ge [math]::Max($MinMonthlyCostUSD / 2, 0.05 * $curRed * $scale30)) {
                if ($best.L -eq 0) {
                    & $F 'Medium' 'Pricing' "Commitment tier ($commit GB/day) is larger than needed" ("$basis the commitment is not fully used. Reverting to pay-as-you-go would save ~{0}/month. Tiers have a 31-day commitment (can be lowered within 6h of a change)." -f (Format-Usd $saving)) $saving "az monitor log-analytics workspace update -g $rg -n $($ws.name) --sku PerGB2018" 'Low' '' $true
                }
                else {
                    $verb = if ($commit) { "Change commitment tier from $commit to $($best.L) GB/day" } else { "Move to the $($best.L) GB/day commitment tier" }
                    & $F (Get-SeverityBySaving $saving) 'Pricing' $verb ("$basis the {0} GB/day tier is the cheapest option: ~{1}/month saving. Commitment covers Analytics tables only and has a 31-day lock; days below the commitment still bill the full tier." -f $best.L, (Format-Usd $saving)) $saving "az monitor log-analytics workspace update -g $rg -n $($ws.name) --sku CapacityReservation --capacity-reservation-level $($best.L)" 'Low' '' $true
                }
            }
            elseif (-not $commit -and $avgRed -ge 60) {
                & $F 'Low' 'Pricing' 'Approaching the 100 GB/day commitment tier' ("Avg {0} GB/day - re-evaluate as volume grows; the first tier gives ~15% off." -f $avgRed) 0 '' 'Low' '' $false
            }
        }
        # --- Trend / spikes / governance ---
        $nz = @($dArr | Where-Object { $_ -gt 0 } | Sort-Object)
        if ($nz.Count -ge 3) {
            $med = $nz[[int][math]::Floor($nz.Count / 2)]
            if ($med -gt 0 -and $peakGB -gt 3 * $med -and ($peakGB - $med) * $effRate -ge 5) {
                & $F 'Medium' 'Anomaly' "Ingestion spike on $peakDay" ("Peak {0} GB is {1}x the median day ({2} GB) - roughly {3} of unexpected cost. Find the culprit table/resource and fix verbose logging or loops." -f $peakGB, [math]::Round($peakGB / $med, 1), [math]::Round($med, 2), (Format-Usd (($peakGB - $med) * $effRate))) 0 "Usage | where TimeGenerated between (datetime($peakDay) .. datetime($peakDay)+1d) | where IsBillable | summarize GB=sum(Quantity)/1000 by DataType | top 5 by GB" 'Low' '' $false
            }
        }
        if ($Days -ge 14 -and $ageDays -ge 14) {
            $last = ($dArr[($Days - 7)..($Days - 1)] | Measure-Object -Sum).Sum
            $prev = ($dArr[($Days - 14)..($Days - 8)] | Measure-Object -Sum).Sum
            if ($prev -gt 0 -and ($last / $prev) -ge 1.4 -and ($last * $effRate * 30 / 7) -ge $MinMonthlyCostUSD) {
                & $F 'Medium' 'Anomaly' ('Ingestion growing {0:N0}% week-over-week' -f (100 * ($last / $prev - 1))) ("Last 7 days {0} GB vs prior 7 days {1} GB. At this rate the workspace runs at ~{2}/month. Investigate new onboarding or log-level changes." -f [math]::Round($last, 2), [math]::Round($prev, 2), (Format-Usd ($last * $effRate * 30 / 7))) 0 '' 'Low' '' $false
            }
        }
        if ($capText -eq 'None') {
            & $F 'Low' 'Governance' 'No daily cap or ingestion alert' 'Add a log-search alert on ingestion volume (Usage table) and, for non-production workspaces, a daily cap (data is dropped once the cap is hit).' 0 "az monitor log-analytics workspace update -g $rg -n $($ws.name) --quota <GB-per-day>" 'Low' '' $false
        }
    }

    $saved = [math]::Round((@($findings | Where-Object { $_.CountInTotal -and $_.Severity -ne 'Info' }) | Measure-Object EstMonthlySavingUSD -Sum).Sum, 2)
    $score = if ($material -and $monthly -gt 0) { [int][math]::Max(0, [math]::Min(100, 100 - [math]::Round(100 * $saved / $monthly))) } else { $null }
    $findings | ForEach-Object { $script:AllFindings.Add($_) }
    $tableRows | ForEach-Object { $script:AllTables.Add($_) }

    $resRows = @($topRes | ForEach-Object { [pscustomobject]@{ Resource = Get-ShortResource $_.Res; ResourceId = $_.Res; GB7d = [math]::Round($_.GB, 3); Tables = (@($_.Tables) -join ', ') } })
    $sum = [pscustomobject]@{
        Subscription = $sub.Name; Workspace = $ws.name; ResourceGroup = $rg; Location = $ws.location; Sku = $p.sku.name
        CommitmentGBPerDay = $commit; RetentionDays = $p.retentionInDays; DailyCap = $capText
        BillableGB = [math]::Round($totalGB, 3); AvgGBPerDay = $avgDay; AnalyticsAvgGBPerDay = [math]::Round($anaGB / $Days, 3); PeakGB = $peakGB; PeakDay = $peakDay
        EstMonthlyUSD = $monthly; PotentialSavingUSD = $saved; EfficiencyScore = $score; TopTable = $(if ($byTable) { $byTable[0].DataType } else { '' })
        Findings = @($findings | Where-Object Severity -ne 'Info').Count; AgeDays = $ageDays
        Daily = $dArr; DayLabels = $dayLabels; TopTables = @($tableRows | Select-Object -First 8); TopResources = $resRows
    }
    $script:AllSummary.Add($sum)

    # ----- console card -----
    Write-Host
    Write-Host ('  SKU {0}{1}  ·  Retention {2}d  ·  Daily cap {3}  ·  Age {4}' -f $p.sku.name, $(if ($commit) { " ($commit GB/day)" }), $p.retentionInDays, $capText, $(if ($ageDays -ge 999) { 'n/a' } else { "$ageDays d" })) -ForegroundColor DarkGray
    Write-Host '  Ingestion  ' -NoNewline -ForegroundColor Gray
    Write-Host ('{0:N2} GB' -f $totalGB) -NoNewline -ForegroundColor White
    Write-Host ("  avg {0:N3} GB/day  peak {1:N2} GB ({2})  " -f $avgDay, $peakGB, $peakDay) -NoNewline -ForegroundColor Gray
    Write-Host ('~{0}/month' -f (Format-Usd $monthly)) -ForegroundColor Yellow
    if ($totalGB -gt 0) {
        Write-Host ('  Trend      ' + (New-Spark $dArr) + ('  ({0}d)' -f $Days)) -ForegroundColor DarkCyan
        Write-Host
        foreach ($tr in ($tableRows | Select-Object -First 6)) {
            Write-Host ('  {0,-30}' -f $(if ($tr.Table.Length -gt 29) { $tr.Table.Substring(0, 29) } else { $tr.Table })) -NoNewline -ForegroundColor White
            Write-Host (New-Bar $tr.PctOfTotal 20) -NoNewline -ForegroundColor $(if ($tr.PctOfTotal -ge 50) { 'Red' } elseif ($tr.PctOfTotal -ge 25) { 'Yellow' } else { 'Cyan' })
            Write-Host (' {0,5}%  {1,9} GB  {2,9}  {3}' -f $tr.PctOfTotal, ('{0:N3}' -f $tr.IngestedGB), (Format-Usd $tr.EstMonthlyUSD), $tr.Plan) -ForegroundColor Gray
        }
        if ($resRows.Count) {
            Write-Host; Write-Host '  Top resources (7d)' -ForegroundColor DarkGray
            foreach ($rr in ($resRows | Select-Object -First 4)) { Write-Host ('   · {0,-52} {1,8:N3} GB' -f $(if ($rr.Resource.Length -gt 51) { $rr.Resource.Substring(0, 51) } else { $rr.Resource }), $rr.GB7d) -ForegroundColor Gray }
        }
    }
    $shown = @($findings | Sort-Object @{ e = { @{ High = 0; Medium = 1; Low = 2; Info = 3 }[$_.Severity] } }, @{ e = 'EstMonthlySavingUSD'; Descending = $true })
    if ($shown.Count) {
        Write-Host; Write-Host '  Recommendations' -ForegroundColor Magenta
        foreach ($f in $shown) {
            Write-Host ('   {0,-6}' -f $f.Severity.ToUpper()) -NoNewline -ForegroundColor (Get-SevColor $f.Severity)
            Write-Host (' {0}' -f $f.Title) -NoNewline -ForegroundColor White
            if ($f.EstMonthlySavingUSD -gt 0 -and $f.Severity -ne 'Info') { Write-Host ('   save ~{0}/mo' -f (Format-Usd $f.EstMonthlySavingUSD)) -NoNewline -ForegroundColor Green }
            Write-Host
        }
    }
    if ($null -ne $score) {
        Write-Host ('  Efficiency score  {0}/100  {1}   potential saving ~{2}/month' -f $score, (New-Bar $score 20), (Format-Usd $saved)) -ForegroundColor $(if ($score -ge 80) { 'Green' } elseif ($score -ge 50) { 'Yellow' } else { 'Red' })
    }
}


# ---------- HTML report ----------
function ConvertTo-HtmlText($s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }
function New-DonutSvg($Segs, [string]$Center, [string]$Sub, [int]$Size = 150) {
    $total = ($Segs | Measure-Object V -Sum).Sum; if (-not $total) { $total = 1 }
    $off = 25.0; $arcs = ''
    foreach ($s in $Segs) {
        $p = 100.0 * $s.V / $total
        $arcs += [string]::Format([cultureinfo]::InvariantCulture, '<circle r="15.9155" cx="21" cy="21" fill="none" stroke="{0}" stroke-width="4.5" stroke-dasharray="{1:N2} {2:N2}" stroke-dashoffset="{3:N2}"/>', $s.C, $p, (100 - $p), $off)
        $off -= $p
    }
    '<svg viewBox="0 0 42 42" width="{0}" height="{0}" role="img"><circle r="15.9155" cx="21" cy="21" fill="none" stroke="var(--track)" stroke-width="4.5"/>{1}<text x="21" y="21.8" text-anchor="middle" class="dn">{2}</text><text x="21" y="26.6" text-anchor="middle" class="ds">{3}</text></svg>' -f $Size, $arcs, (ConvertTo-HtmlText $Center), (ConvertTo-HtmlText $Sub)
}
function New-RingSvg($Score, [int]$Size = 52) {
    if ($null -eq $Score) { return ('<div class="ring na" style="width:{0}px;height:{0}px">n/a</div>' -f $Size) }
    $c = if ($Score -ge 80) { 'var(--good)' } elseif ($Score -ge 50) { 'var(--warn)' } else { 'var(--bad)' }
    '<svg class="ring" viewBox="0 0 42 42" width="{0}" height="{0}"><circle r="15.9155" cx="21" cy="21" fill="none" stroke="var(--track)" stroke-width="4"/><circle r="15.9155" cx="21" cy="21" fill="none" stroke="{1}" stroke-width="4" stroke-linecap="round" stroke-dasharray="{2} {3}" stroke-dashoffset="25"/><text x="21" y="24.5" text-anchor="middle" class="rn">{2}</text></svg>' -f $Size, $c, [int]$Score, (100 - [int]$Score)
}
function New-AreaSvg([double[]]$v, [string[]]$labels, [int]$w = 720, [int]$h = 130) {
    if (-not $v -or $v.Count -lt 2) { return '' }
    $ci = [cultureinfo]::InvariantCulture
    $m = ($v | Measure-Object -Maximum).Maximum; if ($m -le 0) { $m = 1 }
    $pad = 6; $pts = @(); $dots = ''
    for ($i = 0; $i -lt $v.Count; $i++) {
        $x = $i * $w / ($v.Count - 1); $y = $h - $pad - ($v[$i] / $m) * ($h - 2 * $pad - 8)
        $pts += [string]::Format($ci, '{0:N1},{1:N1}', $x, $y)
        $dots += [string]::Format($ci, '<circle cx="{0:N1}" cy="{1:N1}" r="6" fill="transparent"><title>{2}: {3:N3} GB</title></circle>', $x, $y, $labels[$i], $v[$i])
    }
    $line = $pts -join ' '
    [string]::Format($ci, '<svg class="area" viewBox="0 0 {0} {1}" preserveAspectRatio="none"><defs><linearGradient id="g{4}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--accent)" stop-opacity=".35"/><stop offset="1" stop-color="var(--accent)" stop-opacity="0"/></linearGradient></defs><polygon fill="url(#g{4})" points="0,{1} {2} {0},{1}"/><polyline fill="none" stroke="var(--accent)" stroke-width="2" vector-effect="non-scaling-stroke" points="{2}"/>{3}</svg><div class="axis"><span>{5}</span><span>peak {6:N2} GB/day</span><span>{7}</span></div>', $w, $h, $line, $dots, $script:areaId++, $labels[0], $m, $labels[-1])
}
function New-MiniSpark([double[]]$v) {
    if (-not $v -or $v.Count -lt 2) { return '' }
    $ci = [cultureinfo]::InvariantCulture; $w = 110; $h = 28
    $m = ($v | Measure-Object -Maximum).Maximum; if ($m -le 0) { $m = 1 }
    $pts = for ($i = 0; $i -lt $v.Count; $i++) { [string]::Format($ci, '{0:N1},{1:N1}', ($i * $w / ($v.Count - 1)), ($h - 3 - ($v[$i] / $m) * ($h - 6))) }
    '<svg width="{0}" height="{1}" viewBox="0 0 {0} {1}"><polyline fill="none" stroke="var(--accent)" stroke-width="1.6" points="{2}"/></svg>' -f $w, $h, ($pts -join ' ')
}

function New-HtmlReport {
    $prevCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
    [System.Threading.Thread]::CurrentThread.CurrentCulture = [cultureinfo]::InvariantCulture
    try {
        $script:areaId = 1
        $e = { param($x) ConvertTo-HtmlText $x }
        $sb = New-Object System.Text.StringBuilder
        $sevRank = { @{ High = 0; Medium = 1; Low = 2; Info = 3 }[$_.Severity] }
        $counted = @($AllFindings | Where-Object { $_.CountInTotal -and $_.Severity -ne 'Info' -and $_.EstMonthlySavingUSD -gt 0 })
        $tot = [double](($AllSummary | Measure-Object EstMonthlyUSD -Sum).Sum)
        $sav = [double](($counted | Measure-Object EstMonthlySavingUSD -Sum).Sum)
        $pct = if ($tot -gt 0) { [math]::Min(100, [math]::Round(100 * $sav / $tot)) } else { 0 }
        $hi = @($AllFindings | Where-Object Severity -eq 'High').Count; $me = @($AllFindings | Where-Object Severity -eq 'Medium').Count; $lo = @($AllFindings | Where-Object Severity -eq 'Low').Count
        $subCount = @($AllSummary | Select-Object -ExpandProperty Subscription -Unique).Count
        $gbTotal = [double](($AllSummary | Measure-Object BillableGB -Sum).Sum)
        $catColors = @{ 'Pricing' = '#6366f1'; 'Table plan' = '#06b6d4'; 'Collection' = '#10b981'; 'Retention' = '#f59e0b'; 'Anomaly' = '#ef4444'; 'Governance' = '#8b5cf6'; 'Hygiene' = '#64748b' }

        $css = @'
:root{--bg:#f5f7fb;--card:#fff;--ink:#0f172a;--mute:#64748b;--line:#e6eaf2;--track:#e8edf5;--accent:#2563eb;--accent2:#7c3aed;--good:#16a34a;--warn:#d97706;--bad:#dc2626;--shadow:0 1px 2px rgba(15,23,42,.04),0 8px 24px rgba(15,23,42,.06);--code:#0b1220}
[data-theme=dark]{--bg:#0b1220;--card:#111a2e;--ink:#e6edf7;--mute:#8da0bb;--line:#1d2a44;--track:#1b2740;--accent:#60a5fa;--accent2:#a78bfa;--good:#4ade80;--warn:#fbbf24;--bad:#f87171;--shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.35);--code:#070c17}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI Variable","Segoe UI",Inter,system-ui,-apple-system,Roboto,Arial,sans-serif;-webkit-font-smoothing:antialiased}
nav{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:6px;padding:10px 32px;background:color-mix(in srgb,var(--card) 82%,transparent);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
nav b{margin-right:auto;font-size:14px;letter-spacing:.2px}nav a{color:var(--mute);text-decoration:none;padding:6px 10px;border-radius:8px;font-size:13px}nav a:hover{background:var(--track);color:var(--ink)}
button{font:inherit;cursor:pointer}.btn{border:1px solid var(--line);background:var(--card);color:var(--ink);padding:6px 12px;border-radius:8px}.btn:hover{border-color:var(--accent)}
.hero{background:radial-gradient(1200px 400px at 85% -20%,#7c3aed55,transparent),linear-gradient(120deg,#0b1f3a,#133a73 55%,#1d5fd1);color:#fff;padding:44px 32px 86px}
.wrap{max-width:1240px;margin:0 auto}.hero .wrap{display:grid;grid-template-columns:1fr auto;gap:32px;align-items:center}
.eyebrow{text-transform:uppercase;letter-spacing:1.6px;font-size:11px;opacity:.75}.hero h1{margin:6px 0 10px;font-size:34px;line-height:1.15;letter-spacing:-.5px}
.big{font-size:56px;font-weight:800;letter-spacing:-1.5px;line-height:1}.big small{font-size:18px;font-weight:500;opacity:.8;letter-spacing:0}
.sub{opacity:.85;margin-top:8px}.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}.chip{font-size:12px;padding:4px 10px;border-radius:999px;background:#ffffff1f;border:1px solid #ffffff33}
.hero .dn{fill:#fff;font-size:8px;font-weight:800}.hero .ds{fill:#cfe0ff;font-size:2.6px}
main{margin-top:-58px;padding:0 32px 40px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px 18px;box-shadow:var(--shadow);position:relative;overflow:hidden}
.kpi:before{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:var(--k,var(--accent))}
.kpi span{display:block;font-size:11.5px;color:var(--mute);text-transform:uppercase;letter-spacing:.7px}.kpi b{display:block;font-size:26px;letter-spacing:-.5px;margin-top:2px}.kpi i{font-style:normal;font-size:12px;color:var(--mute)}
h2{font-size:18px;margin:36px 0 12px;letter-spacing:-.2px;display:flex;align-items:center;gap:10px}h2:after{content:"";flex:1;height:1px;background:var(--line)}
.grid2{display:grid;grid-template-columns:1.4fr 1fr;gap:16px}@media(max-width:960px){.grid2,.hero .wrap{grid-template-columns:1fr}.big{font-size:42px}nav{padding:10px 16px}main,.hero{padding-left:16px;padding-right:16px}}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px 20px;box-shadow:var(--shadow)}
.card h3{margin:0 0 12px;font-size:14px;color:var(--mute);font-weight:600;text-transform:uppercase;letter-spacing:.6px}
.hbar{display:grid;grid-template-columns:200px 1fr 92px;gap:10px;align-items:center;margin:9px 0;font-size:13px}.hbar .n{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hbar .t{height:10px;background:var(--track);border-radius:6px;overflow:hidden}.hbar .t i{display:block;height:100%;border-radius:6px;background:linear-gradient(90deg,var(--accent),var(--accent2))}.hbar .v{text-align:right;font-variant-numeric:tabular-nums;color:var(--mute)}
.legend{display:grid;gap:8px;font-size:13px}.legend div{display:flex;align-items:center;gap:8px}.legend i{width:10px;height:10px;border-radius:3px;flex:none}.legend em{margin-left:auto;font-style:normal;font-weight:700;font-variant-numeric:tabular-nums}
.donut{display:flex;gap:20px;align-items:center;flex-wrap:wrap}.dn{fill:var(--ink);font-size:6px;font-weight:800}.ds{fill:var(--mute);font-size:2.6px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}
.win{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px;box-shadow:var(--shadow)}.win .amt{color:var(--good);font-weight:800;font-size:20px}.win .ttl{font-weight:600;margin:2px 0}.win .ws{color:var(--mute);font-size:12px}
.tag{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;padding:2px 8px;border-radius:999px;color:#fff;vertical-align:middle}
.t-High{background:var(--bad)}.t-Medium{background:var(--warn)}.t-Low{background:#0ea5e9}.t-Info{background:#94a3b8}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--mute);font-size:11px;text-transform:uppercase;letter-spacing:.6px;padding:8px 10px;border-bottom:1px solid var(--line)}td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}tr:last-child td{border-bottom:0}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}.good{color:var(--good);font-weight:700}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}.toolbar input{flex:1;min-width:200px;padding:8px 12px;border-radius:10px;border:1px solid var(--line);background:var(--card);color:var(--ink);font:inherit}
.pill{border:1px solid var(--line);background:var(--card);color:var(--ink);padding:6px 12px;border-radius:999px;font-size:12.5px}.pill.on{background:var(--accent);border-color:var(--accent);color:#fff}
details.ws{background:var(--card);border:1px solid var(--line);border-radius:16px;margin:12px 0;box-shadow:var(--shadow)}
details.ws>summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:56px 1.6fr 120px 110px 110px 24px;gap:14px;align-items:center;padding:14px 18px}
details.ws>summary::-webkit-details-marker{display:none}details.ws>summary:after{content:"\25B8";color:var(--mute);transition:transform .15s}details[open].ws>summary:after{transform:rotate(90deg)}
.wn b{display:block;font-size:15px}.wn small{color:var(--mute)}.col small{display:block;color:var(--mute);font-size:11px;text-transform:uppercase;letter-spacing:.5px}.col b{font-variant-numeric:tabular-nums}
.ring .rn{fill:var(--ink);font-size:11px;font-weight:800}.ring.na{display:flex;align-items:center;justify-content:center;border-radius:50%;background:var(--track);color:var(--mute);font-size:11px}
.body{padding:4px 18px 18px;border-top:1px solid var(--line)}.mini{display:flex;flex-wrap:wrap;gap:22px;margin:12px 0;color:var(--mute);font-size:12.5px}.mini b{color:var(--ink)}
.area{width:100%;height:130px;display:block}.axis{display:flex;justify-content:space-between;color:var(--mute);font-size:11px;margin-top:2px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin:14px 0}@media(max-width:960px){.two{grid-template-columns:1fr}details.ws>summary{grid-template-columns:48px 1fr 24px}.col{display:none}}
.trow{display:grid;grid-template-columns:150px 1fr 270px;gap:10px;align-items:center;font-size:12.5px;margin:6px 0}.trow .n{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.trow .t{height:8px;background:var(--track);border-radius:5px}.trow .t i{display:block;height:100%;border-radius:5px;background:var(--accent)}.trow .v{color:var(--mute);white-space:nowrap;text-align:right;font-variant-numeric:tabular-nums}
.badge{font-size:10px;padding:1px 6px;border-radius:6px;background:var(--track);color:var(--mute);margin-left:4px}
.f{border:1px solid var(--line);border-left:4px solid var(--c);border-radius:12px;padding:12px 14px;margin:10px 0;background:var(--card)}
.f.High{--c:var(--bad)}.f.Medium{--c:var(--warn)}.f.Low{--c:#0ea5e9}.f.Info{--c:#94a3b8}
.fh{display:flex;gap:10px;align-items:flex-start}.fh .ft{font-weight:650;flex:1}.fh .sv{color:var(--good);font-weight:800;white-space:nowrap}.fm{color:var(--mute);font-size:12px;margin-top:2px}.fd{margin-top:6px}
.how{margin-top:8px}.how summary{cursor:pointer;color:var(--accent);font-size:12.5px}.how pre{position:relative;margin:8px 0 0;background:var(--code);color:#cfe3ff;padding:12px 14px;border-radius:10px;font:12px/1.5 Cascadia Code,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
.copy{position:absolute;top:8px;right:8px;font-size:11px;padding:3px 8px;border-radius:6px;border:1px solid #ffffff30;background:#ffffff12;color:#cfe3ff}
.note{color:var(--mute);font-size:12.5px}ul.note li{margin:4px 0}code{background:var(--track);padding:1px 5px;border-radius:5px}
footer{padding:24px 32px 48px;color:var(--mute);font-size:12px;text-align:center}.empty{padding:26px;text-align:center;color:var(--mute)}
@media print{nav,.toolbar,.copy{display:none}.hero{padding-bottom:40px}main{margin-top:0}details.ws .body{display:block}body{background:#fff}}
'@
        $js = @'
(function(){var d=document,r=d.documentElement,t=localStorage.getItem('lat');if(t)r.dataset.theme=t;else if(matchMedia('(prefers-color-scheme:dark)').matches)r.dataset.theme='dark';
d.getElementById('th').onclick=function(){r.dataset.theme=r.dataset.theme==='dark'?'light':'dark';localStorage.setItem('lat',r.dataset.theme)};
var sev='all',q='';function apply(){d.querySelectorAll('details.ws').forEach(function(w){var any=0,name=(w.dataset.name||'').toLowerCase();
w.querySelectorAll('.f').forEach(function(f){var ok=(sev==='all'||f.dataset.sev===sev)&&(!q||(f.textContent.toLowerCase().indexOf(q)>-1||name.indexOf(q)>-1));f.style.display=ok?'':'none';if(ok)any++});
var nm=!q||name.indexOf(q)>-1;w.style.display=(any||(sev==='all'&&nm&&!w.querySelector('.f')))?'':'none';if(q&&any&&sev!=='all')w.open=true});}
d.querySelectorAll('.pill[data-sev]').forEach(function(b){b.onclick=function(){d.querySelectorAll('.pill[data-sev]').forEach(function(x){x.classList.remove('on')});b.classList.add('on');sev=b.dataset.sev;apply()}});
var s=d.getElementById('q');if(s)s.oninput=function(){q=s.value.toLowerCase();apply()};
var ex=d.getElementById('ex');if(ex)ex.onclick=function(){var o=ex.dataset.o!=='1';d.querySelectorAll('details.ws').forEach(function(w){w.open=o});ex.dataset.o=o?'1':'0';ex.textContent=o?'Collapse all':'Expand all'};
d.querySelectorAll('.copy').forEach(function(b){b.onclick=function(){var c=b.parentNode.querySelector('code').textContent;navigator.clipboard.writeText(c).then(function(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy'},1400)})}});
addEventListener('beforeprint',function(){d.querySelectorAll('details').forEach(function(x){x.open=true})});})();
'@
        [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Log Analytics Cost Intelligence</title><style>' + $css + '</style></head><body>')
        [void]$sb.AppendLine('<nav><b>&#9670; Log Analytics Cost Intelligence</b><a href="#summary">Summary</a><a href="#wins">Quick wins</a><a href="#opps">Opportunities</a><a href="#workspaces">Workspaces</a><a href="#method">Method</a><button class="btn" id="th" title="Toggle theme">&#9680; Theme</button><button class="btn" onclick="print()">Print / PDF</button></nav>')

        # ---- hero ----
        $donut = New-DonutSvg @(@{ V = $pct; C = '#5eead4' }, @{ V = (100 - $pct); C = '#ffffff30' }) ("$pct%") 'of spend' 170
        $metaChips = ('<span class="chip">{0}-day window</span><span class="chip">PAYG {1}/GB</span><span class="chip">{2} workspaces</span><span class="chip">{3} subscription(s)</span><span class="chip">Table matrix: {4}</span><span class="chip">{5:yyyy-MM-dd HH:mm}</span>' -f $Days, (Format-Usd $script:Price), $AllSummary.Count, $subCount, (& $e $FeatureMatrix.Source), (Get-Date))
        [void]$sb.AppendLine(@"
<header class="hero" id="summary"><div class="wrap"><div><div class="eyebrow">Azure Monitor &middot; Cost optimisation assessment</div><h1>Potential saving identified</h1>
<div class="big">$(Format-Usd $sav)<small> / month</small></div><div class="sub">&asymp; $(Format-Usd ($sav * 12)) per year &middot; $pct% of an estimated $(Format-Usd $tot) monthly Log Analytics spend</div><div class="chips">$metaChips</div></div><div>$donut</div></div></header>
<main><div class="wrap">
<div class="kpis">
<div class="kpi" style="--k:#2563eb"><span>Est. monthly spend</span><b>$(Format-Usd $tot)</b><i>$([math]::Round($gbTotal,1)) GB billable in window</i></div>
<div class="kpi" style="--k:#16a34a"><span>Potential saving</span><b>$(Format-Usd $sav)</b><i>$(Format-Usd ($sav*12)) annualised</i></div>
<div class="kpi" style="--k:#dc2626"><span>High priority</span><b>$hi</b><i>$me medium &middot; $lo low</i></div>
<div class="kpi" style="--k:#7c3aed"><span>Workspaces</span><b>$($AllSummary.Count)</b><i>$subCount subscription(s)</i></div>
</div>
"@)

        # ---- where the money goes ----
        $topSpend = @($AllSummary | Sort-Object EstMonthlyUSD -Descending | Select-Object -First 8)
        $maxSpend = [double](($topSpend | Measure-Object EstMonthlyUSD -Maximum).Maximum); if ($maxSpend -le 0) { $maxSpend = 1 }
        $bars = ($topSpend | ForEach-Object { '<div class="hbar"><span class="n" title="{0}">{0}</span><span class="t"><i style="width:{1:N1}%"></i></span><span class="v">{2}</span></div>' -f (& $e $_.Workspace), (100 * $_.EstMonthlyUSD / $maxSpend), (Format-Usd $_.EstMonthlyUSD) }) -join ''
        $cats = @($counted | Group-Object Category | ForEach-Object { [pscustomobject]@{ Name = $_.Name; V = ($_.Group | Measure-Object EstMonthlySavingUSD -Sum).Sum } } | Sort-Object V -Descending)
        $segs = @($cats | ForEach-Object { @{ V = $_.V; C = $(if ($catColors[$_.Name]) { $catColors[$_.Name] } else { '#64748b' }) } })
        $legend = ($cats | ForEach-Object { '<div><i style="background:{0}"></i>{1}<em>{2}</em></div>' -f $(if ($catColors[$_.Name]) { $catColors[$_.Name] } else { '#64748b' }), (& $e $_.Name), (Format-Usd $_.V) }) -join ''
        $catBlock = if ($cats.Count) { '<div class="donut">' + (New-DonutSvg $segs (Format-Usd $sav) 'per month' 150) + '<div class="legend" style="flex:1;min-width:150px">' + $legend + '</div></div>' } else { '<div class="empty">No quantified savings above the materiality threshold.</div>' }
        [void]$sb.AppendLine(('<h2>Where the money goes</h2><div class="grid2"><div class="card"><h3>Estimated monthly spend by workspace</h3>{0}</div><div class="card"><h3>Savings by category</h3>{1}</div></div>' -f $bars, $catBlock))

        # ---- quick wins / strategic ----
        $ranked = @($counted | Sort-Object EstMonthlySavingUSD -Descending)
        $quick = @($ranked | Where-Object { $_.Effort -eq 'Low' } | Select-Object -First 6)
        $strat = @($ranked | Where-Object { $_.Effort -ne 'Low' } | Select-Object -First 6)
        $card = { param($f) '<div class="win"><div class="amt">{0}<span class="note"> /mo</span></div><div class="ttl">{1}</div><div class="ws">{2} &middot; {3} effort</div></div>' -f (Format-Usd $f.EstMonthlySavingUSD), (& $e $f.Title), (& $e $f.Workspace), $f.Effort }
        [void]$sb.AppendLine('<h2 id="wins">Quick wins <span class="note">low effort, configuration only</span></h2>')
        if ($quick.Count) { [void]$sb.AppendLine('<div class="cards">' + (($quick | ForEach-Object { & $card $_ }) -join '') + '</div>') } else { [void]$sb.AppendLine('<div class="card empty">No low-effort quantified savings.</div>') }
        if ($strat.Count) { [void]$sb.AppendLine('<h2>Strategic initiatives <span class="note">needs validation or change control</span></h2><div class="cards">' + (($strat | ForEach-Object { & $card $_ }) -join '') + '</div>') }

        # ---- opportunities table ----
        $cross = @($AllFindings | Where-Object { $_.Workspace -like '(consolidation)*' })
        $top = @($ranked | Select-Object -First 12)
        [void]$sb.AppendLine('<h2 id="opps">Top opportunities</h2><div class="card">')
        if ($top.Count) {
            [void]$sb.AppendLine('<table><tr><th>#</th><th>Priority</th><th>Opportunity</th><th>Workspace</th><th class="num">Saving / mo</th><th>Effort</th></tr>')
            $n = 0; foreach ($f in $top) { $n++; [void]$sb.AppendLine(('<tr><td>{0}</td><td><span class="tag t-{1}">{1}</span></td><td><b>{2}</b></td><td>{3}</td><td class="num good">{4}</td><td>{5}</td></tr>' -f $n, $f.Severity, (& $e $f.Title), (& $e $f.Workspace), (Format-Usd $f.EstMonthlySavingUSD), $f.Effort)) }
            [void]$sb.AppendLine('</table><p class="note">Indicative and not strictly additive. Pricing-tier savings are evaluated on the volume remaining after table-level optimisations.</p>')
        }
        else { [void]$sb.AppendLine('<div class="empty">The environment looks efficient - nothing above the materiality threshold.</div>') }
        [void]$sb.AppendLine('</div>')
        if ($cross.Count) {
            [void]$sb.AppendLine('<h2>Cross-workspace opportunities</h2>')
            foreach ($f in $cross) { [void]$sb.AppendLine(('<div class="f {0}"><div class="fh"><span class="tag t-{0}">{0}</span><span class="ft">{1}</span><span class="sv">{2}/mo</span></div><div class="fm">{3}</div><div class="fd">{4}</div></div>' -f $f.Severity, (& $e $f.Title), (Format-Usd $f.EstMonthlySavingUSD), (& $e $f.Workspace), (& $e $f.Detail))) }
        }

        # ---- workspaces ----
        [void]$sb.AppendLine('<h2 id="workspaces">Workspace deep-dive</h2><div class="toolbar"><input id="q" type="search" placeholder="Search workspaces, tables, findings..."><button class="pill on" data-sev="all">All</button><button class="pill" data-sev="High">High</button><button class="pill" data-sev="Medium">Medium</button><button class="pill" data-sev="Low">Low</button><button class="btn" id="ex" data-o="0">Expand all</button></div>')
        $order = 0
        foreach ($s in ($AllSummary | Sort-Object @{ e = 'PotentialSavingUSD'; Descending = $true }, @{ e = 'EstMonthlyUSD'; Descending = $true })) {
            $order++; $key = "$($s.Workspace) [$($s.ResourceGroup)]"
            $open = if ($order -le 2 -and ($s.PotentialSavingUSD -gt 0)) { ' open' } else { '' }
            [void]$sb.AppendLine(('<details class="ws" data-name="{0}"{1}><summary><div>{2}</div><div class="wn"><b>{3}</b><small>{4} &middot; {5} &middot; {6}</small></div><div>{7}</div><div class="col"><small>Spend / mo</small><b>{8}</b></div><div class="col"><small>Saving / mo</small><b class="good">{9}</b></div></summary><div class="body">' -f (& $e "$($s.Workspace) $($s.ResourceGroup) $($s.Subscription)"), $open, (New-RingSvg $s.EfficiencyScore), (& $e $s.Workspace), (& $e $s.ResourceGroup), $s.Location, (& $e $s.Subscription), (New-MiniSpark $s.Daily), (Format-Usd $s.EstMonthlyUSD), (Format-Usd $s.PotentialSavingUSD)))
            [void]$sb.AppendLine(('<div class="mini"><span>SKU <b>{0}{1}</b></span><span>Retention <b>{2}d</b></span><span>Daily cap <b>{3}</b></span><span>Ingested <b>{4:N2} GB</b></span><span>Avg <b>{5:N3} GB/day</b></span><span>Peak <b>{6:N2} GB</b> ({7})</span></div>' -f $s.Sku, $(if ($s.CommitmentGBPerDay) { " ($($s.CommitmentGBPerDay) GB/d)" } else { '' }), $s.RetentionDays, $s.DailyCap, $s.BillableGB, $s.AvgGBPerDay, $s.PeakGB, $s.PeakDay))
            if ($s.BillableGB -gt 0) {
                $tbars = ($s.TopTables | ForEach-Object { '<div class="trow"><span class="n" title="{0}">{0}</span><span class="t"><i style="width:{1}%"></i></span><span class="v">{1}% &middot; {2:N3} GB &middot; {3}<span class="badge">{4}</span></span></div>' -f (& $e $_.Table), $_.PctOfTotal, $_.IngestedGB, (Format-Usd $_.EstMonthlyUSD), $_.Plan }) -join ''
                $rbars = if ($s.TopResources.Count) { ($s.TopResources | ForEach-Object { '<div class="trow" style="grid-template-columns:1fr 130px"><span class="n" title="{0}">{1}</span><span class="v">{2:N3} GB</span></div>' -f (& $e $_.ResourceId), (& $e $_.Resource), $_.GB7d }) -join '' } else { '<div class="note">Not collected.</div>' }
                [void]$sb.AppendLine(('<div class="note">Daily analytics ingestion</div>{0}<div class="two"><div><div class="note">Top tables</div>{1}</div><div><div class="note">Top resources (7 days)</div>{2}</div></div>' -f (New-AreaSvg $s.Daily $s.DayLabels), $tbars, $rbars))
            }
            $fs = @($AllFindings | Where-Object { $_.Workspace -eq $key } | Sort-Object @{ e = $sevRank }, @{ e = 'EstMonthlySavingUSD'; Descending = $true })
            foreach ($f in $fs) {
                $act = if ($f.Action) { '<details class="how"><summary>How to implement</summary><pre><button class="copy">Copy</button><code>' + (& $e $f.Action) + '</code></pre></details>' } else { '' }
                [void]$sb.AppendLine(('<div class="f {0}" data-sev="{0}"><div class="fh"><span class="tag t-{0}">{0}</span><span class="ft">{1}</span>{2}</div><div class="fm">{3} &middot; {4} effort</div><div class="fd">{5}</div>{6}</div>' -f $f.Severity, (& $e $f.Title), $(if ($f.EstMonthlySavingUSD -gt 0 -and $f.Severity -ne 'Info') { '<span class="sv">' + (Format-Usd $f.EstMonthlySavingUSD) + '/mo</span>' } else { '' }), $f.Category, $f.Effort, (& $e $f.Detail), $act))
            }
            [void]$sb.AppendLine('</div></details>')
        }

        # ---- method ----
        [void]$sb.AppendLine(('<h2 id="method">Method and assumptions</h2><div class="card"><ul class="note"><li>Billable ingestion comes from the workspace <code>Usage</code> table (UTC calendar days, last {0} days). All costs in USD.</li><li>Analytics ingestion priced at {1}/GB (pay-as-you-go) or the commitment-tier effective rate. Tier discounts are approximated at 15-30% (100-5000 GB/day) and evaluated against <b>actual daily volumes</b>; days below the commitment still bill the full tier.</li><li>Basic ~{2}/GB, Auxiliary ~{3}/GB, extended interactive retention ~{4}/GB-month, archive ~{5}/GB-month (list prices scaled to your pay-as-you-go rate).</li><li>Basic/Auxiliary eligibility follows Microsoft''s published table feature matrix ({6}). Basic has trade-offs: no alerts, limited KQL, 30-day interactive retention and a per-GB query charge.</li><li>Free retention: 31 days for Analytics tables, 90 days for Application Insights tables.</li><li>Findings are indicative. Validate in Azure Cost Management and the Azure pricing calculator before changing production workspaces.</li></ul><p class="note">Sources: Microsoft Learn - Azure Monitor cost optimization best practices, Log Analytics cost calculations, table plans, table feature support.</p></div></div></main><footer>Log Analytics Cost Intelligence v{7} &middot; read-only analysis &middot; generated {8:yyyy-MM-dd HH:mm}</footer><script>{9}</script></body></html>' -f $Days, (Format-Usd $script:Price), (Format-Usd ($BasicListPerGB * $script:Scale)), (Format-Usd ($AuxListPerGB * $script:Scale)), (Format-Usd ($RetentionListPerGBMonth * $script:Scale)), (Format-Usd ($ArchiveListPerGBMonth * $script:Scale)), (& $e $FeatureMatrix.Source), $script:Version, (Get-Date), $js))
        $sb.ToString()
    }
    finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $prevCulture }
}

if ($env:LA_COSTANALYZER_NOMAIN) { return }
# ================= MAIN =================
$swTotal = [System.Diagnostics.Stopwatch]::StartNew()
$script:AllSummary = New-Object System.Collections.Generic.List[object]
$script:AllFindings = New-Object System.Collections.Generic.List[object]
$script:AllTables = New-Object System.Collections.Generic.List[object]
$interactive = -not ($SubscriptionId -or $AllSubscriptions) -and -not [Console]::IsInputRedirected

Show-Banner
Write-Rule 'Sign-in'
if (-not (Get-Module -ListAvailable Az.Accounts)) { throw 'Az.Accounts module not found. Run: Install-Module Az.Accounts -Scope CurrentUser' }
Import-Module Az.Accounts -ErrorAction Stop
$ctx = Get-AzContext
if (-not $ctx) { Write-Line '  Opening Azure sign-in...' 'Gray'; Connect-AzAccount | Out-Null; $ctx = Get-AzContext }
elseif ($interactive) {
    $pick = @(Select-Interactive -Items @("Continue as $($ctx.Account.Id)", 'Sign in with a different account') -Title 'Azure account' -PageSize 2)
    if (-not $pick.Count) { Write-Line '  Cancelled.' 'Yellow'; return }
    if ($pick[0] -like 'Sign in*') { Connect-AzAccount -Force | Out-Null; $ctx = Get-AzContext }
}
Write-Host ('  ✔ Signed in as ') -NoNewline -ForegroundColor Green; Write-Host $ctx.Account.Id -ForegroundColor White

Write-Rule 'Subscriptions'
$subs = @(Invoke-Step 'Discovering subscriptions' { Get-AzSubscription -WarningAction SilentlyContinue | Where-Object State -eq 'Enabled' | Sort-Object Name })
if (-not $subs.Count) { throw 'No enabled subscriptions found for this account.' }
if ($AllSubscriptions) { $chosen = $subs }
elseif ($SubscriptionId) { $chosen = @($subs | Where-Object { $SubscriptionId -contains $_.Id -or $SubscriptionId -contains $_.Name }); if (-not $chosen.Count) { throw 'None of the requested subscriptions were found.' } }
else {
    $allEntry = [pscustomobject]@{ Name = ('★ ALL SUBSCRIPTIONS  ({0} enabled)' -f $subs.Count); Id = '*'; IsAll = $true }
    $picked = @(Select-Interactive -Items (@($allEntry) + $subs) -Label { if ($_.IsAll) { $_.Name } else { "{0}   ({1})" -f $_.Name, $_.Id } } -Title ("Select subscription(s) - first entry analyses ALL ({0} available)" -f $subs.Count) -Multi)
    $chosen = if ($picked | Where-Object { $_.IsAll }) { $subs } else { $picked }
}
if (-not $chosen.Count) { Write-Line '  Nothing selected.' 'Yellow'; return }
Write-Host ('  ✔ {0} subscription(s) selected' -f $chosen.Count) -ForegroundColor Green

Write-Rule 'Settings'
if ($Days -eq 0) {
    if ($interactive) {
        $opt = @('Last 7 days', 'Last 14 days', 'Last 30 days  (recommended)', 'Last 60 days', 'Last 90 days')
        $o = @(Select-Interactive -Items $opt -Title 'Analysis window' -PageSize 5 -StartIndex 2)
        if (-not $o.Count) { return }
        $Days = [int](($o[0] -split ' ')[1])
    }
    else { $Days = 30 }
}
if ($PricePerGB -le 0) {
    $PricePerGB = 2.76
    if ($interactive) {
        $a = Read-Host ('  Customer pay-as-you-go price per GB in USD [{0}]' -f $PricePerGB)
        $v = 0.0; if ([double]::TryParse($a, [ref]$v) -and $v -gt 0) { $PricePerGB = $v }
    }
}
$script:Price = $PricePerGB; $script:Scale = $PricePerGB / $ListPaygPerGB
Write-Host ('  ✔ Window {0} days  ·  PAYG {1}/GB  ·  materiality {2}/month  ·  currency USD' -f $Days, (Format-Usd $PricePerGB), (Format-Usd $MinMonthlyCostUSD)) -ForegroundColor Green
$FeatureMatrix = Invoke-Step 'Loading Basic/Auxiliary table capability matrix' { Get-TableFeatureMatrix }
if (-not $FeatureMatrix) { $FeatureMatrix = @{ Basic = (New-Object 'System.Collections.Generic.HashSet[string]'); Aux = (New-Object 'System.Collections.Generic.HashSet[string]'); Source = 'unavailable' } }

Write-Rule 'Discovery'
$work = New-Object System.Collections.Generic.List[object]
foreach ($sub in $chosen) {
    $wsList = @(Invoke-Step ("Workspaces in {0}" -f $(if ($sub.Name.Length -gt 34) { $sub.Name.Substring(0, 34) } else { $sub.Name })) {
            Set-AzContext -SubscriptionId $sub.Id -TenantId $sub.TenantId -WarningAction SilentlyContinue | Out-Null
            (Invoke-Arm "/subscriptions/$($sub.Id)/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01").value
        })
    foreach ($w in $wsList) { $work.Add(@{ Sub = $sub; Ws = $w }) }
}
if (-not $work.Count) { Write-Line '  No Log Analytics workspaces found in the selected subscription(s).' 'Yellow'; return }
Write-Host ('  ✔ {0} workspace(s) to analyse' -f $work.Count) -ForegroundColor Green

$i = 0; $lastSub = $null
foreach ($item in $work) {
    $i++
    try {
        if ($lastSub -ne $item.Sub.Id) { Set-AzContext -SubscriptionId $item.Sub.Id -TenantId $item.Sub.TenantId -WarningAction SilentlyContinue | Out-Null; $lastSub = $item.Sub.Id }
        Invoke-WorkspaceAnalysis -ws $item.Ws -sub $item.Sub -Index $i -Total $work.Count
    }
    catch { Write-Host ("  ✖ Analysis failed for {0}: {1}" -f $item.Ws.name, $_.Exception.Message) -ForegroundColor Red; $script:StepErrors.Add("$($item.Ws.name): $($_.Exception.Message)") }
}

# ---------- Cross-workspace consolidation ----------
foreach ($g in ($AllSummary | Where-Object { $_.CommitmentGBPerDay -eq 0 -and $_.AnalyticsAvgGBPerDay -lt 100 } | Group-Object Subscription, Location)) {
    $sumGB = ($g.Group | Measure-Object AnalyticsAvgGBPerDay -Sum).Sum
    if ($g.Count -ge 2 -and $sumGB -ge 100) {
        $s30 = $sumGB * 30 * $script:Price * 0.15
        $script:AllFindings.Add((New-Finding -Ws "(consolidation) $($g.Group[0].Subscription) / $($g.Group[0].Location)" -Sub $g.Group[0].Subscription -Sev 'High' -Cat 'Pricing' -Title "Combine $($g.Count) workspaces to reach a commitment tier" -Detail ("Together these workspaces ingest ~{0:N0} GB/day of Analytics data but none reaches the 100 GB/day tier alone. Consolidating (or using a dedicated cluster) unlocks ~15% discount: ~{1}/month. Check RBAC, data residency and table-level access needs first." -f $sumGB, (Format-Usd $s30)) -Saving $s30 -Action 'Plan workspace consolidation or a dedicated cluster; validate access-control and residency requirements.' -Effort 'High'))
    }
}

# ---------- Executive summary ----------
Write-Host; Write-Rule 'Executive summary' 'Magenta'
$totSpend = [math]::Round((($AllSummary | Measure-Object EstMonthlyUSD -Sum).Sum), 2)
$totSave = [math]::Round((($AllFindings | Where-Object { $_.CountInTotal -and $_.Severity -ne 'Info' } | Measure-Object EstMonthlySavingUSD -Sum).Sum), 2)
$totPct = if ($totSpend -gt 0) { [math]::Round(100 * $totSave / $totSpend) } else { 0 }
$hi = @($AllFindings | Where-Object Severity -eq 'High').Count; $me = @($AllFindings | Where-Object Severity -eq 'Medium').Count; $lo = @($AllFindings | Where-Object Severity -eq 'Low').Count
Write-Box 'Overview' @(
    ('Workspaces analysed   {0}   across {1} subscription(s)' -f $AllSummary.Count, @($AllSummary | Select-Object -ExpandProperty Subscription -Unique).Count),
    ('Estimated spend       {0} / month  ({1}-day window, USD)' -f (Format-Usd $totSpend), $Days),
    ('Potential saving      {0} / month  (~{1}% of spend, indicative)' -f (Format-Usd $totSave), $totPct),
    ('Findings              {0} high  ·  {1} medium  ·  {2} low' -f $hi, $me, $lo)
) 'Cyan'
$topF = @($AllFindings | Where-Object { $_.CountInTotal -and $_.EstMonthlySavingUSD -gt 0 } | Sort-Object EstMonthlySavingUSD -Descending | Select-Object -First 6)
if ($topF.Count) {
    Write-Host; Write-Host '  Top opportunities' -ForegroundColor Magenta
    $n = 0; foreach ($f in $topF) { $n++; Write-Host ('   {0}. ' -f $n) -NoNewline -ForegroundColor DarkGray; Write-Host ('{0,9}/mo ' -f (Format-Usd $f.EstMonthlySavingUSD)) -NoNewline -ForegroundColor Green; Write-Host $f.Title -NoNewline -ForegroundColor White; Write-Host ('  [{0}]' -f $f.Workspace) -ForegroundColor DarkGray }
}
if ($script:StepErrors.Count) { Write-Host; Write-Host ('  ⚠ {0} step(s) were skipped (permissions or timeouts). Run with -Verbose for details.' -f $script:StepErrors.Count) -ForegroundColor Yellow; $script:StepErrors | ForEach-Object { Write-Verbose $_ } }

# ---------- Exports ----------
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$AllSummary | Select-Object * -ExcludeProperty Daily, DayLabels, TopTables, TopResources | Export-Csv (Join-Path $OutputFolder 'workspaces.csv') -NoTypeInformation
$AllTables | Export-Csv (Join-Path $OutputFolder 'tables.csv') -NoTypeInformation
$AllFindings | Export-Csv (Join-Path $OutputFolder 'recommendations.csv') -NoTypeInformation
@{ generated = (Get-Date).ToString('s'); days = $Days; pricePerGB = $PricePerGB; workspaces = $AllSummary; findings = $AllFindings } | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutputFolder 'report.json') -Encoding UTF8
$htmlPath = Join-Path $OutputFolder 'report.html'
New-HtmlReport | Set-Content -Path $htmlPath -Encoding UTF8
Write-Host
Write-Box 'Reports' @("Folder  $OutputFolder", 'Files   report.html · recommendations.csv · workspaces.csv · tables.csv · report.json', ('Elapsed {0:N0}s' -f $swTotal.Elapsed.TotalSeconds)) 'Green'
if (-not $NoOpen -and $env:OS -eq 'Windows_NT') { Start-Process $htmlPath }
