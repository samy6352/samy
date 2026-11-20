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
function New-SvgSpark([double[]]$v, [int]$w = 260, [int]$h = 44) {
    if (-not $v -or $v.Count -lt 2) { return '' }
    $m = ($v | Measure-Object -Maximum).Maximum; if ($m -le 0) { $m = 1 }
    $pts = for ($i = 0; $i -lt $v.Count; $i++) { '{0:N1},{1:N1}' -f ($i * $w / ($v.Count - 1)), ($h - 3 - ($v[$i] / $m) * ($h - 8)) }
    ('<svg width="{0}" height="{1}" viewBox="0 0 {0} {1}"><polyline fill="none" stroke="#2f80ed" stroke-width="2" points="{2}"/><polyline fill="rgba(47,128,237,.12)" stroke="none" points="0,{1} {2} {0},{1}"/></svg>' -f $w, $h, ($pts -join ' '))
}
function New-HtmlReport {
    $sb = New-Object System.Text.StringBuilder
    $e = { param($x) ConvertTo-HtmlText $x }
    $tot = ($AllSummary | Measure-Object EstMonthlyUSD -Sum).Sum
    $sav = ($AllSummary | Measure-Object PotentialSavingUSD -Sum).Sum
    $savC = [math]::Round($sav + (@($AllFindings | Where-Object { $_.Workspace -like '(consolidation)*' -and $_.CountInTotal }) | Measure-Object EstMonthlySavingUSD -Sum).Sum, 2)
    $pct = if ($tot -gt 0) { [math]::Round(100 * $savC / $tot) } else { 0 }
    $high = @($AllFindings | Where-Object Severity -eq 'High').Count
    $css = @'
*{box-sizing:border-box}body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6fa;color:#1b2430}
header{background:linear-gradient(120deg,#0b1f3a,#12467a 60%,#1b6ec2);color:#fff;padding:28px 40px}
header h1{margin:0 0 4px;font-size:26px;letter-spacing:.3px}header p{margin:0;opacity:.85;font-size:13px}
main{padding:24px 40px;max-width:1280px;margin:auto}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin:-34px 0 24px}
.kpi{background:#fff;border-radius:10px;padding:14px 16px;box-shadow:0 2px 10px rgba(16,40,80,.1);border-top:3px solid #2f80ed}
.kpi b{display:block;font-size:24px}.kpi span{font-size:12px;color:#5b6b7f;text-transform:uppercase;letter-spacing:.5px}
.kpi.g{border-top-color:#27ae60}.kpi.r{border-top-color:#eb5757}.kpi.y{border-top-color:#f2c94c}
h2{margin:30px 0 10px;font-size:18px;border-left:4px solid #2f80ed;padding-left:10px}
table{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;overflow:hidden;font-size:13px;box-shadow:0 1px 6px rgba(16,40,80,.07)}
th{background:#eef2f8;text-align:left;padding:8px 10px;font-size:12px;color:#40526b;text-transform:uppercase;letter-spacing:.4px}
td{padding:8px 10px;border-top:1px solid #edf0f5;vertical-align:top}
.chip{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
.High{background:#eb5757}.Medium{background:#f2994a}.Low{background:#2d9cdb}.Info{background:#9aa5b5}
.save{color:#1e8e4e;font-weight:700;white-space:nowrap}
.ws{background:#fff;border-radius:12px;box-shadow:0 2px 10px rgba(16,40,80,.08);padding:18px 22px;margin:18px 0}
.wshead{display:flex;justify-content:space-between;align-items:center}.wshead h3{margin:0}.wshead small{color:#6b7b90;font-weight:400}
.score{font-size:22px;font-weight:800;border-radius:50%;width:56px;height:56px;display:flex;align-items:center;justify-content:center;color:#fff}
.sg{background:#27ae60}.sy{background:#e0a800}.sr{background:#eb5757}.sn{background:#9aa5b5;font-size:13px}
.mini{display:flex;gap:26px;flex-wrap:wrap;margin:10px 0;font-size:13px;color:#40526b}.mini b{color:#1b2430}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin:12px 0}
.bar{display:flex;align-items:center;gap:8px;font-size:12px;margin:4px 0}.bar .n{width:190px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar .t{flex:1;background:#eaeef5;height:10px;border-radius:5px}.bar .t i{display:block;height:10px;border-radius:5px;background:#2f80ed}
.bar .v{width:150px;color:#5b6b7f;text-align:right}
details{margin-top:6px}summary{cursor:pointer;color:#12467a;font-size:12px}
pre{background:#0f1b2d;color:#d6e4ff;padding:10px 12px;border-radius:6px;font-size:12px;white-space:pre-wrap;word-break:break-all;margin:6px 0 0}
.note{font-size:12px;color:#5b6b7f}footer{padding:20px 40px;color:#7a899c;font-size:12px}
@media(max-width:900px){.cols{grid-template-columns:1fr}main,header{padding:18px}}
'@
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Log Analytics Cost Intelligence</title><style>' + $css + '</style></head><body>')
    [void]$sb.AppendLine(('<header><h1>Log Analytics Cost Intelligence</h1><p>Generated {0:yyyy-MM-dd HH:mm} &middot; window: last {1} days &middot; currency: USD &middot; PAYG basis {2}/GB &middot; table matrix: {3}</p></header><main>' -f (Get-Date), $Days, (Format-Usd $script:Price), (& $e $FeatureMatrix.Source)))
    [void]$sb.AppendLine(('<div class="kpis"><div class="kpi"><b>{0}</b><span>Subscriptions</span></div><div class="kpi"><b>{1}</b><span>Workspaces</span></div><div class="kpi y"><b>{2}</b><span>Est. monthly spend</span></div><div class="kpi g"><b>{3}</b><span>Potential saving / month ({4}%)</span></div><div class="kpi r"><b>{5}</b><span>High-priority findings</span></div></div>' -f @($AllSummary | Select-Object -ExpandProperty Subscription -Unique).Count, $AllSummary.Count, (Format-Usd $tot), (Format-Usd $savC), $pct, $high))

    # Top opportunities
    $top = @($AllFindings | Where-Object { $_.CountInTotal -and $_.EstMonthlySavingUSD -gt 0 } | Sort-Object EstMonthlySavingUSD -Descending | Select-Object -First 10)
    [void]$sb.AppendLine('<h2>Top savings opportunities</h2>')
    if ($top.Count) {
        [void]$sb.AppendLine('<table><tr><th>#</th><th>Saving / mo</th><th>Priority</th><th>Workspace</th><th>Opportunity</th><th>Effort</th></tr>')
        $n = 0; foreach ($f in $top) { $n++; [void]$sb.AppendLine(('<tr><td>{0}</td><td class="save">{1}</td><td><span class="chip {2}">{2}</span></td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f $n, (Format-Usd $f.EstMonthlySavingUSD), $f.Severity, (& $e $f.Workspace), (& $e $f.Title), $f.Effort)) }
        [void]$sb.AppendLine('</table><p class="note">Savings are indicative and not strictly additive (e.g. a pricing-tier change is evaluated on current volume).</p>')
    }
    else { [void]$sb.AppendLine('<p class="note">No quantified savings found above the materiality threshold - the environment looks efficient.</p>') }

    # League table
    [void]$sb.AppendLine('<h2>Workspace league table</h2><table><tr><th>Subscription</th><th>Workspace</th><th>Region</th><th>SKU</th><th>GB</th><th>Avg GB/day</th><th>Est. $/mo</th><th>Saving $/mo</th><th>Score</th></tr>')
    foreach ($s in ($AllSummary | Sort-Object EstMonthlyUSD -Descending)) {
        [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}{4}</td><td>{5:N2}</td><td>{6:N3}</td><td>{7}</td><td class="save">{8}</td><td>{9}</td></tr>' -f (& $e $s.Subscription), (& $e $s.Workspace), $s.Location, $s.Sku, $(if ($s.CommitmentGBPerDay) { " ($($s.CommitmentGBPerDay) GB/d)" } else { '' }), $s.BillableGB, $s.AvgGBPerDay, (Format-Usd $s.EstMonthlyUSD), (Format-Usd $s.PotentialSavingUSD), $(if ($null -ne $s.EfficiencyScore) { $s.EfficiencyScore } else { 'n/a' })))
    }
    [void]$sb.AppendLine('</table>')

    # Cross-workspace findings
    $cross = @($AllFindings | Where-Object { $_.Workspace -like '(consolidation)*' })
    if ($cross.Count) {
        [void]$sb.AppendLine('<h2>Cross-workspace opportunities</h2><table><tr><th>Priority</th><th>Scope</th><th>Opportunity</th><th>Saving / mo</th></tr>')
        foreach ($f in $cross) { [void]$sb.AppendLine(('<tr><td><span class="chip {0}">{0}</span></td><td>{1}</td><td><b>{2}</b><br>{3}</td><td class="save">{4}</td></tr>' -f $f.Severity, (& $e $f.Workspace), (& $e $f.Title), (& $e $f.Detail), (Format-Usd $f.EstMonthlySavingUSD))) }
        [void]$sb.AppendLine('</table>')
    }

    # Workspace details
    [void]$sb.AppendLine('<h2>Workspace details</h2>')
    foreach ($s in ($AllSummary | Sort-Object EstMonthlyUSD -Descending)) {
        $key = "$($s.Workspace) [$($s.ResourceGroup)]"
        $sc = $s.EfficiencyScore; $scCls = if ($null -eq $sc) { 'sn' } elseif ($sc -ge 80) { 'sg' } elseif ($sc -ge 50) { 'sy' } else { 'sr' }
        [void]$sb.AppendLine(('<section class="ws"><div class="wshead"><h3>{0} <small>{1} &middot; {2} &middot; {3}</small></h3><div class="score {4}">{5}</div></div>' -f (& $e $s.Workspace), (& $e $s.ResourceGroup), $s.Location, (& $e $s.Subscription), $scCls, $(if ($null -ne $sc) { $sc } else { 'n/a' })))
        [void]$sb.AppendLine(('<div class="mini"><span>SKU <b>{0}{1}</b></span><span>Retention <b>{2}d</b></span><span>Daily cap <b>{3}</b></span><span>Ingested <b>{4:N2} GB</b></span><span>Peak <b>{5:N2} GB</b> ({6})</span><span>Est. <b>{7}/mo</b></span><span>Saving <b class="save">{8}/mo</b></span></div>' -f $s.Sku, $(if ($s.CommitmentGBPerDay) { " ($($s.CommitmentGBPerDay) GB/d)" } else { '' }), $s.RetentionDays, $s.DailyCap, $s.BillableGB, $s.PeakGB, $s.PeakDay, (Format-Usd $s.EstMonthlyUSD), (Format-Usd $s.PotentialSavingUSD)))
        if ($s.BillableGB -gt 0) {
            [void]$sb.AppendLine('<div class="cols"><div><div class="note">Daily analytics ingestion (GB)</div>' + (New-SvgSpark $s.Daily) + '<div style="margin-top:8px" class="note">Top tables</div>')
            foreach ($t in $s.TopTables) { [void]$sb.AppendLine(('<div class="bar"><span class="n" title="{0}">{0}</span><span class="t"><i style="width:{1}%"></i></span><span class="v">{1}% &middot; {2:N3} GB &middot; {3} &middot; {4}</span></div>' -f (& $e $t.Table), $t.PctOfTotal, $t.IngestedGB, (Format-Usd $t.EstMonthlyUSD), $t.Plan)) }
            [void]$sb.AppendLine('</div><div><div class="note">Top resources (7 days)</div>')
            if ($s.TopResources.Count) { foreach ($r in $s.TopResources) { [void]$sb.AppendLine(('<div class="bar"><span class="n" title="{0}">{1}</span><span class="v" style="flex:1">{2:N3} GB &middot; {3}</span></div>' -f (& $e $r.ResourceId), (& $e $r.Resource), $r.GB7d, (& $e $r.Tables))) } }
            else { [void]$sb.AppendLine('<div class="note">Not collected.</div>') }
            [void]$sb.AppendLine('</div></div>')
        }
        $fs = @($AllFindings | Where-Object { $_.Workspace -eq $key } | Sort-Object @{ e = { @{ High = 0; Medium = 1; Low = 2; Info = 3 }[$_.Severity] } }, @{ e = 'EstMonthlySavingUSD'; Descending = $true })
        if ($fs.Count) {
            [void]$sb.AppendLine('<table><tr><th>Priority</th><th>Category</th><th>Finding</th><th>Saving / mo</th><th>Effort</th></tr>')
            foreach ($f in $fs) {
                $act = if ($f.Action) { '<details><summary>How to implement</summary><pre>' + (& $e $f.Action) + '</pre></details>' } else { '' }
                [void]$sb.AppendLine(('<tr><td><span class="chip {0}">{0}</span></td><td>{1}</td><td><b>{2}</b><br>{3}{4}</td><td class="save">{5}</td><td>{6}</td></tr>' -f $f.Severity, $f.Category, (& $e $f.Title), (& $e $f.Detail), $act, $(if ($f.EstMonthlySavingUSD -gt 0) { Format-Usd $f.EstMonthlySavingUSD } else { '-' }), $f.Effort))
            }
            [void]$sb.AppendLine('</table>')
        }
        [void]$sb.AppendLine('</section>')
    }
    $paygTxt = Format-Usd $script:Price
    [void]$sb.AppendLine(('<h2>Method and assumptions</h2><ul class="note"><li>Billable ingestion from the workspace <code>Usage</code> table (UTC days, last {0} days). Costs shown in USD.</li><li>Analytics ingestion priced at {1}/GB (pay-as-you-go) or the commitment-tier effective rate; tier discounts approximated at 15-30% (100-5000 GB/day) and evaluated against <b>actual daily volumes</b> (days below the commitment still pay the commitment).</li><li>Basic ~{2}/GB, Auxiliary ~{3}/GB, interactive retention beyond free period ~{4}/GB-month, archive ~{5}/GB-month (list prices scaled to your PAYG rate).</li><li>Basic/Auxiliary eligibility comes from Microsoft''s published table feature matrix ({6}).</li><li>Free retention: 31 days for Analytics tables, 90 days for Application Insights tables.</li><li>Estimates are indicative. Validate in Azure Cost Management and the Azure pricing calculator before changing production workspaces.</li></ul><p class="note">Sources: Microsoft Learn - Azure Monitor cost optimization, Log Analytics cost calculations, table plans and table feature support.</p></main><footer>Log Analytics Cost Intelligence v{7}</footer></body></html>' -f $Days, $paygTxt, (Format-Usd ($BasicListPerGB * $script:Scale)), (Format-Usd ($AuxListPerGB * $script:Scale)), (Format-Usd ($RetentionListPerGBMonth * $script:Scale)), (Format-Usd ($ArchiveListPerGBMonth * $script:Scale)), (& $e $FeatureMatrix.Source), $script:Version))
    $sb.ToString()
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
else { $chosen = @(Select-Interactive -Items $subs -Label { "{0}   ({1})" -f $_.Name, $_.Id } -Title ("Select subscription(s) to analyse - {0} available" -f $subs.Count) -Multi) }
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
