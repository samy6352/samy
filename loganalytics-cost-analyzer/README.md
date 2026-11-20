# Log Analytics Cost Intelligence

Interactive, **read-only** PowerShell tool that analyses Azure Monitor Log Analytics workspaces and produces a prioritised, quantified cost-saving plan (USD).

## Run
```powershell
Install-Module Az.Accounts -Scope CurrentUser
irm https://raw.githubusercontent.com/samy6352/samy/master/loganalytics-cost-analyzer/LogAnalytics-CostAnalyzer.ps1 -OutFile LogAnalytics-CostAnalyzer.ps1
.\LogAnalytics-CostAnalyzer.ps1
```
Arrow-key picker: type to filter, Space to select several subscriptions, Ctrl+A for all, Enter to confirm.

Non-interactive: `.\LogAnalytics-CostAnalyzer.ps1 -SubscriptionId <id> -Days 30 -PricePerGB 2.76 -NoOpen`

Needs Reader on the subscription and Log Analytics Reader on the workspaces.

## What it checks
- Billable ingestion by table and by resource, daily trend, spikes and week-over-week growth
- Pricing: PAYG vs commitment tiers evaluated on your **actual daily volumes** (after table optimisations), legacy SKUs, cross-workspace consolidation
- Table plans: Basic/Auxiliary eligibility from Microsoft's live table-feature matrix, with savings estimate
- Collection tuning playbook per table (Perf, Syslog, ContainerLogV2, AppTraces, AzureDiagnostics, SecurityEvent, ...)
- Retention vs archive economics, idle/new workspaces, missing caps/alerts
- Per finding: estimated monthly saving, effort, and a ready-to-run `az` command / DCR action
- Workspace efficiency score and executive summary

## Output
`report.html` (executive report), `recommendations.csv`, `workspaces.csv`, `tables.csv`, `report.json` in `LA-CostReport-<timestamp>`.

Parameters: `-Days`, `-PricePerGB`, `-MinMonthlyCostUSD`, `-SubscriptionId`, `-AllSubscriptions`, `-SkipResourceBreakdown`, `-OutputFolder`, `-NoOpen`.

Prices are approximate list prices scaled to the customer's PAYG rate; validate in Azure Cost Management before changing production.
