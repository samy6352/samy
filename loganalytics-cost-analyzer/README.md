# Log Analytics Cost Analyzer

Read-only PowerShell utility: sign in to Azure, pick one or more subscriptions, and get a Log Analytics cost-optimisation report (USD).

## Prerequisites
- PowerShell 5.1+ or 7+
- `Install-Module Az.Accounts -Scope CurrentUser`
- Reader on the subscription and Log Analytics Reader on the workspaces

## Run
```powershell
irm https://raw.githubusercontent.com/samy6352/samy/master/loganalytics-cost-analyzer/LogAnalytics-CostAnalyzer.ps1 -OutFile LogAnalytics-CostAnalyzer.ps1
.\LogAnalytics-CostAnalyzer.ps1 -Days 30 -PricePerGB 2.76
```
At the subscription prompt enter `2`, `1,3` or `A` for all.

## Output
Console summary plus `workspaces.csv`, `tables.csv`, `recommendations.csv` and `report.html` in an `LA-CostReport-<timestamp>` folder.

Covers: ingestion by table/resource, daily peak, retention, table plans, daily cap, commitment-tier fit, Basic-plan candidates. Prices are approximate list prices; adjust `-PricePerGB` for the customer's agreement.
