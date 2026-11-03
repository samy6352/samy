# AVD Cost Assessment

A read-only PowerShell script that reviews **Azure Virtual Desktop cost components only**, one subscription at a time, and produces a single Excel report (CSV fallback).

## Quick start

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/samy6352/samy/master/avd-cost-assessment/AVD-CostAssessment.ps1 -OutFile AVD-CostAssessment.ps1
.\AVD-CostAssessment.ps1
```

Works in PowerShell 7, Windows PowerShell 5.1 and Azure Cloud Shell. Required modules (`Az.Accounts`, `Az.ResourceGraph`, `ImportExcel`) are installed for the current user automatically.

1. Sign in (browser, device code fallback, or managed identity in Cloud Shell).
2. Pick a subscription by number, ID or name. Review its results on screen.
3. Enter the next subscription, or press Enter to finish and build the report.

| Option | Purpose |
|---|---|
| `-SubscriptionIds <id,name>` | Review specific subscriptions without prompts |
| `-All` | Review every accessible enabled subscription |
| `-TenantId <guid>` | Sign in to a specific tenant |
| `-OutputPath <folder>` | Report folder (default `.\AVD-Assessment-Output`) |
| `-NoOpen` | Do not open the report when finished |

## Access and safety

Needs **Reader** on the subscriptions. Nothing is modified. Queries run against Azure Resource Graph only.

## What it checks

- **Scaling:** no or disabled scaling plan, BreadthFirst load balancing, Start VM on Connect off for personal pools.
- **Session hosts:** stopped-not-deallocated, idle running hosts, unhealthy or stale hosts, unassigned personal hosts, stale registrations.
- **Licensing and sizing:** missing Windows licence type (Hybrid Benefit), older VM generations, Premium OS disks, mixed sizes in a pool.
- **AVD resource groups:** unattached disks, old snapshots, public IPs on session hosts, Premium or geo-redundant FSLogix storage.
- **Commitments:** reservation / savings plan candidates by VM size and region.
- **Azure Advisor:** cost recommendations touching session hosts or AVD resource groups.

## Report

`Summary`, `Findings` (High to Low), `HostPools`, `SessionHosts`, `ScalingPlans`, `Storage`.

## Limits

Findings are point-in-time configuration checks, not utilisation metrics. Validate licensing entitlement and workload patterns before acting. CPU/memory right-sizing is not covered.
