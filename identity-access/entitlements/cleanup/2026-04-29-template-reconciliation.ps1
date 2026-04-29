<#
.SYNOPSIS
    One-shot reconciliation of RBAC template accounts to eliminate variance
    in three normalized role definitions.

.DESCRIPTION
    Applies the AD-side fixes agreed on 2026-04-29 to close the variance
    blocks in:

        Lab_Operations-Supervisor_Lab_Specimen_Processing
        Sales-Account_Manager
        Sales-Territory_Manager

    Decisions captured here:

        Lab_Operations-Supervisor_Lab_Specimen_Processing
            - rbac_sls is redundant (mistitled). Delete it.
            - rbac_slsp becomes the sole template; its current memberships
              (Duo Lab Ops, Lab Assistants, MH WLAN Access) become baseline.

        Sales-Account_Manager
            - MH WLAN Access and SalesForceUsers are baseline for all AMs.
            - Add to rbac_am1 and rbac_am3 (rbac_am2 already has them).

        Sales-Territory_Manager
            - rbac_tm1 was cloned from an AM template:
                * Remove BTC_AM (AM-scoped, drift on TM template)
                * Add BTC_TM (the role's canonical group)
            - LSA Territory Managers (DL) is baseline; add to rbac_tm1, rbac_tm2.
            - MH Reps is baseline; add to rbac_tm3.

    After this script applies cleanly, re-run the snapshot exporter and
    Convert-EntitlementSnapshot.ps1; all three role files should regenerate
    without a variance block.

.PARAMETER Apply
    Switch. When omitted (default), every change runs under -WhatIf and only
    previews. Pass -Apply to actually mutate AD.

.EXAMPLE
    .\2026-04-29-template-reconciliation.ps1            # preview only
    .\2026-04-29-template-reconciliation.ps1 -Apply     # commit changes
#>
[CmdletBinding()]
param(
    [switch]$Apply
)

#Requires -Modules ActiveDirectory
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cmn = @{ WhatIf = (-not $Apply); Confirm = $false }

# ---------- Group DNs (full DN avoids any CN ambiguity) ----------
$g_MHWLAN  = 'CN=MH WLAN Access,OU=Security Groups,DC=mlabs,DC=com'
$g_SFUsers = 'CN=SalesForceUsers,OU=Security Groups,DC=mlabs,DC=com'
$g_BTC_AM  = 'CN=BTC_AM,OU=Security Groups,DC=mlabs,DC=com'
$g_BTC_TM  = 'CN=BTC_TM,OU=Security Groups,DC=mlabs,DC=com'
$g_MHReps  = 'CN=MH Reps,OU=Security Groups,DC=mlabs,DC=com'
$dl_LSA_TM = 'CN=LSA Territory Managers,OU=Distribution Groups,DC=mlabs,DC=com'

# ---------- Sales: Account Manager ----------
# am2 already has these; bring am1, am3 up to baseline.
foreach ($u in 'rbac_am1','rbac_am3') {
    Add-ADGroupMember -Identity $g_MHWLAN  -Members $u @cmn
    Add-ADGroupMember -Identity $g_SFUsers -Members $u @cmn
}

# ---------- Sales: Territory Manager ----------
# tm1 was cloned from an AM template - drop AM drift, add canonical TM group.
Remove-ADGroupMember -Identity $g_BTC_AM  -Members 'rbac_tm1' @cmn
Add-ADGroupMember    -Identity $g_BTC_TM  -Members 'rbac_tm1' @cmn

# Universalize TM-baseline groups across all three templates.
Add-ADGroupMember    -Identity $dl_LSA_TM -Members 'rbac_tm1','rbac_tm2' @cmn
Add-ADGroupMember    -Identity $g_MHReps  -Members 'rbac_tm3' @cmn

# ---------- Lab Ops: delete redundant Supervisor template ----------
# Run last so rbac_sls is still around if any earlier step needs context.
Remove-ADUser -Identity 'rbac_sls' @cmn

Write-Host ('Apply mode: {0}' -f $Apply.IsPresent) -ForegroundColor Cyan

# ---------- Post-apply verification (manual) ----------
# 'rbac_am1','rbac_am2','rbac_am3','rbac_tm1','rbac_tm2','rbac_tm3','rbac_slsp' |
#     ForEach-Object {
#         $u = Get-ADUser $_ -Properties MemberOf, Title
#         [pscustomobject]@{
#             Sam    = $u.SamAccountName
#             Title  = $u.Title
#             Groups = $u.MemberOf.Count
#         }
#     } | Format-Table -AutoSize
# Get-ADUser -Filter "SamAccountName -eq 'rbac_sls'"   # expect: no output
