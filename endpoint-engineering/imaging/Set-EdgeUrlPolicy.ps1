#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateNotNullOrEmpty()]
    [string]$TargetUser = 'KioskUser'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------- Configuration ----------
$BlockList = @('*')
$AllowList = @(
    'example.com'
    'login.microsoftonline.com'
    '*.microsoft.com'
)

# ---------- Resolve SID ----------
$userObj = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='$TargetUser'"
if (-not $userObj) { throw "User '$TargetUser' not found" }
$sid = $userObj.SID

# Verify hive is loaded
if (-not (Test-Path "Registry::HKEY_USERS\$sid")) {
    throw "Hive for $TargetUser ($sid) is not loaded -- is the user logged in?"
}

# ---------- Helper ----------
function Set-EdgeUrlListKey {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$SID,
        [Parameter(Mandatory)][string]$PolicyName,
        [string[]]$Urls
    )

    $regPath = "Registry::HKEY_USERS\$SID\SOFTWARE\Policies\Microsoft\Edge\$PolicyName"

    if (Test-Path $regPath) {
        if ($PSCmdlet.ShouldProcess($regPath, 'Remove existing key')) {
            Remove-Item -Path $regPath -Recurse -Force
        }
    }
    if ($PSCmdlet.ShouldProcess($regPath, "Create key with $($Urls.Count) entries")) {
        New-Item -Path $regPath -Force | Out-Null
        for ($i = 0; $i -lt $Urls.Count; $i++) {
            New-ItemProperty -Path $regPath -Name ($i + 1).ToString() -Value $Urls[$i] -PropertyType String -Force | Out-Null
        }
    }

    Write-Output "  $PolicyName : $($Urls.Count) entries"
}

# ---------- Apply ----------
Write-Output "Applying Edge URL policies for $TargetUser ($sid)..."
Set-EdgeUrlListKey -SID $sid -PolicyName 'URLBlocklist' -Urls $BlockList
Set-EdgeUrlListKey -SID $sid -PolicyName 'URLAllowlist' -Urls $AllowList
Write-Output 'Done.'
