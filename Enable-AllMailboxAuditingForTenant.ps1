<#
.SYNOPSIS
    Enables and configures mailbox auditing for all mailboxes in an Exchange Online tenant, skipping mailboxes that are already compliant.

.DESCRIPTION
    This script connects to Exchange Online and systematically processes all mailboxes
    (User, Shared, Room, and Equipment) to ensure mailbox auditing is enabled and
    configured with a standard set of audited actions for Owner, Admin, and Delegate access.

    This version is highly optimized for performance in large tenants by fetching all
    mailbox data in a single call, reducing remote operations significantly.

    Key Features:
    - **High Performance:** Uses a single `Get-EXOMailbox` call to retrieve all mailboxes and properties, minimizing remote calls.
    - Automatically checks for and helps install the required ExchangeOnlineManagement module.
    - Connects to Exchange Online using modern authentication.
    - **Pre-flight Check:** Verifies that auditing is enabled at the organization level before proceeding.
    - **Optimization:** Processes mailboxes locally and only applies changes if they are necessary, reducing write operations.
    - **Detailed Logging:** Provides step-by-step compliance check details for transparency and easier debugging.
    - **Verification:** After applying changes, the script re-checks all settings to confirm they were applied successfully.
    - **Detailed Summary:** At the end, it provides a summary of exactly which settings were changed on which mailboxes.
    - **Type-Safe:** Uses [TimeSpan] objects for robust handling of the audit log age limit.
    - Implements robust error handling to skip problematic mailboxes and continue processing.
    - Creates a detailed transcript log of the entire operation in a 'Logs' subdirectory.

.NOTES
    Prerequisites:      Windows PowerShell 5.1 or later.
                        Permissions: The user running the script must have at least 'View-Only Organization Management'
                        and 'Mail Recipients' roles. 'Organization Management' is required to make changes.
    Advanced:           This script does not check for mailbox audit bypass associations set with
                        'Set-MailboxAuditBypassAssociation'. If auditing does not appear to work for
                        a specific account after running this script, check for a bypass association separately.

.EXAMPLE
    .\Enable-AllMailboxAuditingForTenant.ps1

    The script now automatically provides verbose output without needing the -Verbose switch.
#>

#region Configuration Variables
# --------------------------------------------------------------------------------------
# SCRIPT CONFIGURATION
# You can customize these variables to fit your organization's compliance requirements.
# --------------------------------------------------------------------------------------

# Set the maximum age for audit log entries in days. Default is 90 days.
[int]$AuditLogAgeLimitDays = 90

# Define the actions to be audited for the mailbox owner.
[string[]]$OwnerActions = @(
    "MailboxLogin",
    "HardDelete",
    "SoftDelete",
    "Update",
    "Create",
    "MoveToDeletedItems",
    "Move"
)

# Define the actions to be audited for administrators.
[string[]]$AdminActions = @(
    "HardDelete",
    "SoftDelete",
    "Update",
    "Create",
    "FolderBind",
    "SendAs",
    "SendOnBehalf",
    "MoveToDeletedItems"
)

# Define the actions to be audited for delegates.
[string[]]$DelegateActions = @(
    "HardDelete",
    "SoftDelete",
    "Update",
    "Create",
    "FolderBind",
    "SendAs",
    "SendOnBehalf",
    "MoveToDeletedItems"
)

# Brief pause in milliseconds between each mailbox WRITE operation to prevent throttling.
[int]$ThrottleDelay = 200

#endregion

#region Script Setup and Pre-flight Checks

# Suppress verbose output from the underlying EXO V2 module, but keep our own script's detailed output.
$VerbosePreference = "SilentlyContinue"

# --- Start Logging ---
$LogDirectory = Join-Path -Path $PSScriptRoot -ChildPath "Logs"
if (-not (Test-Path -Path $LogDirectory)) {
    Write-Host "Creating log directory at: $LogDirectory"
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}
$TranscriptLog = Join-Path -Path $LogDirectory -ChildPath "MailboxAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $TranscriptLog
Write-Host "Transcript logging started. Log file: `"$TranscriptLog`"" -ForegroundColor Green

# --- Function to Check and Connect to Exchange Online ---
function Connect-ToExchangeOnline {
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Warning "The ExchangeOnlineManagement PowerShell module is not installed."
        $installChoice = Read-Host "Do you want to install it now? (Y/N)"
        if ($installChoice -eq 'Y') {
            try {
                Write-Host "Installing ExchangeOnlineManagement module..." -ForegroundColor Yellow
                Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
                Write-Host "Module installed successfully." -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to install the module. Please install it manually and re-run the script."
                Write-Error "Error details: $($_.Exception.Message)"
                Stop-Transcript; Exit
            }
        }
        else {
            Write-Error "Module installation declined. Script cannot continue."
            Stop-Transcript; Exit
        }
    }

    $connection = Get-ConnectionInformation | Where-Object { $_.ModuleName -eq 'ExchangeOnlineManagement' }
    if ($connection) {
        Write-Host "Already connected to Exchange Online as $($connection.UserPrincipalName)." -ForegroundColor Cyan
    }
    else {
        Write-Host "Connecting to Exchange Online. Please authenticate if prompted." -ForegroundColor Yellow
        try {
            Connect-ExchangeOnline -ShowBanner:$false
        }
        catch {
            Write-Error "Failed to connect to Exchange Online. Please check your credentials and permissions."
            Write-Error "Error details: $($_.Exception.Message)"
            Stop-Transcript; Exit
        }
    }
    Write-Host "Successfully connected to Exchange Online." -ForegroundColor Green
}

#endregion

#region Main Processing Block

# --- Initialize Counters and Change Log ---
$totalMailboxes = 0
$successCount = 0
$failureCount = 0
$skippedCount = 0
$changedMailboxes = New-Object System.Collections.Generic.List[PSCustomObject]
$startTime = Get-Date
$targetAgeLimitTimeSpan = [TimeSpan]::FromDays($AuditLogAgeLimitDays) # Type-safe TimeSpan object

# --- Connect to Exchange ---
Connect-ToExchangeOnline

# --- PRE-FLIGHT CHECK: Verify Organization Audit Setting ---
Write-Host "`nVerifying organization-wide audit settings..." -ForegroundColor Yellow
try {
    $orgConfig = Get-OrganizationConfig
    if ($orgConfig.AuditDisabled) {
        Write-Error "CRITICAL: Mailbox auditing is disabled at the organization level."
        Write-Error "Please enable it first by running 'Set-OrganizationConfig -AuditDisabled `$false' and then re-run this script."
        Stop-Transcript; Exit
    }
    Write-Host "Organization-wide auditing is enabled." -ForegroundColor Green
}
catch {
    Write-Error "Failed to retrieve organization configuration. Please check permissions."
    Write-Error "Error details: $($_.Exception.ToString())"
    Stop-Transcript; Exit
}

# --- PERFORMANCE OPTIMIZATION: Get All Mailboxes in a Single Call ---
Write-Host "`nRetrieving all mailboxes and their audit settings. This may take a moment..." -ForegroundColor Yellow
try {
    $mailboxProperties = @(
        "PrimarySmtpAddress", "DisplayName", "AuditEnabled", "AuditLogAgeLimit",
        "AuditOwner", "AuditAdmin", "AuditDelegate"
    )
    $recipientTypeDetails = @(
        "UserMailbox", "SharedMailbox", "RoomMailbox", "EquipmentMailbox", "DiscoveryMailbox"
    )
    
    $mailboxes = Get-EXOMailbox -ResultSize Unlimited -Properties $mailboxProperties -RecipientTypeDetails $recipientTypeDetails
    $totalMailboxes = ($mailboxes | Measure-Object).Count
    Write-Host "Found $totalMailboxes mailboxes to process." -ForegroundColor Green
}
catch {
    Write-Error "Failed to retrieve mailboxes. Please check permissions."
    Write-Error "Error details: $($_.Exception.ToString())"
    Stop-Transcript; Exit
}

# --- Process Each Mailbox ---
if ($totalMailboxes -gt 0) {
    $currentMailboxIndex = 0
    foreach ($mailbox in $mailboxes) {
        $currentMailboxIndex++
        $identity = $mailbox.PrimarySmtpAddress
        $displayName = $mailbox.DisplayName
        $progress = [math]::Round(($currentMailboxIndex / $totalMailboxes) * 100, 2)

        if (-not $identity) {
            Write-Warning "-> FAILED: Mailbox with DisplayName '$displayName' does not have a PrimarySmtpAddress. Cannot process."
            $failureCount++; continue
        }

        Write-Host "`n[$($currentMailboxIndex)/$($totalMailboxes) | $($progress)%] Processing: '$($displayName)' ($($identity))"

        try {
            Write-Host "  Checking current audit settings..."
            $isCompliant = $true
            $changesToApply = New-Object System.Collections.Generic.List[string]

            # 1. Check AuditEnabled
            if ($mailbox.AuditEnabled -ne $true) {
                $isCompliant = $false
                $changesToApply.Add("AuditEnabled: Is '$($mailbox.AuditEnabled)', will be set to 'True'.")
            }

            # 2. Check AuditLogAgeLimit
            if ($mailbox.AuditLogAgeLimit -ne $targetAgeLimitTimeSpan) {
                $isCompliant = $false
                $currentAgeDisplay = if ($null -eq $mailbox.AuditLogAgeLimit) { "[not set]" } else { "$($mailbox.AuditLogAgeLimit)" }
                $changesToApply.Add("AuditLogAgeLimit: Is '$currentAgeDisplay', will be set to '$($targetAgeLimitTimeSpan)'.")
            }

            # 3. Check Owner actions (with null check)
            if (($null -ne $mailbox.AuditOwner) -and (Compare-Object -Ref ($OwnerActions | Sort-Object) -Diff ($mailbox.AuditOwner | Sort-Object))) {
                $isCompliant = $false
                $changesToApply.Add("AuditOwner: Actions are non-compliant and will be updated.")
            }

            # 4. Check Admin actions (with null check)
            if (($null -ne $mailbox.AuditAdmin) -and (Compare-Object -Ref ($AdminActions | Sort-Object) -Diff ($mailbox.AuditAdmin | Sort-Object))) {
                $isCompliant = $false
                $changesToApply.Add("AuditAdmin: Actions are non-compliant and will be updated.")
            }
            
            # 5. Check Delegate actions (with null check)
            if (($null -ne $mailbox.AuditDelegate) -and (Compare-Object -Ref ($DelegateActions | Sort-Object) -Diff ($mailbox.AuditDelegate | Sort-Object))) {
                $isCompliant = $false
                $changesToApply.Add("AuditDelegate: Actions are non-compliant and will be updated.")
            }

            if (-not $isCompliant) {
                Write-Host "-> Settings are not compliant. Applying changes:" -ForegroundColor Yellow
                $changesToApply | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }

                $setMailboxParams = @{
                    Identity              = $identity
                    AuditEnabled          = $true
                    AuditLogAgeLimit      = $targetAgeLimitTimeSpan
                    AuditOwner            = $OwnerActions
                    AuditAdmin            = $AdminActions
                    AuditDelegate         = $DelegateActions
                    ErrorAction           = 'Stop'
                    Confirm               = $false
                }
                Set-Mailbox @setMailboxParams

                Write-Host "-> Successfully applied configuration for '$($displayName)'." -ForegroundColor Green
                $successCount++

                $changedMailboxes.Add([PSCustomObject]@{
                    DisplayName = $displayName
                    Identity    = $identity
                    Changes     = $changesToApply.ToArray()
                })
                
                Start-Sleep -Milliseconds $ThrottleDelay

                # --- Verification Step ---
                Write-Host "  Verifying all settings after application..."
                $verificationPassed = $true
                try {
                    $verifiedSettings = Get-EXOMailbox -Identity $identity -Properties AuditEnabled, AuditLogAgeLimit, AuditOwner, AuditAdmin, AuditDelegate
                    
                    if ($verifiedSettings.AuditEnabled -ne $true) { $verificationPassed = $false; Write-Warning "  VERIFICATION FAILED: AuditEnabled" }
                    if ($verifiedSettings.AuditLogAgeLimit -ne $targetAgeLimitTimeSpan) { $verificationPassed = $false; Write-Warning "  VERIFICATION FAILED: AuditLogAgeLimit" }
                    if (Compare-Object -Ref ($OwnerActions | Sort) -Diff ($verifiedSettings.AuditOwner | Sort)) { $verificationPassed = $false; Write-Warning "  VERIFICATION FAILED: AuditOwner actions" }
                    if (Compare-Object -Ref ($AdminActions | Sort) -Diff ($verifiedSettings.AuditAdmin | Sort)) { $verificationPassed = $false; Write-Warning "  VERIFICATION FAILED: AuditAdmin actions" }
                    if (Compare-Object -Ref ($DelegateActions | Sort) -Diff ($verifiedSettings.AuditDelegate | Sort)) { $verificationPassed = $false; Write-Warning "  VERIFICATION FAILED: AuditDelegate actions" }

                    if ($verificationPassed) {
                        Write-Host "-> Successfully confirmed application of all settings for '$($displayName)'." -ForegroundColor Green
                    } else {
                        Write-Error "-> Verification FAILED for one or more settings on '$($displayName)'. Please review warnings."
                    }
                } catch {
                    Write-Error "-> An error occurred during verification for '$($displayName)': $($_.Exception.Message)"
                }
            } else {
                Write-Host "-> Already compliant. Skipping." -ForegroundColor DarkGray
                $skippedCount++
            }
        } catch {
            Write-Warning "-> FAILED to process '$($displayName)'. See error below."
            Write-Warning "    Error: $($_.Exception.ToString())"
            $failureCount++
        }
    }
} else {
    Write-Warning "No mailboxes were found to process."
}
#endregion

#region Finalization and Summary

$endTime = Get-Date
$duration = New-TimeSpan -Start $startTime -End $endTime

Write-Host "`n------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Processing Complete!" -ForegroundColor Cyan
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Duration: $($duration.Hours)h $($duration.Minutes)m $($duration.Seconds)s"
Write-Host "Total Mailboxes Found: $totalMailboxes"
Write-Host "Successfully Configured: $successCount" -ForegroundColor Green
Write-Host "Skipped (Already Compliant): $skippedCount" -ForegroundColor DarkGray
Write-Host "Failed to Configure: $failureCount" -ForegroundColor $(if ($failureCount -gt 0) { 'Red' } else { 'Green' })

if ($changedMailboxes.Count -gt 0) {
    Write-Host "`n------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "Detailed Change Summary for Modified Mailboxes" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    foreach ($entry in $changedMailboxes) {
        Write-Host "`nMailbox: $($entry.DisplayName) ($($entry.Identity))" -ForegroundColor White
        foreach ($change in $entry.Changes) {
            Write-Host "  - $change" -ForegroundColor Yellow
        }
    }
}

if ($failureCount -gt 0) {
    Write-Warning "`nSome mailboxes failed. Please review the transcript log for details:"
    Write-Warning $TranscriptLog
}

# --- Disconnect Session ---
$connection = Get-ConnectionInformation | Where-Object { $_.ModuleName -eq 'ExchangeOnlineManagement' }
if ($connection) {
    Write-Host "`nDisconnecting from Exchange Online..."
    Disconnect-ExchangeOnline -Confirm:$false
}

# --- Stop Logging ---
Stop-Transcript
Write-Host "Transcript logging stopped."

#endregion
