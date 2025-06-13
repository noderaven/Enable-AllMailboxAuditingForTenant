<#
.SYNOPSIS
    Enables and configures mailbox auditing for all mailboxes in an Exchange Online tenant, skipping mailboxes that are already compliant.

.DESCRIPTION
    This script connects to Exchange Online and systematically processes all mailboxes
    (User, Shared, Room, and Equipment) to ensure mailbox auditing is enabled and
    configured with a standard set of audited actions for Owner, Admin, and Delegate access.

    This version is optimized to prevent throttling by first checking if a mailbox's audit
    settings are already compliant. It only applies changes if they are necessary, reducing
    the number of write operations.

    Key Features:
    - Automatically checks for and helps install the required ExchangeOnlineManagement module.
    - Connects to Exchange Online using modern authentication.
    - **Pre-flight Check:** Verifies that auditing is enabled at the organization level before proceeding.
    - Retrieves all recipient types using the modern 'Get-EXORecipient' cmdlet.
    - **Optimization:** Checks current audit settings using the modern 'Get-EXOMailbox' cmdlet and skips mailboxes that are already compliant.
    - **Detailed Logging:** Provides step-by-step compliance check details for transparency and easier debugging.
    - **Verification:** After applying changes, the script re-checks all settings to confirm they were applied successfully.
    - **Detailed Summary:** At the end, it provides a summary of exactly which settings were changed on which mailboxes.
    - Applies a comprehensive and customizable set of auditing rules.
    - Implements robust error handling to skip problematic mailboxes and continue processing.
    - Provides real-time progress updates in the console.
    - Creates a detailed transcript log of the entire operation in a 'Logs' subdirectory.
    - Summarizes the results upon completion.

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

# Set the maximum age for audit log entries in days. Default is 90 days for E3 licenses.
[int]$AuditLogAgeLimit = 90

# Define the actions to be audited for the mailbox owner.
# This list is refined based on direct cmdlet feedback for the Owner scope.
[string[]]$OwnerActions = @(
    "MailboxLogin",
    "HardDelete",
    "SoftDelete",
    "Update",
    "Create",
    "MoveToDeletedItems",
    "Move"
)

# Define the actions to be audited for administrators. These can be more comprehensive.
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
    # Check if the ExchangeOnlineManagement module is installed
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
                Stop-Transcript
                Exit
            }
        }
        else {
            Write-Error "Module installation declined. Script cannot continue."
            Stop-Transcript
            Exit
        }
    }

    # Check if already connected
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
            Stop-Transcript
            Exit
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
$changedMailboxes = New-Object System.Collections.Generic.List[PSCustomObject] # For detailed change summary
$startTime = Get-Date

# --- Connect to Exchange ---
Connect-ToExchangeOnline

# --- PRE-FLIGHT CHECK: Verify Organization Audit Setting ---
Write-Host "`nVerifying organization-wide audit settings..." -ForegroundColor Yellow
try {
    $orgConfig = Get-OrganizationConfig
    if ($orgConfig.AuditDisabled) {
        Write-Error "CRITICAL: Mailbox auditing is disabled at the organization level."
        Write-Error "Please enable it first by running 'Set-OrganizationConfig -AuditDisabled `$false' and then re-run this script."
        Stop-Transcript
        Exit
    }
    Write-Host "Organization-wide auditing is enabled." -ForegroundColor Green
}
catch {
    Write-Error "Failed to retrieve organization configuration. Please check permissions."
    Write-Error "Error details: $($_.Exception.ToString())"
    Stop-Transcript
    Exit
}

# --- Get All Mailboxes ---
Write-Host "`nRetrieving all mailboxes. This may take a while for large environments..." -ForegroundColor Yellow
try {
    # Get-EXORecipient is faster for large datasets. We filter for types that support Set-Mailbox auditing.
    $mailboxes = Get-EXORecipient -ResultSize Unlimited | Where-Object { $_.RecipientTypeDetails -in @('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox', 'DiscoveryMailbox') }
    $totalMailboxes = ($mailboxes | Measure-Object).Count
    Write-Host "Found $totalMailboxes mailboxes to process." -ForegroundColor Green
}
catch {
    Write-Error "Failed to retrieve mailboxes. Please check permissions."
    Write-Error "Error details: $($_.Exception.ToString())"
    Stop-Transcript
    Exit
}

# --- Process Each Mailbox ---
if ($totalMailboxes -gt 0) {
    $currentMailboxIndex = 0
    foreach ($mailbox in $mailboxes) {
        $currentMailboxIndex++
        $identity = $mailbox.PrimarySmtpAddress
        $displayName = $mailbox.DisplayName
        $progress = [math]::Round(($currentMailboxIndex / $totalMailboxes) * 100, 2)

        # A primary SMTP address is required to reliably identify the mailbox.
        if (-not $identity) {
            Write-Warning "-> FAILED: Mailbox '$displayName' does not have a PrimarySmtpAddress. Cannot process."
            $failureCount++
            continue
        }

        Write-Host "`n[$($currentMailboxIndex)/$($totalMailboxes) | $($progress)%] Processing: '$($displayName)' ($($identity))"

        try {
            # OPTIMIZATION: Get current settings to see if an update is needed.
            Write-Host "  Checking current audit settings..."
            $currentSettings = Get-EXOMailbox -Identity $identity -Properties AuditEnabled, AuditLogAgeLimit, AuditOwner, AuditAdmin, AuditDelegate
            
            $isCompliant = $true
            $changesToApply = New-Object System.Collections.Generic.List[string]

            # 1. Check if auditing is enabled
            Write-Host "    - Checking AuditEnabled..."
            if ($currentSettings.AuditEnabled -ne $true) {
                $isCompliant = $false
                $changesToApply.Add("AuditEnabled: Is '$($currentSettings.AuditEnabled)', will be set to 'True'.")
            } else {
                Write-Host "      ...Compliant." -ForegroundColor DarkGray
            }

            # 2. Check the log age limit using robust string comparison.
            Write-Host "    - Checking AuditLogAgeLimit..."
            $targetAgeLimitString = "$($AuditLogAgeLimit).00:00:00"
            if ("$($currentSettings.AuditLogAgeLimit)" -ne $targetAgeLimitString) {
                $isCompliant = $false
                $currentAgeDisplay = if ([string]::IsNullOrEmpty($currentSettings.AuditLogAgeLimit)) { "[not set]" } else { "$($currentSettings.AuditLogAgeLimit)" }
                $changesToApply.Add("AuditLogAgeLimit: Is '$currentAgeDisplay', will be set to '$targetAgeLimitString'.")
            } else {
                Write-Host "      ...Compliant." -ForegroundColor DarkGray
            }

            # 3. Check Owner actions
            Write-Host "    - Checking AuditOwner actions..."
            if (Compare-Object -ReferenceObject ($OwnerActions | Sort-Object) -DifferenceObject ($currentSettings.AuditOwner | Sort-Object)) {
                $isCompliant = $false
                $changesToApply.Add("AuditOwner: Actions are non-compliant and will be updated.")
            } else {
                Write-Host "      ...Compliant." -ForegroundColor DarkGray
            }

            # 4. Check Admin actions
            Write-Host "    - Checking AuditAdmin actions..."
            if (Compare-Object -ReferenceObject ($AdminActions | Sort-Object) -DifferenceObject ($currentSettings.AuditAdmin | Sort-Object)) {
                $isCompliant = $false
                $changesToApply.Add("AuditAdmin: Actions are non-compliant and will be updated.")
            } else {
                Write-Host "      ...Compliant." -ForegroundColor DarkGray
            }
            
            # 5. Check Delegate actions
            Write-Host "    - Checking AuditDelegate actions..."
            if (Compare-Object -ReferenceObject ($DelegateActions | Sort-Object) -DifferenceObject ($currentSettings.AuditDelegate | Sort-Object)) {
                $isCompliant = $false
                $changesToApply.Add("AuditDelegate: Actions are non-compliant and will be updated.")
            } else {
                Write-Host "      ...Compliant." -ForegroundColor DarkGray
            }

            # If the mailbox is not compliant, apply the necessary changes.
            if (-not $isCompliant) {
                Write-Host "-> Settings are not compliant. Applying changes:" -ForegroundColor Yellow
                
                foreach ($change in $changesToApply) {
                    Write-Host "  - $change" -ForegroundColor Yellow
                }

                $setMailboxParams = @{
                    Identity              = $identity
                    AuditEnabled          = $true
                    AuditLogAgeLimit      = $targetAgeLimitString # Use explicit TimeSpan string format
                    AuditOwner            = $OwnerActions
                    AuditAdmin            = $AdminActions
                    AuditDelegate         = $DelegateActions
                    ErrorAction           = 'Stop'
                    Confirm               = $false # Suppress confirmation prompt warning
                }
                Set-Mailbox @setMailboxParams

                Write-Host "-> Successfully applied configuration for '$($displayName)'." -ForegroundColor Green
                $successCount++

                # Add details to the summary log
                $changeLogEntry = [PSCustomObject]@{
                    DisplayName = $displayName
                    Identity    = $identity
                    Changes     = $changesToApply.ToArray() # Convert list to array for stable storage
                }
                $changedMailboxes.Add($changeLogEntry)
                
                # Pause only after a successful write operation.
                Start-Sleep -Milliseconds $ThrottleDelay

                # --- NEW: Full Verification Step ---
                Write-Host "  Verifying all settings after application..."
                $verificationPassed = $true
                try {
                    # Get all relevant properties at once for verification
                    $verifiedSettings = Get-EXOMailbox -Identity $identity -Properties AuditEnabled, AuditLogAgeLimit, AuditOwner, AuditAdmin, AuditDelegate

                    # 1. Verify AuditEnabled
                    if ($verifiedSettings.AuditEnabled -ne $true) {
                        $verificationPassed = $false
                        Write-Warning "  VERIFICATION FAILED: AuditEnabled is '$($verifiedSettings.AuditEnabled)', expected 'True'."
                    }

                    # 2. Verify AuditLogAgeLimit
                    if ("$($verifiedSettings.AuditLogAgeLimit)" -ne $targetAgeLimitString) {
                        $verificationPassed = $false
                        Write-Warning "  VERIFICATION FAILED: AuditLogAgeLimit is '$($verifiedSettings.AuditLogAgeLimit)', expected '$targetAgeLimitString'."
                    }

                    # 3. Verify AuditOwner actions
                    if (Compare-Object -ReferenceObject ($OwnerActions | Sort-Object) -DifferenceObject ($verifiedSettings.AuditOwner | Sort-Object)) {
                        $verificationPassed = $false
                        Write-Warning "  VERIFICATION FAILED: AuditOwner actions do not match the target configuration."
                    }

                    # 4. Verify AuditAdmin actions
                    if (Compare-Object -ReferenceObject ($AdminActions | Sort-Object) -DifferenceObject ($verifiedSettings.AuditAdmin | Sort-Object)) {
                        $verificationPassed = $false
                        Write-Warning "  VERIFICATION FAILED: AuditAdmin actions do not match the target configuration."
                    }

                    # 5. Verify AuditDelegate actions
                    if (Compare-Object -ReferenceObject ($DelegateActions | Sort-Object) -DifferenceObject ($verifiedSettings.AuditDelegate | Sort-Object)) {
                        $verificationPassed = $false
                        Write-Warning "  VERIFICATION FAILED: AuditDelegate actions do not match the target configuration."
                    }

                    # Final confirmation message based on verification outcome
                    if ($verificationPassed) {
                        Write-Host "-> Successfully confirmed application of all settings for '$($displayName)'." -ForegroundColor Green
                    } else {
                        Write-Error "-> Verification FAILED for one or more settings on '$($displayName)'. Please review the warnings above."
                    }
                }
                catch {
                    Write-Error "-> An error occurred during the verification step for '$($displayName)': $($_.Exception.Message)"
                }
            }
            else {
                Write-Host "-> Already compliant. Skipping." -ForegroundColor DarkGray
                $skippedCount++
            }
        }
        catch {
            # Catch errors for individual mailboxes so the script can continue
            Write-Warning "-> FAILED to process '$($displayName)'. See error below."
            Write-Warning "    Error: $($_.Exception.ToString())" # Log the full exception details
            $failureCount++
        }
    }
}
else {
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

# --- Detailed Change Summary ---
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
