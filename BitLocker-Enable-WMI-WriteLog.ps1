#Requires -Version 3.0
#Requires -RunAsAdministrator

## Quick check if the drive is FullyDecrypted. 
Try {if ($((Get-WmiObject -Query "Select * from Win32_EncryptableVolume where (DriveLetter = `"$env:SystemDrive`")" -Namespace 'root\CIMv2\Security\MicrosoftVolumeEncryption' -ErrorAction Stop).GetConversionStatus().ConversionStatus) -ne 0) {Return}} Catch {}

function Write-ScriptLog
{
    param (
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Message,
        [Parameter(Mandatory=$false,Position=2)]
        [ValidateSet("Information","Warning","Error")]
        [string]$LogType = "Information",
        [Parameter(Mandatory=$false,Position=3)]
        [string]$LogFile = $(if ($Script:LogFile) {$Script:LogFile})
    )
    
    ## Setting a default LogFile location if one isn't set
    if ((-not($LogFile)) -or (-not(Split-Path -Path $LogFile -Parent))) {
        Write-Warning -Message "LogFile wasn't specified or does not include a valid path. Generating a log name and defining path."
        if ($PSCommandPath) {
            [string]$LogDir = $PSScriptRoot
            [string]$LogName = ((Get-Item $PSCommandPath).BaseName) + ".log"
        } else {
            [string]$LogDir = $PWD
            [string]$LogName = (Get-Date -Format yyyyMMdd) + "-" + (Get-Date -Format HHmmss) + ".log"
        }
        [string]$Script:LogFile = Join-Path -Path $LogDir -ChildPath $LogName;$LogFile = $Script:LogFile
        Write-Warning -Message "LogFile is $LogFile"
    } else {
        [string]$LogDir = (Split-Path -Path $LogFile -Parent)
        [string]$LogName = (Split-Path -Path $LogFile -Leaf)
    }
    
    ## Create the log if it doesn't exist
    if (-not(Test-Path -Path $LogFile)) {
        if (-not(Test-Path -Path "$LogDir")) {
            # Create the log directory
            New-Item -Path (Split-Path -Path "$LogDir" -Parent) -Name (Split-Path -Path "$LogDir" -Leaf) -ItemType Directory -Force -ErrorAction Stop | Out-Null
            # Creating the log file
            New-Item -Path "$LogDir" -Name $LogName -ItemType File -ErrorAction Stop | Out-Null
        }
    }
    
    ## Defining the required variables to create a CMTrace compatible log file
    [string]$CMTraceFormat = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="{7}">'
    [string]$CMTraceSource = $(if ($PSCommandPath) {Get-Item $PSCommandPath | Select-Object -ExpandProperty BaseName} else {Write-Output "ISE"})
    [string]$CMTraceLogDate = (Get-Date -Format "MM-dd-yyyy").ToString()
    [string]$CMTraceTimeZoneOffset = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes
    [string]$CMTraceLogTime = ((Get-Date -Format "HH:mm:ss.fff").ToString()) + $CMTraceTimeZoneOffset
    [string]$CMTraceContext = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    if (-not($Script:Component)) {$Script:Component = "Not Defined"} else {$Component = $Script:Component}
    switch ($LogType) {
        "Information" { $CMTraceType = 1; $Color = "White" }
        "Warning" { $CMTraceType = 2; $Color = "DarkYellow" }
        "Error" { $CMTraceType = 3; $Color = "Red" }
    }
    $LogEntry = @($Message,$CMTraceLogTime,$CMTraceLogDate,$Component,$CMTraceContext,$CMTraceType,$PID,$CMTraceSource)
    [string]$Output = $CMTraceFormat -f $LogEntry
    Add-Content -Value $Output -Path $LogFile -ErrorAction Stop 
    Write-Host $Message -ForegroundColor $Color
    
}

Try {

    ## Setting initial variables
    [string]$LogFile = Join-Path -Path $env:windir -ChildPath 'Logs\BitLocker\EnableBitLocker.log'
    [string]$Component = 'Requirements'

    ## Validating requirements
    Write-ScriptLog -Message "[Check] OS Version"
    if (-not(Get-WmiObject -Query 'Select * from Win32_OperatingSystem Where ((ProductType != 1) and (Version like "10.0%" or Version like "6.[1-3]%")) or ((Version like "10.0%" or Version like "6.[2-3]%") and (Caption like "%Pro%" or Caption like "%Education%" or Caption like "%Enterprise%")) or ((Version like "6.1%") and (Caption like "%Enterprise%" or Caption like "%Ultimate%"))')) {
        Throw "BitLocker cannot be enabled on this version of Windows"
    }
    Write-ScriptLog -Message "[OK] OS Version"

    ## Creating a WMI Object for the Win32_TPM Class
    Write-ScriptLog -Message "[Check] Win32_TPM"
    $Win32_TPM = Get-WmiObject -Class Win32_TPM -Namespace 'root\CIMv2\Security\MicrosoftTPM' -ErrorAction Stop
    if (-not($Win32_TPM)) {Throw "[Failed] TPM not present"}
    Write-ScriptLog -Message "[OK] Win32_TPM"

    ## Creating a WMI Object for the Win32_EncryptableVolume Class for the System Drive
    Write-ScriptLog -Message "[Check] Win32_EncryptableVolume"
    $Win32_EncryptableVolume = Get-WmiObject -Query "Select * from Win32_EncryptableVolume where (DriveLetter = `"$env:SystemDrive`")" -Namespace 'root\CIMv2\Security\MicrosoftVolumeEncryption' -ErrorAction Stop
    if (-not($Win32_EncryptableVolume)) {Throw "Failed to create a WmiObject for drive $env:SystemDrive"}
    Write-ScriptLog -Message "[OK] Win32_EncryptableVolume"

    ## Checking to see if the hardware test has been requested -- https://docs.microsoft.com/en-us/windows/desktop/secprov/gethardwareteststatus-win32-encryptablevolume
    ## Results are 0 -- Not failed, not pending, 1 -- Failed, 2 -- Pending
    Write-ScriptLog -Message "[Check] Hardware Test Status"
    [string]$Result = $Win32_EncryptableVolume.GetHardwareTestStatus().TestStatus
    switch -Exact ($Result) {
        0 {Write-ScriptLog -Message "[OK] Not pending"}
        1 {Write-ScriptLog -Message "[Warning] Hardware test failed" -LogType Warning}
        2 {Write-ScriptLog -Message "[Warning] Pending restart - Exiting" -LogType Warning; Return}
        default {Throw "[Failed] Return code $Result unknown"}
    }
    
    ## Checking the conversion status -- https://docs.microsoft.com/en-us/windows/desktop/secprov/getconversionstatus-win32-encryptablevolume
    ## Results are 0 -- FullyDecrypted, 1 -- FullyEncrypted, 2 -- EncryptionInProgress, 3 -- DecryptionInProgress, 4 -- EncryptionPaused, 5 -- DecryptionPaused
    Write-ScriptLog -Message "[Check] Conversion Status"
    [string]$Result = $Win32_EncryptableVolume.GetConversionStatus().ConversionStatus
    switch -Exact ($Result) {
        0 {Write-ScriptLog -Message "[OK] FullyDecrypted"}
        1 {Write-ScriptLog -Message "[Warning] FullyEncrypted - Exiting"; Return}
        2 {Write-ScriptLog -Message "[Warning] EncryptionInProgress - Exiting"; Return}
        3 {Write-ScriptLog -Message "[Warning] DecryptionInProgress - Exiting"; Return}
        4 {Write-ScriptLog -Message "[Warning] EncryptionPaused - Exiting"; Return}
        5 {Write-ScriptLog -Message "[Warning] DecryptionPaused - Exiting"; Return}
        default {Throw "[Failed] Return code $Result unknown"}
    }

    ## Checking the TPM status
    Write-ScriptLog -Message "[Check] TPM Ownership"
    if (-not($($Win32_TPM.IsOwned().IsOwned))) {
        Write-ScriptLog -Message "[Warning] TPM is not owned" -LogType Warning
        Write-ScriptLog -Message "[Check] TPM - Is Ownership Allowed"
        if ($($Win32_TPM.IsActivated_InitialValue) -and $($Win32_TPM.IsEnabled_InitialValue) -and $($Win32_TPM.IsOwnershipAllowed().IsOwnershipAllowed)) {
            ## Taking ownership of the TPM -- https://docs.microsoft.com/en-us/windows/desktop/secprov/takeownership-win32-tpm
            [string]$Result = $Win32_TPM.TakeOwnership().ReturnValue
            switch -Exact ($Result) {
                0 {Write-ScriptLog -Message "[OK] Successfully took ownership of the TPM"}
                2147942487 {Throw "[Failed] The OwnerAuth parameter is not valid"}
                2150105108 {Throw "[Failed] An owner already exists on the TPM"}
                2150105123 {Throw "[Failed] No endorsement key can be found on the TPM"}
                2150105099 {Throw "[Failed] An owner cannot be installed on this TPM"}
                2150107139 {Throw "[Failed] The TPM is defending against dictionary attacks and is in a time-out period"}
                default {Throw "[Failed] Return code $Result unknown"}
            }
        } else {Throw "[Failed] Unable to take ownership of TPM - Validate that the TPM is enabled"}
    } else {
        Write-ScriptLog -Message "[OK] TPM Is Owned"
    }

    ## Checking to ensure that there is enough free space on the drive (not necessarily required but for Windows 7 especially it is recommended)
    Write-ScriptLog -Message "[Check] Disk Space > 20GB"
    [int]$Result = $([System.Math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Namespace 'root\CIMv2' -ErrorAction SilentlyContinue | Where-Object -FilterScript {$_.DeviceID -eq "$env:SystemDrive"} | Select-Object -ExpandProperty FreeSpace) / 1GB))
    if ($Result -lt 20) {
        Throw ("[Failed] " + [string]$Result + "GB of disk space remaining. Exiting.")
    }
    Write-ScriptLog -Message ("[OK] " + [string]$Result + "GB of disk space remaining")

    [string]$Component = 'KeyProtectors'
    ## Checking for numerical password key protectors - https://docs.microsoft.com/en-us/windows/desktop/secprov/getkeyprotectors-win32-encryptablevolume
    Write-ScriptLog -Message "[Check] Numerical Key Protectors"
    [string[]]$NumericKeyProtectorIDs = $Win32_EncryptableVolume.GetKeyProtectors(3).VolumeKeyProtectorID
    if (-not($NumericKeyProtectorIDs)) {
        Write-ScriptLog -Message "[OK] Numerical Key Protectors - Not Found"
        ## Adding a Numeric Key Protector - https://docs.microsoft.com/en-us/windows/desktop/secprov/protectkeywithnumericalpassword-win32-encryptablevolume
        Write-ScriptLog -Message "[Action] Add Numerical Key Protector"
        [string]$Result = $Win32_EncryptableVolume.ProtectKeyWithNumericalPassword().ReturnValue
        switch -Exact ($Result) {
            0 {Write-ScriptLog -Message "[Success] Added Numerical Key Protector"}
            2147942487 {Throw "[Failed] The NumericalPassword parameter does not have a valid format"}
            2150694912 {Throw "[Failed] The volume is locked"}
            Default {Throw "[Failed] Return code $Result unknown"}
        }
        [string[]]$NumericKeyProtectorIDs = $Win32_EncryptableVolume.GetKeyProtectors(3).VolumeKeyProtectorID
    }

    ## Saving the key protectors in Active Directory - https://docs.microsoft.com/en-us/windows/desktop/secprov/backuprecoveryinformationtoactivedirectory-win32-encryptablevolume
    foreach ($NumericKeyProtectorID in $NumericKeyProtectorIDs) {
        Write-ScriptLog -Message "[Action] Save KeyProtectorID $NumericKeyProtectorID to Active Directory"
        [string]$Result = $Win32_EncryptableVolume.BackupRecoveryInformationToActiveDirectory($NumericKeyProtectorID).ReturnValue
        switch -Exact ($Result) {
            0 {Write-ScriptLog -Message "[Success] Saved KeyProtectorID $NumericKeyProtectorID to Active Directory"}
            1 {Throw "[Failed] Group Policy does not permit the storage of recovery information to Active Directory"}
            2150694920 {Throw "[Failed] BitLocker is not enabled on the volume. Add a key protector to enable BitLocker"}
            2150694970 {Throw "[Failed] The specified key protector is not a numerical key protector. You must enter a numerical password protector"}
            default {Throw "[Failed] Return code $Result unknown"}
        }
    }

    ## Checking for a TPM key protector - https://docs.microsoft.com/en-us/windows/desktop/secprov/getkeyprotectors-win32-encryptablevolume
    Write-ScriptLog -Message "[Check] TPM Protector"
    if (-not($($Win32_EncryptableVolume.GetKeyProtectors(1).VolumeKeyProtectorID))) {
        Write-ScriptLog -Message "[OK] TPM Protector - Not Found."
        ## Adding a TPM Key Protector - https://docs.microsoft.com/en-us/windows/desktop/secprov/protectkeywithtpm-win32-encryptablevolume
        Write-ScriptLog -Message "[Action] Add TPM Protector"
        [string]$Result = $Win32_EncryptableVolume.ProtectKeyWithTPM().ReturnValue
        switch -Exact ($Result) {
            0 {Write-ScriptLog -Message "[Success] Added TPM Protector"}
            2150694912 {Throw "[Failed] The volume is locked"}
            2150121480 {Throw "[Failed] The TPM cannot secure the volume's encryption key because the volume does not contain the currently running operating system"}
            2147942487 {Throw "[Failed] The PlatformValidationProfile parameter is provided but its values are not within the known range, or it does not match the Group Policy setting currently in effect"}
            Default {Throw "[Failed] Return code $Result unknown"}
        }
    }

    [string]$Component = 'Enable'
    ## Enabling BitLocker - https://docs.microsoft.com/en-us/windows/desktop/secprov/encryptafterhardwaretest-win32-encryptablevolume
    Write-ScriptLog -Message "[Action] Enable BitLocker"
    [version]$OSVersion = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version
    if (($OSVersion -gt 6.1) -and ($OSVersion -lt (6.2))) {
        [string]$Result = $Win32_EncryptableVolume.EncryptAfterHardwareTest(0).ReturnValue
    } elseif ($OSVersion -gt 6.2) {
        [string]$Result = $Win32_EncryptableVolume.EncryptAfterHardwareTest(0,0x00000001).ReturnValue
    }
    switch -Exact ($Result) {
        0 {Write-ScriptLog -Message "[Success] Enabled BitLocker - Pending Hardware Test."}
        2147942487 {Throw "[Failed] The EncryptionMethod parameter is provided but is not within the known range or does not match the current Group Policy setting"}
        2150694958 {Throw "[Failed] No encryption key exists for the volume"}
        2150694942 {Throw "[Failed] The volume cannot be encrypted because this computer is configured to be part of a server cluster"}
        2150694971 {Throw "[Failed] No key protectors of the type `"TPM`", `"TPM And PIN`", `"TPM And PIN And Startup Key`", `"TPM And Startup Key`", or `"External Key`" can be found. The hardware test only involves the previous key protectors"}
        2150694969 {Throw "[Failed] The volume is partially or fully encrypted"}
        2150694952 {Throw "[Failed] The volume is a data volume. The hardware test applies only to volumes that can start the operating system. Run this method on the currently started operating system volume"}
        2150694956 {Throw "[Failed] No key protectors of the type `"Numerical Password`" are specified. The Group Policy requires a backup of recovery information to Active Directory Domain Services"}
    }

    # Checking for logged on users
    Write-ScriptLog -Message "[Check] Logged On Users"
    [string[]]$Restart = quser 2>&1 | Select-String 'No User exists for'
    if ($Restart) {
        Write-ScriptLog -Message "[OK ] No Users Found - Restarting"
        Start-Process -FilePath 'shutdown.exe' -ArgumentList '-r -t 120 -c "Restarting to begin encryption' -WindowStyle Hidden
    } else {
        Write-ScriptLog -Message "[Warning] Users Found - Skip Restart" -LogType Warning
    }

} Catch {
    ## Writing error to log
    if ($Error[0].Exception.Message) {
        [string]$ErrorMessage = $Error[0].Exception.Message
    } elseif ($Error[0].Message) {
        [string]$ErrorMessage = $Error[0].Message
    }
    Write-ScriptLog -Message $ErrorMessage -LogType Error
}

## Copying the log to a file share
Try {
    Copy-Item -Path $LogFile -Destination "\\SPECIFYFILESERVER\SPECIFYSHARE\SPECIFYFOLDER\$env:COMPUTERNAME-BitLocker.log" -Force -ErrorAction Stop
} Catch {
    ## Do nothing
}