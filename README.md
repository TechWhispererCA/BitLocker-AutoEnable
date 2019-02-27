# BitLocker-AutoEnable
A script to automatically enable BitLocker on Windows 7 or later. It is assumed the script will be deployed in a domain environment and the recovery key will be backed up to Active Directory. After successfully backing up the key, it will enable BitLocker and reboot (if no one is logged in). The TPM must be active in the BIOS but the script will take ownership if required. The script could be extended to prompt the user to enable the TPM if desired.

The main purpose of this script is to automatically enable BitLocker on devices regardless of how they are deployed and without requiring Microsoft BitLocker Admininistration and Monitoring (MBAM).

## BitLocker-Enable-WMI-WriteLog.ps1
The script to actually enable BitLocker on the operating system volume.

## Deploying with Group Policy

### WMI Filters
There are three WMI filters that should be used with Group Policy to scope the policy. The filters will target devices where the TPM is enabled in the BIOS and where BitLocker is not enabled on the system volume. If the Group Policy Management window is running as a standard user, the first two queries in the root\CIMv2\Security branch will generate an error about the namespace due to lack of permissions on the local device. This error can be ignored and will not be present if the Group Policy Management window is elevated.

1. Query to validate the TPM is Enabled.

Namespace:

``root\CIMv2\Security\MicrosoftTPM``

Query:

``Select * from Win32_TPM Where (IsActivated_InitialValue = "True") and (IsEnabled_InitialValue = "True")``

2. Query to validate BitLocker is not protecting the system volume.

Namespace:

``root\CIMv2\Security\MicrosoftVolumeEncryption``

Query:

``Select * from Win32_EncryptableVolume Where (DriveLetter = "C:") and (ProtectionStatus = "0")``

3. Query to validate the operating system is capable of enabling BitLocker.

Namespace:

``root\CIMv2``

Query:

``Select * from Win32_OperatingSystem Where ((ProductType != 1) and (Version like "10.0%" or Version like "6.[1-3]%")) or ((Version like "10.0%" or Version like "6.[2-3]%") and (Caption like "%Pro%" or Caption like "%Education%" or Caption like "%Enterprise%")) or ((Version like "6.1%") and (Caption like "%Enterprise%" or Caption like "%Ultimate%"))``

### Scheduled Task Settings (Computer Configuration)
Create a scheduled task with the following properties (adjusting as needed):

* Action: ``Replace``
* Description: ``Enable BitLocker``
* User Account: ``NT AUTHORITY\System``
* Run with highest privileges: Checked
* Triggers: ``At task creation/modification``
* Action: ``Start a program``
 * Program/Script : ``%windir%\System32\WindowsPowerShell\v1.0\powershell.exe``
 * Add arguments: ``-NonInteractive -ExecutionPolicy Bypass -File \\SPECIFYFILESERVER\SPECIFYFILESHARE\SPECIFYFOLDER\EnableBitLocker.ps1``
* Remove this item when it is no longer applied: ``Checked``