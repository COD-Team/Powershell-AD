<#

    .DESCRIPTION
        Script runs across all computers on the DOMAIN for Bitlocker Compliance, also checks TPM Module, FIPS Compliance, BIOS and Local Policy Settings. 

    .EXAMPLE
        Option 1
        1. Command Prompt (Admin) "powershell -Executionpolicy Bypass -File PATH\Bitlocker.ps1"
    
    .EXAMPLE
        Option 2
        1. Run the set-executionpolicy unrestricted or Set-ExecutionPolicy RemoteSigned
        2. Run Bitlocker.ps1 as administrator

    .OUTPUTS
        Report found under $logPath below, default is c:\COD-Logs\DOMAINNAME\DATETIME

    .NOTES
        See README.md (Requires WinRM to be enabled)

    .NOTES
        Encryption Method is not returning, Running latest Win10/Server2016. "Manage-BDE -Status" does not return values either.
        Does return for Standalone Computers, but not Domain Computers. 

    .FUNCTIONALITY
        PowerShell Language
        Active Directory
    
    .Link
    https://github.com/COD-Team/Powershell-AD

#>

Clear-Host

# Get Domain Name, Creates a DomainName Folder to Store Reports
$ComputerDomain = (Get-WmiObject win32_computersystem).domain

#### Using Comment (On/Off) choose $DomainComputers you want to use, 3 options

#option 1 = Scans AD and returns all Computers Names
$DomainComputers = Get-ADComputer -Filter {OperatingSystem -like "Windows*"} -Properties Name | Select-Object -ExpandProperty Name 

#option 2 = Randomly select which DomainComputers get scanned, Adjust $rcount
<#
$rCount = 2
$DomainComputers = Get-Random -InputObject (Get-ADComputer -Filter {OperatingSystem -like "Windows*"} -Properties Name | Select-Object -ExpandProperty Name ) -Count $rCount
#>

#option 3 = Specific Computers, Update Array.
#$DomainComputers = ('Computer1', 'Computer2')

# Where the Logs will be stored, Adjust as needed UNC Paths will also work to save in your Network Admin Share
#$logpath = "\\SERVER\SHARENAME\COD-Logs\$ComputerDomain\$(get-date -format "yyyyMMdd-hhmmss")"
$logpath = "C:\COD-Logs\$ComputerDomain\$(get-date -format "yyyyMMdd-hhmmss")"
    If(!(test-path $logpath))
    {
          New-Item -ItemType Directory -Force -Path $logpath
    }

#OutputLog is the name if the file for all the results. 
$OutputLog = "$logpath\BitLocker.log"

#This Function will execute based on $DomainComputers Option and/or if they are $Online
Function GetBitlocker 
{

    # Gets all the Bitlocker information for ALL drives.
    $GetBL = Get-BitLockerVolume  -ErrorAction SilentlyContinue | Select-Object ComputerName, Mountpoint, EncryptionMethod, AutoUnlockEnabled, AutoUnlockKeyStored, Metadataversion, VolumnStatus, ProtectionStatus, LockStatus, EncryptionPercentage, WipePercentage, VolumnType, CapacityGB, KeyProtector

    # Gets FIPS Algorithm Policy (Disabled/Enabled)
    $FIPS = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name 'Enabled' -ErrorAction SilentlyContinue | Select-Object -expandproperty Enabled

    # Gets all Registry Settings for Bitlocker, Allows you to compare settings to actual. 
    $GetFVE = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -ErrorAction SilentlyContinue | Select-Object UseAdvancedStartup, EnableBDEWithNoTPM, UseTPM, UseTPMPIN, UseTPMKey, UseTPMKeyPIN, MinimumPIN, EncryptionMethodWithXtsOs, EncryptionMethodWithXtsFdv, EncryptionMethodWithXtsRdv

    # Gets TPM Information
    $GetTPM = Get-TPM

    # Gets BIOS information applicable to BitLocker and Computer Type
    $BIOSInfo= Get-WmiObject -Class Win32_Bios -ErrorAction SilentlyContinue

    # This Section is all Reporting
    $Report=[PSCustomObject] [ordered]@{
        'Hostname'= $env:COMPUTERNAME
        'Computer Type' = if ($BIOSInfo.SerialNumber -like 'VM*') {'Virtual Computer'} else {'Physical Computer'}
        'RegistrySettings' = '#################'
        'FIPS' = Switch ($FIPS) 
            {
                0 {'FIPS Disabled'}
                1 {'FIPS Enabled'}
                Default {'No FIPS Settings Found'}
            }

        'UseAdvancedStartup' = Switch ($GetFVE.UseAdvancedStartup)
            {
                0 {'Disabled'}
                1 {'Enabled'}
                Default {'No Settings Found'}
            }

        'EnableBDEWithNoTPM' = Switch ($GetFVE.EnableBDEWithNoTPM)
            {
                0 {'Disabled'}
                1 {'Enabled'}
                Default {'No Settings Found'}
            }

        'UseTPM' = Switch ($GetFVE.UseTPM)
            {
                0 {'Do not allow TPM'}
                1 {'Require TPM'}
                2 {'Allow TPM'}
                Default {'No Settings Found'}
            }

        'UseTPMPIN' = Switch ($GetFVE.UseTPMPIN)
            {
                0 {'Do not allow startup PIN with TPM'}
                1 {'Require startup PIN with TPM'}
                2 {'Allow startup PIN with TPM'}
                Default {'No Settings Found'}
            }

        'UseTPMKey' = Switch ($GetFVE.UseTPMKey)
            {
                0 {'Do not allow startup KEY with TPM'}
                1 {'Require startup KEY with TPM'}
                2 {'Allow startup KEY with TPM'}
                Default {'No Settings Found'}

            }

        'UseTPMKeyPIN' = Switch ($GetFVE.UseTPMKeyPIN)
            {
                0 {'Do not allow startup KEY and PIN with TPM'}
                1 {'Require startup KEY and PIN with TPM'}
                2 {'Allow startup KEY and PIN with TPM'}
                Default {'No Settings Found'}

            }

        'MinimumPIN' = Switch ($GetFVE.MinimumPIN)
            {
                {$_ -ge 1 -and $_ -le 3} {'Pin=' + $_ + ' Is less than Min 4'}
                {$_ -ge 4 -and $_ -le 20} {'Pin=' + $_ + ' is between Min 4 and Max 20'}
                {$_ -ge 21} {'Pin=' + $_ + ' Exceeds Max of 20'}
                Default {'No Settings Found'}
            }

        'EncryptionMethodWithXtsOs' = Switch ($GetFVE.EncryptionMethodWithXtsOs)
            {
                0 {'UNSPECIFIED'}
                1 {'AES_128_WITH_DIFFUSER'}
                2 {'AES_256_WITH_DIFFUSER'}
                3 {'AES_128'}
                4 {'AES_256'}
                5 {'HARDWARE_ENCRYPTION'}
                6 {'AES_256'}
                7 {'XTS_AES_256'}
                Default {'No Settings Found'}
            }

        'EncryptionMethodWithXtsFdv' =  Switch ($GetFVE.EncryptionMethodWithXtsFdv)
            {
                0 {'UNSPECIFIED'}
                1 {'AES_128_WITH_DIFFUSER'}
                2 {'AES_256_WITH_DIFFUSER'}
                3 {'AES_128'}
                4 {'AES_256'}
                5 {'HARDWARE_ENCRYPTION'}
                6 {'AES_256'}
                7 {'XTS_AES_256'}
                Default {'No Settings Found'}
            }

        'EncryptionMethodWithXtsRdv' = Switch ($GetFVE.EncryptionMethodWithXtsRdv)
            {
                0 {'UNSPECIFIED'}
                1 {'AES_128_WITH_DIFFUSER'}
                2 {'AES_256_WITH_DIFFUSER'}
                3 {'AES_128'}
                4 {'AES_256'}
                5 {'HARDWARE_ENCRYPTION'}
                6 {'AES_256'}
                7 {'XTS_AES_256'}
                Default {'No Settings Found'}
            }

        'TPMPresent' = Switch ($GetTPM.TPMPresent)
            {
                'False' {'TPM Not Present'}
                'True' {'TPM Present'}
                Default {'No TPM Settings Found'}
            }

        'TPMReady' = Switch ($GetTPM.TPMReady)
            {
                'False' {'TPM Not Ready'}
                'True' {'TPM Ready'}
                Default {'No TPM Settings Found'}
            }

        'TPMEnabled' = Switch ($GetTPM.TPMEnabled)
            {
                'False' {'TPM Not Enabled'}
                'True' {'TPM Enabled'}
                Default {'No TPM Settings Found'}
            }

        'TPMActivated' = Switch ($GetTPM.TPMActivated)
            {
                'False' {'TPM Not Activated'}
                'True' {'TPM Activated'}
                Default {'No TPM Settings Found'}
            }

        'ManufacturerVersion' =  $GetTPM.ManufacturerVersion

        'Bitlocker Device Settings' = '#################'
    } 

    # Returns Bitlocker settings, no reporting formatting from above, returns all Bitlocker settings
    $BLReport = If ($null -eq $GetBL) {'Bitlocker Not Avialable on '+ $env:computername} else {$GetBL} 

    # $Report includes all items in Report EXCEPT Bitlocker
    $Report

    # $BLReport returns ALL Bitlocker from ALL Drives, did not feel the need to seperate as a sub report due to enumeration of drives
    $BLReport
    Write-Output '------------------------------------------------------------------------------' #| Out-File -Append $OutputLOG
}
## END OF GetBitlocker FUNCTION

Measure-Command {

    # This section tests all computers in $DomainComputers Array for accessability (Online/Offline) Produces $Online Array
    $GetOnline = Invoke-command –ComputerName $DomainComputers -ErrorAction SilentlyContinue –scriptblock {[pscustomobject]@{ result = (Get-Service -name "winRM").count}}

        $Online =  $GetOnline | Select-Object -ExpandProperty PSComputerName

        $Offline = Compare-Object -ReferenceObject $DomainComputers -DifferenceObject $Online | Select-Object -ExpandProperty InputObject 

        #Display to Screen
        if ($Offline -ge 1) {
            Write-Host -fore red 'Computers Offline' -Separator "`n" 
            Write-Host -fore red '-----------------' -Separator "`n" 
            Write-Host -fore red $Offline -Separator "`n" 
            Write-Host -fore red '' -Separator "`n"
            }

        if ($Online -ge 1) {
            Write-Host -fore green 'Computers Online' -Separator "`n" 
            Write-Host -fore green '-----------------' -Separator "`n"
            Write-Host -fore green $online -Separator "`n" 
            }

        #Write to File
        Write-Output 'Computers Offline' | Out-File -Append $OutputLOG
        $Offline | Out-File -Append $OutputLOG
        Write-Output '' | Out-File -Append $OutputLOG
        Write-Output 'Computers Online' | Out-File -Append $OutputLOG
        $Online | Out-File -Append $OutputLOG

# Uses the $Online Array to execute GetBitlocker Function on all Computers Online only
Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock ${Function:GetBitlocker} | Out-File -Append $OutputLOG

write-host -fore green "LOG saved to: $OutputLOG" 
write-host -fore green "Script Completed"
}

$text = @"
   _____ ____  _____    _                                                     
  / ____/ __ \|  __ \  (_)         /\                                         
 | |   | |  | | |  | |  _ ___     /  \__      _____  ___  ___  _ __ ___   ___ 
 | |   | |  | | |  | | | / __|   / /\ \ \ /\ / / _ \/ __|/ _ \| '_ ` _ \ / _ \
 | |___| |__| | |__| | | \__ \  / ____ \ V  V /  __/\__ \ (_) | | | | | |  __/
  \_____\____/|_____/  |_|___/ /_/    \_\_/\_/ \___||___/\___/|_| |_| |_|\___|

"@

for ($i=0;$i -lt $text.length;$i++) {
if ($i%2) {
 $c = "red"
}
elseif ($i%5) {
 $c = "yellow"
}
elseif ($i%7) {
 $c = "green"
}
else {
   $c = "white"
}
write-host $text[$i] -NoNewline -ForegroundColor $c
}

Start-Process notepad.exe $OutputLog -NoNewWindow