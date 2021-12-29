<#
    .DESCRIPTION
        Script Pulls from the Domain and all computers in the Domain for the following:
        
                
    .PARAMETER NAME
        No Parameters, but control Functions by commenting or uncommenting under $TASKS

    .OUTPUTS
        Report found under $logPath below, default is c:\COD-Logs\DOMAINNAME\DATETIME
    
    .EXAMPLE
        Option 1
        1. Command Prompt (Admin) "powershell -Executionpolicy Bypass -File PATH\Domain.ps1"

        Option 2
        1. Run the set-executionpolicy unrestricted or Set-ExecutionPolicy RemoteSigned
        2. Run Domain.ps1 as administrator

    .NOTES
        Encryption Method is not returning, Running latest Win10/Server2016. "Manage-BDE -Status" does not return values either.
        Does return for Standalone Computers, but not Domain Computers. 

        Author Perkins
        Last Update 12/12/21
    
        Powershell 5 or higher
        Run as Administrator
        Domain requires RSAT ActiveDriectory tools installed - DC has by Default (Error Checking in Place)
    
    .FUNCTIONALITY
        PowerShell Language
        Active Directory
    
    .Link
    https://github.com/COD-Team
    https://youtu.be/8qKRF7SqlOk
    See README.md

#>

$Tasks = @(
    ,"GetADComputers"    
    ,"GetWindowsVersion"
    ,"GetBiosInfo"
    ,"GetPowerShellVersion"
    ,"GetADusers"
    ,"GetLocalUsers"
    ,"GetADAdministrators"
    ,"GetLocalAdministrators" 
    ,"GetDomainUserGroups"
    ,"GetLocalGroup"
    ,"GetNetAccounts"
    ,"GetExecutionPolicy"
    ,"GetUSBActivity"    
    ,"GetPNPDevices"
    ,"GetPNPDeviceProperties"
    ,"GetAuditPol"
    ,"GetPortsandProcesses"
    ,"GetLocalPorts"                
    ,"GetTPM"
    ,"GetSMBShares"
    ,"GetDiskInfo"
    ,"GetPSDrives"
    ,"GetBitlocker"
    ,"GetWindowsCapability"
    ,"GetWindowsOptionalFeatures"
    ,"GetInstalledPrograms"
    ,"GetStartupPrograms"
    ,"GetScheduledTasks"
    ,"GetWindowsUpdates"
    ,"GetHotFix" 
    ,"GetRunningServices"
    ,"GetDomainGPObjects" 
    ,"GetGPResultantSetofPolicy"
    ,"GetGPResult"    
    ,"GetEventLogList"
    ,"GetFirewallProfile"
    ,"GetFirewallRules"
    #,"GetSystemInfo"               # Minimal Value as an assessor, SA's might have interest
    #,"GetComputerInfo"             # Minimal Value as an assessor, SA's might have interest
    #,"GetStoppedServices"          # Minimal Value as an assessor, Good Information for Incident Response
    #,"GetEventLog"                 # System log Only - Create Script specific for EventLogs
    #,"GetVolumes"                  # Minimal Value as an assessor, Good Information for Incident Response
    #,"GetHost"                     # Minimal Value as an assessor, Good Information for Incident Response
    #,"GetDependentServices"
    #,"GetDNSCache"
    #,"GetSecEdit"                  # Return a few settings with seperate script - Lockout Duration
    #,"GetDriverHash"               # Incident Response
    ,"OpenGPResultantSetofPolicy"   # Recommend keep toward bottom of execution to allow all files to be written. 
    ,"LaunchNotepad"
)


#Requires -RunAsAdministrator

$versionMinimum = [Version]'5.1.000.000'
    if ($versionMinimum -gt $PSVersionTable.PSVersion)
    { throw "This script requires PowerShell $versionMinimum" }

# If your computer is NOT on a Domain, Script will exit - Checkout Standalone.ps1 for non-domain computers
if ($env:computername  -eq $env:userdomain) 
    {
        Write-Host -fore red "$env:ComputerName is not joined to a Domain, Script Exiting" 
        Exit
    }

Measure-Command {
# Get Domain Name, Creates a DomainName Folder to Store Reports
$DomainName = (Get-WmiObject win32_computersystem).domain

# Get Computer Name
$ComputerName = $env:computername

# Path where the results will be written. Network Share Required and Accessible. 
$logpath = "\\DC2016\SHARES\COD-Logs\$DomainName\$(get-date -format "yyyyMMdd-hhmmss")"
    If(!(test-path $logpath))
    {
          New-Item -ItemType Directory -Force -Path $logpath
    }

# Counter for Write-Progress
$Counter = 0

# Logfile where all the results are dumped
$OutputFile = "$logpath\Master.log"

# Sets Header information for the Reports
Write-Output "[INFO] Running $PSCommandPath" | Out-File -Append $OutputFile
Write-Output (Get-Date) | Out-File -Append $OutputFile
Write-Output "POWERSHELL ASSESSMENT SCRIPT" | Out-File -Append $OutputFile
Write-Output "Executed Script from $ComputerName on Domain $DomainName" | Out-File -Append $OutputFile
Write-Output "------------------------------------------------------------------------------------------------------------------------" | Out-File -Append $OutputFile

# Return all Windows Computers from Active Directory
$DomainControllers = Get-ADDomainController | Select-Object Name

$DomainComputers = Get-ADComputer -Filter {OperatingSystem -like "Windows*"} -Properties Name, OperatingSystem | Select-Object Name, OperatingSystem 
# Only Scan computers listed in Array
#$DomainComputers = ('DC2016', 'DoDWin10')
# Randomly scan a set number of computers in the domain
#$DomainComputers = Get-Random -count 2 (Get-ADComputer -Filter {OperatingSystem -like "Windows*"} -Properties Name | Select-Object -ExpandProperty Name)

# This section tests all computers in $DomainComputers Array for Accessibility (Online/Offline) Produces $Online Array
$GetOnline = Invoke-command –ComputerName $DomainComputers.Name -ErrorAction SilentlyContinue –scriptblock {[pscustomobject]@{ result = (Get-Service -name "winRM").count}}
    $Online =  $GetOnline | Select-Object -ExpandProperty PSComputerName
    $Offline = Compare-Object -ReferenceObject $DomainComputers.Name -DifferenceObject $Online | Select-Object -ExpandProperty InputObject 

# Display to Screen all Domain Controllers
if ((Get-ADDomainController -filter * | Select-Object name | Measure-Object | Select-Object Count).count -ge 1) {
    Write-Host -fore Cyan 'Domain Controllers' -Separator "`n" 
    Write-Host -fore Cyan '-----------------' -Separator "`n"
    Write-Host -fore Cyan $DomainControllers -Separator "`n" 
    Write-Host '' -Separator "`n"
}
# Display to Screen all Computers not Accessible 
if ($Offline -ge 1) {
    Write-Host -fore red 'Computers Offline' -Separator "`n" 
    Write-Host -fore red '-----------------' -Separator "`n" 
    Write-Host -fore red $Offline -Separator "`n" 
    Write-Host -fore red '' -Separator "`n"
}
# Display to Screen all Computers Accessible, Script will execute functions on all computers listed
if ($Online -ge 1) {
    Write-Host -fore green 'Computers Online' -Separator "`n" 
    Write-Host -fore green '-----------------' -Separator "`n"
    Write-Host -fore green $online -Separator "`n" 
}

#Write to File
if ((Get-ADDomainController -filter * | Select-Object name | Measure-Object | Select-Object Count).count -ge 1) {
    Write-Output 'Domain Controllers' | Out-File -Append $OutputFile
    Write-Output '-----------------' | Out-File -Append $OutputFile
    $DomainControllers | Out-File -Append $OutputFile
    Write-Output '' | Out-File -Append $OutputFile
}
if ($Offline -ge 1) {
    Write-Output 'Computers Offline' | Out-File -Append $OutputFile
    Write-Output '-----------------' | Out-File -Append $OutputFile
    $Offline | Out-File -Append $OutputFile
    Write-Output '' | Out-File -Append $OutputFile
}
if ($Online -ge 1) {
    Write-Output 'Computers Online' | Out-File -Append $OutputFile
    Write-Output '-----------------' | Out-File -Append $OutputFile
    $Online | Out-File -Append $OutputFile
}
###################################################################################################################################################################
Function GetGPResultantSetofPolicy
{
    $Results = Invoke-Command -ComputerName $Online -ScriptBlock {Get-WindowsCapability -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0" -Online | Where-Object state -like Installed}

    Invoke-Command -ComputerName $Results.PSComputerName -ErrorAction SilentlyContinue -ScriptBlock {
        if (Get-Module -ListAvailable -Name GroupPolicy)
        {
            If(-Not(test-path $Using:logpath\$env:Computername))
            {
                New-Item -ItemType Directory -Force -Path $Using:logpath\$env:Computername
            }
            
            Get-GPResultantSetOfPolicy -ReportType Html -Path "$Using:logpath\$env:Computername\GPResults.html"
        }
    }

    $NoResults = Compare-Object -ReferenceObject $Online -DifferenceObject $Results.PSComputerName | Select-Object -ExpandProperty InputObject
    Write-Output "No Group Policy Results from $NoResults.$DomainName" | out-file -Append $OutputFile
    Write-Output "" | out-file -Append $OutputFile

    Write-Output "Group Policy Results Executed, open from links below " | out-file -Append $OutputFile
    foreach ($Computer in $Results.PSComputerName) {
        If (Test-Path -Path "$logpath\$Computer\GPResults.html") {
            Write-Output "$logpath\$Computer\GPResults.html" | out-file -Append $OutputFile
        }
    }
}
Function OpenGPResultantSetofPolicy 
{
    Start-Sleep -Seconds 10
    foreach ($Computer in $Online) {
        If (Test-Path -Path "$logpath\$Computer\GPResults.html") {
            Start-Process "$logpath\$Computer\GPResults.html"
        }
    }
}
Function GetAuditPol 
{
    Write-Output "AuditPol.exe /get /category:* if STIG compliant, Account Managment / Security Group Managment for Success and Failure, open from $logpath\$env:Computername\AuditPol.log" | out-file -Append $OutputFile
    Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {    

        If(!(test-path $Using:logpath\$env:Computername))
            {
              New-Item -ItemType Directory -Force -Path $Using:logpath\$env:Computername
            }    
        
        $command = "auditpol.exe"
        $arguments = "/get /category:*"
        $stdout = "$Using:logpath\$env:Computername\AuditPol.log"

        Write-Output "AuditPol - $env:computername" | out-file -Append $OutputFile
        Start-Process $command $arguments -NoNewWindow -Wait -RedirectStandardOutput $stdout
    }

    foreach ($Computer in $Online) {
        $reportpath = "$logpath\$Computer\AuditPol.log"
        Write-Output "AuditPol Settings for $Computer" | out-file -Append $OutputFile
        Write-Output "----------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
        Get-Content -Path $reportpath | Out-File -Append $OutputFile
        Write-Output "----------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
        }
}    
Function GetSecEdit 
{
    Write-Output "SecEdit, open from $logpath\$env:Computername\SecEdit.log" | out-file -Append $OutputFile
    Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {    

        If(!(test-path $Using:logpath\$env:Computername))
            {
                New-Item -ItemType Directory -Force -Path $Using:logpath\$env:Computername
            }    
                    
        $command = "secedit.exe"
        $stdout = "$Using:logpath\$env:Computername\SecEdit.log"
        $arguments = "/export /areas SECURITYPOLICY /cfg $stdout"

        Write-Output "SecEdit.exe /export /areas SECURITYPOLICY /cfg" | out-file -Append $OutputFile
        Start-Process $command $arguments -NoNewWindow -wait
        }

        foreach ($Computer in $Online) {
            $reportpath = "$logpath\$Computer\SecEdit.log"
            Write-Output "SecEdit Settings for $Computer" | out-file -Append $OutputFile
            Write-Output "----------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
            Get-Content -Path $reportpath | Out-File -Append $OutputFile
            Write-Output "----------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
            }
}
Function GetGPResult 
{
    Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {    

        If(!(test-path $Using:logpath\$env:Computername))
            {
                New-Item -ItemType Directory -Force -Path $Using:logpath\$env:Computername
            }    
    
        $command = "gpresult.exe"
        $stdout = "$Using:logpath\$env:Computername\GPResult.log"
        $arguments = "/R"

        Start-Process $command $arguments -NoNewWindow -wait -PassThru -RedirectStandardOutput $stdout
        }

    foreach ($Computer in $Online) {
        $reportpath = "$logpath\$Computer\GPResult.log"
        Write-Output "GPResults, open from $logpath\$Computer\GPResult.log" | out-file -Append $OutputFile
        Write-Output "GPResult Settings for $Computer" | out-file -Append $OutputFile
        Write-Output "----------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
        Get-Content -Path $reportpath | Out-File -Append $OutputFile
        Write-Output "----------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
        }
}
Function GetNetAccounts
{
    Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {    

        If(!(test-path $Using:logpath\$env:Computername))
            {
                New-Item -ItemType Directory -Force -Path $Using:logpath\$env:Computername
            }    
    
        $command = "net.exe"
        $stdout = "$Using:logpath\$env:Computername\NetAccounts.log"
        $arguments = "Accounts"

        #Write-Output "SecEdit.exe /export /areas SECURITYPOLICY /cfg" | out-file -Append $OutputFile
        Start-Process $command $arguments -NoNewWindow -wait -RedirectStandardOutput $stdout
    }
    foreach ($Computer in $Online) {
        $reportpath = "$logpath\$Computer\NetAccounts.log"
        Write-Output "NetAccounts, open from $logpath\$Computer\NetAccounts.log" | out-file -Append $OutputFile
        Write-Output "NetAccounts Settings for $Computer" | out-file -Append $OutputFile
        Write-Output "----------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
        Get-Content -Path $reportpath | Out-File -Append $OutputFile
        Write-Output "----------------------------------------------------------------------------------------------------" | out-file -Append $OutputFile
        }
}
Function GetDomainUserGroups 
{
    if (!(Get-Module -ListAvailable -Name ActiveDirectory))
        {
            Write-Output "Get-ADUsers - RSAT for Active Directory is not installed on this workstation" | out-file -Append $OutputFile
        }
        else 
        {
        Write-Output "List all Users and Domain Memberships" | out-file -Append $OutputFile
        $DomainUsers = Get-ADUser -Filter {(Enabled -eq $true)}
            foreach ($DomainUser in $DomainUsers) 
            {
                GET-ADUSER –Identity $DomainUser –Properties MemberOf | 
                    out-file -Append $OutputFile
            }
        }   
}
Function GetDomainGPObjects
{
    Write-Output "Get-GPOReport from $DomainName" | out-file -Append $OutputFile
    Get-GPOReport -All -Domain $DomainName -Server $DomainControllers.name -ReportType HTML -Path "$Logpath\DomainGPOjects.html"
    Write-Output "Open from $Logpath\DomainGPOjects.html" | out-file -Append $OutputFile
    Start-Process "$logpath\DomainGPOjects.html"
}
Function GetADusers 
{
    if (!(Get-Module -ListAvailable -Name ActiveDirectory))
        {
            Write-Output "Get-ADUsers - RSAT for Active Directory is not installed on this workstation" | out-file -Append $OutputFile
        }
        else 
        {
        Write-Output "Get-ADUser -Filter Enabled = $True -Properties LastLogonDate, passwordlastset, passwordneverexpires, enabled,lockedout" | out-file -Append $OutputFile
        Get-ADUser -Filter {(Enabled -eq $true)} -Properties PasswordNeverExpires, PasswordLastSet, LastLogondate, enabled, lockedout | 
            Select-Object Name, Enabled, LockedOut, 
                @{Name = 'Password Set'; E = {($_.PasswordLastSet).ToString('MM/dd/yyyy')}}, 
                @{name = 'Password Age'; E = {(new-timespan -start $(Get-date $_.PasswordLastSet) -end (get-date)).days}}, 
                @{Name = 'Last Logon'; E = {($_.LastLogondate).ToString('MM/dd/yyyy')}},
                @{Name = 'Last Logon Days'; E = {(new-timespan -start $(Get-date $_.LastLogondate) -end (get-date)).days}},
                PasswordNeverExpires | 
                Sort-Object 'Last Logon' | Format-Table | out-file -Append $OutputFile
        }
}
Function GetLocalAdministrators 
{
    Write-Output "Get Local Administrators" | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-LocalGroupMember Administrators}
    $Results | Select-Object PSComputerName, Name, ObjectClass, PrincipalSource | Sort-Object PrincipalSource, PSComputerName, Name, ObjectClass  | out-file -Append $OutputFile
}
Function GetEventLogList 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-WinEvent -ListLog * | Select-Object LogName, IsEnabled, Filesize, OldestRecordNumber, RecordCount}
    
    Write-Output "Lists all Event Logs Enabled" | out-file -Append $OutputFile
    $Results | Select-Object PSComputerName, LogName, IsEnabled, Filesize, OldestRecordNumber, RecordCount | Sort-Object PSComputerName, IsEnabled, LogName | Where-Object IsEnabled -eq $true | Format-Table | out-file -Append $OutputFile

    Write-Output "Lists all Event Logs Not Enabled" | out-file -Append $OutputFile
    $Results | Select-Object PSComputerName, LogName, IsEnabled | Sort-Object PSComputerName, IsEnabled, LogName | Where-Object IsEnabled -eq $false | Format-Table | out-file -Append $OutputFile
}
Function GetHotFix
{
    Write-Output "Get HotFixs" | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-HotFix}
    $Results | Select-Object PSComputerName, Description, HotFixID, 
        @{Name = 'InstalledOn'; E = {($_.InstalledOn).ToString('MM/dd/yyyy')}},
        InstalledBy | Format-Table | out-file -Append $OutputFile
}
Function GetADAdministrators 
{
    if (!(Get-Module -ListAvailable -Name ActiveDirectory))
        {
            Write-Output "Get-ADGroupMember - RSAT for Active Directory is not installed on this workstation" | out-file -Append $OutputFile
        }
        else 
        {
            Write-Output "Get-ADGroupMember -Identity Administrators -Recursive | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName"  | out-file -Append $OutputFile
            $(Get-ADGroupMember -Identity Administrators -Recursive | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName| out-file -Append $OutputFile)
        }
}
Function GetADComputers 
{
    if (!(Get-Module -ListAvailable -Name ActiveDirectory))
        {
            Write-Output "Get-ADComputer - RSAT for Active Directory is not installed on this workstation" | out-file -Append $OutputFile
        }
        else 
        {
            Write-Output "Get-ADComputer -Filter Name -Like * -Properties * | Select-Object Name, OperatingSystem, Enabled, LastLogon, DistinguishedName" | out-file -Append $OutputFile
            $(Get-ADComputer -Filter "Name -Like '*'" -Properties * | Select-Object Name, OperatingSystem, Enabled, 
                @{Name = 'Last Logon'; E = {($_.LastLogonDate).ToString('MM/dd/yyyy')}}, 
                DistinguishedName | Sort-Object -Property LastLogonDate | Format-Table | out-file -Append $OutputFile)
        }
}
Function GetDriverHash
{
    Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {
        If(!(test-path $Using:logpath\$env:Computername))
        {
                New-Item -ItemType Directory -Force -Path $Using:logpath\$env:Computername
        }
    Get-ChildItem C:\windows\system32\drivers -Recurse | Get-FileHash | Select-Object -Property Hash, Path | out-file -Append $Using:logpath\$env:Computername\DriverHash.txt
    Get-ChildItem C:\windows\SysWOW64 -Recurse | Get-FileHash | Select-Object -Property Hash, Path | out-file -Append $Using:logpath\$env:Computername\DriverHash.txt}

    Write-Output "Driver Hash Values Created, open from links below " | out-file -Append $OutputFile
    foreach ($Computer in $Online) {
        If (Test-Path -Path "$logpath\$Computer\DriverHash.txt") {
            Write-Output "$logpath\$Computer\DriverHash.txt" | out-file -Append $OutputFile
        }
    }
}
Function GetLocalUsers
{

    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {get-localuser | Where-Object enabled -EQ $True}

    $Results | Select-Object PSComputerName, Name, Enabled, 
            @{Name = 'Last Logon'; E = {($_.LastLogon).ToString('MM/dd/yyyy')}},
            @{Name = 'Last Logon Days'; E = {(new-timespan -start $(Get-date $_.LastLogon) -end (get-date)).days}},
            @{Name = 'Password Set'; E = {($_.PasswordLastSet).ToString('MM/dd/yyyy')}},
            @{Name = 'Password Expires'; E = {($_.PasswordExpires).ToString('MM/dd/yyyy')}},
            @{name = 'Password Age'; E = {(new-timespan -start $(Get-date $_.PasswordLastSet) -end (get-date)).days}}  | 
            Sort-Object PSComputerName, Name | Format-Table  | out-file -Append $OutputFile 
}
Function GetLocalPorts 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-NetTCPConnection -State Listen}

    $Results | Select-Object PSComputerName, LocalAddress, LocalPort, RemoteAddress, RemotePort | Where-Object LocalPort | Format-Table | out-file -Append $OutputFile
}
Function GetPortsandProcesses 
{
    Write-Output "Connections Established"  | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-NetTCPConnection -State Established}
    $Results | Select-Object PSComputername, LocalAddress, LocalPort | Sort-Object PSComputername, LocalPort | out-file -Append $OutputFile
    
    Write-Output "Ports Listening"  | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-NetTCPConnection -State Listen}
    $Results | Select-Object PSComputername, LocalAddress, LocalPort | Sort-Object PSComputername, LocalPort  | out-file -Append $OutputFile
}
Function GetPNPDevices 
{
    Write-Output "PNP Devices - See PNP Device Properties for Additional Details"  | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-pnpdevice | Select-Object PSComputerName, FriendlyName, Class}
    $Results | Select-Object PSComputerName, FriendlyName, Class | Sort-Object PSComputerName, Class, FriendlyName -Unique |
        Format-Table | out-file -Append $OutputFile
}
Function GetPNPDeviceProperties
{
    Write-Output "PNP Device Properties"  | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock { 
        If(!(test-path $Using:logpath\$env:Computername))
        {
                New-Item -ItemType Directory -Force -Path $Using:logpath\$env:Computername
        }

        $InstanceIDs = Get-pnpdevice | Select-Object InstanceID, FriendlyName, Class | Where-Object Class -Notlike System | Where-Object Class -NotLike Volume* | Where-Object Class -NotLike PrintQueue | Where-Object Class -NotLike Processor | Where-Object Class -NotLike HIDClass
            foreach ($InstanceID in $InstanceIDs.instanceid) {
                Get-pnpdeviceproperty -KeyName 'DEVPKEY_Device_DeviceDesc', 'DEVPKEY_Device_Class', 'DEVPKEY_Device_FriendlyName', 'DEVPKEY_Device_EnumeratorName', 'DEVPKEY_Device_InstanceId', 'DEVPKEY_Device_FirstInstallDate', 'DEVPKEY_Device_LastArrivalDate', 'DEVPKEY_Device_IsPresent' -InstanceId $InstanceID |
            Select-Object KeyName, Data | Format-Table | out-file -Append $Using:Logpath\$env:computername\PNPDeviceProperties.txt   
        }
    }
    Write-Output "Group Policy Results Executed, open from links below " | out-file -Append $OutputFile
    foreach ($Computer in $Results.PSComputerName) {
        If (Test-Path -Path "$logpath\$Computer\PNPDeviceProperties.txt") {
            Write-Output "$logpath\$Computer\PNPDeviceProperties.txt" | out-file -Append $OutputFile
        }
    }
}
Function GetWindowsVersion 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\"  | Select-Object ProductName, ReleaseID, InstallDate, CurrentBuild, DisplayVersion}
    $Results | Select-Object PSComputerName, ProductName, ReleaseID, CurrentBuild, DisplayVersion,
        @{Name = 'InstallDate'; E = {(Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromSeconds($_.InstallDate))}} | 
        Sort-Object ProductName, ReleaseID | Format-Table | out-file -Append $OutputFile
}
Function GetPowerShellVersion 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {$PSVersionTable.PSVersion}
    $Results | Select-Object PSComputerName, Major, Minor, Build, Revision | Sort-Object Major, Minor, Build, Revision | 
        Format-Table | out-file -Append $OutputFile
}
Function GetExecutionPolicy 
{
    Write-Output "Get-EexecutionPolicy - Powershell Settings" | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-ExecutionPolicy -List}
    $Results | Select-Object PSComputerName, Scope, ExecutionPolicy | Sort-Object PSComputerName, Scope, ExecutionPolicy | Format-Table | out-file -Append $OutputFile
}    
Function GetWindowsCapability 
{
    Write-Output "Get-WindowsCapability -Name * -Online | Where-object state -like Installed" | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-WindowsCapability -Name * -Online | Select-Object -Property DisplayName, State | Where-object state -like Installed}
    $Results | Select-Object PSComputerName, DisplayName, State  | Sort-Object PSComputerName, DisplayName, State | Format-Table | out-file -Append $OutputFile
}
Function GetWindowsOptionalFeatures
{
    Write-Output "Get-WindowsOptionalFeature -Online | Where-Object State -like Enabled" | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-WindowsOptionalFeature -online | Select-Object FeatureName, State | Where-Object State -like Enabled}
    $Results | Select-Object PSComputerName, FeatureName, State  | Sort-Object PSComputerName, FeatureName, State | Format-Table | out-file -Append $OutputFile
}
Function GetSystemInfo 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {systeminfo}
    $Results | out-file -Append $OutputFile
}
Function GetComputerInfo 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-ComputerInfo}
    $Results | out-file -Append $OutputFile
}
Function GetStartupPrograms 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User}
    $Results | Select-Object PSComputerName, Description, User | Sort-Object PSComputerName, Description, User | out-file -Append $OutputFile
}
Function GetLocalGroup 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-LocalGroup}
    $Results | Select-Object PSComputerName, Name, ObjectClass, PrincipalSource | Sort-Object PSComputerName, Name, ObjectClass, PrincipalSource  | out-file -Append $OutputFile
}    
Function GetInstalledPrograms 
{

    if (!(Test-Path HKLM:\Software\Wow6432Node\Microsoft\CurrentVersion\Uninstall)) 
        {
            #Write-Output "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\CurrentVersion\Uninstall Path does not Exist" | out-file -Append $OutputFile
        }
        else 
        {
            $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {$(Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher)}
            $Results | out-file -Append $OutputFile
        }

    if (!(Test-Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall)) 
        {
            #Write-Output "Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall Path does not Exist"  | out-file -Append $OutputFile
        }
        else 
        {
            $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {$(Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher)}
            $Results | Select-Object PSComputerName, Publisher, DisplayName, DisplayVersion | Sort-Object PSComputerName, Publisher,DisplayName | 
                Where-Object DisplayName -ne $null | out-file -Append $OutputFile
        }
    
    Write-Output "Master Software List from all Accessible Computers (See Script to export to CSV)"  | out-file -Append $OutputFile
    $Results | Select-Object Publisher, DisplayName, DisplayVersion -Unique | Sort-Object Publisher,DisplayName | Where-Object DisplayName -ne $null | out-file -Append $OutputFile
    $Results | Select-Object Publisher, DisplayName, DisplayVersion -Unique | Sort-Object Publisher,DisplayName | Where-Object DisplayName -ne $null | out-file -Append $logpath\SoftwareList.txt
    $Results | Select-Object Publisher, DisplayName, DisplayVersion -Unique | Sort-Object Publisher,DisplayName | Where-Object DisplayName -ne $null | Export-csv -Append $logpath\SoftwareList.csv
}
Function GetRunningServices 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-Service | where-object {$_.Status -eq "running"}}
    $Results | Select-Object PSComputerName, Name, DisplayName, Status | Sort-Object PSComputerName, Name, DisplayName, Status | Format-Table | out-file -Append $OutputFile
}
Function GetStoppedServices 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-Service | where-object {$_.Status -eq "stopped"}}
    $Results | Select-Object PSComputerName, Name, DisplayName, Status | Sort-Object PSComputerName, Name, DisplayName, Status | Format-Table | out-file -Append $OutputFile
}
Function GetUSBActivity 
{
    if (!(Test-Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR)) 
    {
        Write-Output "Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR Path does not Exist"  | out-file -Append $OutputFile
    }
    Else
    {
        $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*}
        $Results | Select-Object PSComputerName, FriendlyName | out-file -Append $OutputFile
    }
    
    if (!(Test-Path HKLM:\SYSTEM\CurrentControlSet\Enum\USB)) 
    {
        Write-Output "Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Enum\USB Path does not Exist"  | out-file -Append $OutputFile
    }
    Else
    {
        $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\*}
        $Results | Select-Object PSComputerName, DeviceDesc, Service, Mfg | out-file -Append $OutputFile
    }
}
Function GetEventLog 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-Eventlog -LogName system -Newest 25}
    $Results | Select-Object PSComputername, TimeGenderated, Source, EntryType, Message | Where-Object {$_.EntryType -eq "warning" -or $_.EntryType -eq "error"}  | out-file -Append $OutputFile
}
Function GetBiosInfo 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-ItemProperty -Path HKLM:\HARDWARE\DESCRIPTION\System\BIOS}
    $Results | Select-Object PSComputername, BaseBoardManufacturer, BaseBoardProduct, BaseBoardVersion, BIOSReleaseDate, BIOSVersion | Format-Table  | out-file -Append $OutputFile
}
Function GetPSDrives 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {[System.IO.DriveInfo]::GetDrives()}
    $Results | Select-Object PSComputerName, Name, DriveType, DriveFormat, IsReady,
        @{Name="Used (GB)"; Expression={[math]::round($_.AvailableFreeSpace/1GB, 2)}},
        @{Name="Free (GB)"; Expression={[math]::round($_.TotalSize/1GB, 2)}} | 
        Format-Table | out-file -Append $OutputFile
}
Function GetVolumes 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-Volume}
    $Results | out-file -Append $OutputFile
}
Function GetHost
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-Host}
    $Results | out-file -Append $OutputFile
}
Function GetDependentServices 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-Service | where-object {$_.DependentServices}}
    $Results | Select-Object PSComputername, name, @{Label="QTY"; Expression={$_.dependentservices.count}}, DependentServices | out-file -Append $OutputFile	
}
Function GetDNSCache 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-DnsClientCache}
    $Results | Select-Object PSComputername, Entry, Data  | out-file -Append $OutputFile
}
Function GetBitlocker
{
    if (((Get-WindowsEdition -Online) | Select-Object Edition) -notmatch 'Standard')
    {
        $disk= Get-WMIObject -Query "Select * From win32_logicaldisk Where DriveType = '3'"
        foreach ( $drive in $disk ) 
        {
            $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-BitLockerVolume -MountPoint $drive.Name}
            $Results | Format-List | out-file -Append $OutputFile
        }
    }
    Else
    {
    Write-Output "This Version does not support Bitlocker" | out-file -Append $OutputFile
    }
}
Function GetTPM 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {
    
        if (((Get-WindowsEdition -Online) | Select-Object Edition) -notmatch 'Standard') 
        {
            Get-TPM
        }
        else 
        {
            Write-Output "$env:Computername - This version of Windows does not support TPM"
        }
    }        
    $Results | Select-Object PSComputerName, TPMPresent, TPMReady, TPMEnabled, TPMActivated | Format-Table | out-file -Append $OutputFile
}
Function GetSMBShares 
{
    Write-Output "Get Local Shares, Shares not Authorized on Workstations or the Root of System Drives" | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-SmbShare}
    $Results | Select-Object PSComputername, Name, Path |Sort-Object PSComputername, Name, Path | out-file -Append $OutputFile
}
Function GetScheduledTasks 
{
    Write-Output "Get-ScheduledTask - Are there tasks not Approved and not used in a Closed Enviroment?" | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-ScheduledTask}
    $Results | Select-Object PSComputerName, Author, TaskName | Sort-Object PSComputerName, Author, TaskName | out-file -Append $OutputFile
}
Function GetDiskInfo 
{
    Write-Output "Disk Information, Check for Disk - IsBoot = Yes then Partition should be GPT unless Virtual. If not GPT secureboot more than likly is off " | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-Disk | Select-Object Number, FriendlyName, SerialNumber, PartitionStyle,
        @{Name="Size"; Expression={[math]::round($_.Size/1GB, 2)}}}
    $Results | Select-Object PSComputerName, Number, FriendlyName, SerialNumber, PartitionStyle, Size | Format-Table | out-file -Append $OutputFile
}
Function GetFirewallProfile
{
    Write-Output "Firewall Profiles - If using 3rd party Auditing Tool, are these logs being ingested" | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-NetFirewallProfile | Select-Object PSComputerName, Name, enabled, LogAllowed, LogBlocked, LogMaxSizeKilobytes, LogFileName}
    $Results | Select-Object PSComputerName, Name, enabled, LogAllowed, LogBlocked, LogMaxSizeKilobytes, LogFileName | Format-Table | out-file -Append $OutputFile
}
Function GetFirewallRules
{
    Write-Output "Enabled Firewall Rules" | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, enabled | Where-Object enabled -eq true}
    $Results | Select-Object PSComputerName, Direction, Action, DisplayName | Sort-Object PSComputerName, DisplayName | Format-Table -AutoSize | out-file -Append $OutputFile
}
Function GetWindowsUpdates 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {
    $Session = New-Object -ComObject "Microsoft.Update.Session"
    $Searcher = $Session.CreateUpdateSearcher()
    $historyCount = $Searcher.GetTotalHistoryCount()
    $Searcher.QueryHistory(0, $historyCount) | 
        Select-Object Date,
            @{name="Status"; expression=
                {switch($_.resultcode){
                    1 {"In Progress"}; 
                    2 {"Succeeded"}; 
                    3 {"Succeeded With Errors"};
                    4 {"Failed"}; 
                    5 {"Aborted"} }}}, 
            Title | Where-Object Title -NotLike *KB2267602* | Sort-Object Date 
    }
    $Results | Select-Object PSComputerName, Date, Status, Title | 
        Sort-Object PSComputerName, Date | Where-Object Date -GE 01/01/2000 | out-file -Append $OutputFile
}
Function LaunchNotepad 
{
    Start-Process Notepad.exe $OutputFile -NoNewWindow
}

Foreach ($Task in $Tasks)
{
    Write-Progress -Activity "Collecting Assessment Data" -Status "In progress: $Task" -PercentComplete (($Counter / $Tasks.count) * 100)     
    Add-Content -Path $OutputFile -Value "------------------------------------------------------------------------------------------------------------------------"
    Add-Content -Path $OutputFile -Value ""
    Add-Content -Path $OutputFile -Value "####################################### Running Function $Task #######################################"
    Add-Content -Path $OutputFile -Value "------------------------------------------------------------------------------------------------------------------------"
    &$Task
    $Counter ++    
}

Add-Content -Path $OutputFile -Value (Get-Date)
Write-Host " "
Write-Host -fore green "Results saved to: $OutputFile" 
write-Host -fore green "Script Completed"

}
