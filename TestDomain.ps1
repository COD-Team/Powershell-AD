<#
    .DESCRIPTION
        Script Attempts to communicate with Active Directory and all Windows Computers in the Domain
        Provides Results and Status to understand if there are connectivity issues. 
        Use at Your Own Risk - This Script does not modify 

    .OUTPUTS
        Report found under $logPath below, default is c:\COD-Logs\COMPUTERNAME\DATETIME
    
    .EXAMPLE
        1. PowerShell 5.1 Command Prompt (Admin) 
            "powershell -Executionpolicy Bypass -File PATH\FILENAME.ps1"
        2. Powershell 7.2.1 Command Prompt (Admin) 
            "pwsh -Executionpolicy Bypass -File PATH\FILENAME.ps1"

    .NOTES
        Author Perkins
        Last Update 1/7/22
        Updated 1/7/22 Tested and Validated PowerShell 5.1 and 7.2.1
    
        Powershell 5 or higher
        Run as Administrator
    
    .FUNCTIONALITY
        PowerShell Language
        Active Directory
    
    .Link
        https://github.com/COD-Team
        YouTube Video https://youtu.be/4LSMP0gj1IQ
#>

$Tasks = @(
    #,"Example"
    ,"GetPingableComputers"
    ,"GetWinRMPortTest"
    ,"GetWinRMService"
    ,"GetADComputers"
    ,"GetWindowsVersion"
    ,"GetPowerShellVersion"
    ,"GetRSATADFeature"
    ,"GetRSATGroupPolicyFeature"
    ,"LaunchNotepad"
    )

# If you are not an Administrator, Script will Exit
#Requires -RunAsAdministrator

# If you are not on Powershell version 5.1 or higher, Script will Exit
$versionMinimum = [Version]'5.1.000.000'
    if ($versionMinimum -gt $PSVersionTable.PSVersion)
    { throw "This script requires PowerShell $versionMinimum" }

# If your computer is NOT on a Domain, Script will exit - Checkout Standalone.ps1 for non-domain computers
if ($env:computername  -eq $env:userdomain) 
    {
        Write-Host -fore red "$env:ComputerName is not joined to a Domain, Script Exiting" 
        Exit
    }

# Measures how long it takes to execute the entire script and displays on the command  prompt window when completed
Measure-Command {

# Get Domain Name, Creates a DomainName Folder to Store Reports
# Added 1/7/21 Powershell 7.2.1 Compatibility Get-WmiObject not compatible with Powershell 7.2.1
#$DomainName = (Get-WmiObject win32_computersystem).domain
$DomainName = (Get-CimInstance Win32_ComputerSystem).Domain


# Get Computer Name
$ComputerName = $env:computername

#Path where the results will be written, suggest network share for best results. 
#$logpath = "C:\COD-Logs\$DomainName\$(get-date -format "yyyyMMdd-hhmmss")"
$logpath = "\\DC2016\SHARES\COD-Logs\$DomainName\$(get-date -format "yyyyMMdd-hhmmss")"
    If(!(test-path $logpath))
    {
          New-Item -ItemType Directory -Force -Path $logpath
    }
#Counter for Write-Progress
$Counter = 0

# Added 1/7/21 PowerShell 7.2.1 Compatibility for Out-File not printing escape characters
if ($PSVersionTable.PSVersion.major -ge 7) {$PSStyle.OutputRendering = 'PlainText'}

# Logfile where all the results are dumped
$OutputFile = "$logpath\Master.log"

#Sets Header information for the Reports
Write-Output "[INFO] Running $PSCommandPath" | Out-File -Append $OutputFile
Write-Output (Get-Date) | Out-File -Append $OutputFile
Write-Output "POWERSHELL COD ASSESSMENT SCRIPT RESULTS" | Out-File -Append $OutputFile
Write-Output "Executed Script from $ComputerName on Domain $DomainName" | Out-File -Append $OutputFile
Write-Output "------------------------------------------------------------------------------------------------------------------------" | Out-File -Append $OutputFile


#$DomainControllers = (Get-ADDomainController | Select-Object Name)
$DomainControllers = (Get-ADForest).Domains | ForEach-Object {Get-ADDomain -Identity $_ | Select-Object -ExpandProperty ReplicaDirectoryServers}

# Return all Windows Computers from Active Directory - Select 1 of the 3 options
$DomainComputers = Get-ADComputer -Filter {OperatingSystem -like "Windows*"} -Properties Name, OperatingSystem | Select-Object Name, OperatingSystem 

# Only Scan computers listed in Array
#$DomainComputers = ('Server', 'Workstation-1')

# Randomly scan a set number of computers in the domain
#$DomainComputers = Get-Random -count 3 (Get-ADComputer -Filter {OperatingSystem -like "Windows*"} -Properties Name, OperatingSystem | Select-Object Name, OperatingSystem)


# This section tests all computers in $DomainComputers Array for Accessibility (Online/Offline) Produces $Online Array, saves time only executing with computers online
$GetOnline = Invoke-command –ComputerName $DomainComputers.Name -ErrorAction SilentlyContinue –scriptblock {[pscustomobject]@{ result = (Get-Service -name "winRM").count}}
    
    $Online =  $GetOnline | Select-Object -ExpandProperty PSComputerName | Sort-Object PSComputerName
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

#This Function (Example) is just to demostrate commenting on functions in the $Tasks List to execute or not. 
Function Example
{
    Write-Output 'Example Function - Comment out in $Tasks to not execute' | Out-File -Append $OutputFile
    Write-Host -fore red ' ' 
    Write-Host -fore red 'Example Function - Comment out in $Tasks to not execute' 
}
Function GetPingableComputers
{
    Write-Output "Testing PING, If not accessible check power and Firewall Settings." | Out-File -Append $OutputFile
    foreach ($Computer in $DomainComputers.name) 
    {
        If (Test-Connection -ComputerName $Computer -Quiet -Count 1 -ErrorAction STOP) {
            Write-Output "$Computer Pingable" | Out-File -Append $OutputFile
        }
        else {
            Write-Output "$Computer Not Pingable" | Out-File -Append $OutputFile
        }
    }
}
Function GetWinRMService
{
    Write-Output "Service Must be Running to Execute Scripts Remotely" | out-file -Append $OutputFile
    $Results = Invoke-Command -ComputerName $Online -ScriptBlock {Get-Service -name "winRM"}
    $Results | Select-Object PSComputerName, Name, Status | Out-File -Append $OutputFile
}
Function GetWinRMPortTest 
{
    Write-Output "WinRM Service Port Test (5985), if not accessible you will not be able to Execute Scripts Remotly." | out-file -Append $OutputFile
    foreach ($Computer in $DomainComputers.name) 
    {
        If (Test-NetConnection -ComputerName $Computer -CommonTCPPort WINRM) {
            Write-Output "$Computer WinRM Accessible" | Out-File -Append $OutputFile
        }
        else {
            Write-Output "$Computer WinRM Not Accessible" | Out-File -Append $OutputFile
        }
    }
}
Function GetRSATADFeature 
{
    $Results = Invoke-Command -ComputerName $Online -ScriptBlock {
        Get-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -Online | Select-Object -Property DisplayName, State
    }
    Write-Output "RSAT Active Directory Feature is required from the Admin Machine executing scripts with AD Functions" | out-file -Append $OutputFile
    Write-Output "RSAT Active Directory Feature should not be required for Domain Controllers" | out-file -Append $OutputFile
    Write-Output "Computers Listed NOTPRESENT, logon locally and execute from a Powershell prompt as Admin" | out-file -Append $OutputFile
    Write-Output 'Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"' | out-file -Append $OutputFile
    $Results | Select-Object PSComputerName, DisplayName, State | Out-File -Append $OutputFile
}
Function GetRSATGroupPolicyFeature 
{
    $Results = Invoke-Command -ComputerName $Online -ScriptBlock {
        Get-WindowsCapability -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0" -Online | Select-Object -Property DisplayName, State
    }
    Write-Output "Group Policy module is required to execute GetGPResultantSetofPolicy in Main Script" | out-file -Append $OutputFile
    Write-Output "Group Policy module should not be required for Domain Controllers" | out-file -Append $OutputFile
    Write-Output "Computers Listed NOTPRESENT, logon locally and execute from a Powershell prompt as Admin" | out-file -Append $OutputFile
    Write-Output 'Add-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"' | out-file -Append $OutputFile
    $Results | Select-Object PSComputerName, DisplayName, State | Out-File -Append $OutputFile
}
Function GetADComputers 
{
    if (-Not(Get-Module -ListAvailable -Name ActiveDirectory))
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
Function GetWindowsVersion 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\"  | Select-Object ProductName, ReleaseID, InstallDate, CurrentBuild, DisplayVersion}
    $Results | Select-Object PSComputerName, ProductName, ReleaseID, CurrentBuild, DisplayVersion,
        @{Name = 'InstallDate'; E = {(Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromSeconds($_.InstallDate))}} | 
    Sort-Object ProductName, ReleaseID |
        Format-Table | out-file -Append $OutputFile
}
Function GetPowerShellVersion 
{
    $Results = Invoke-Command -ComputerName $Online -ErrorAction SilentlyContinue -ScriptBlock {$PSVersionTable.PSVersion}
    $Results | Select-Object PSComputerName, Major, Minor, Build, Revision | Sort-Object Major, Minor, Build, Revision | 
        Format-Table | out-file -Append $OutputFile
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
