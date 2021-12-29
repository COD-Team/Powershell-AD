<#
    .DESCRIPTION
        This SetupAuditScript will create a new event log on a Windows Server accessible from all workstations. 
        
                
    .PARAMETER NAME
        No Parameters necessary, but adjust a few viarables below. 
  
    .EXAMPLE
        Option 1
        1. Command Prompt (Admin) "powershell -Executionpolicy Bypass -File PATH\SetupAuditLog.ps1"

    .NOTES
        Author Perkins
        Last Update 12/29/21
    
        Powershell 5 or higher
        Run as Administrator
        
    .FUNCTIONALITY
        PowerShell Language
        Active Directory
    
    .Link
    https://github.com/COD-Team
    
    Video on this script
    https://youtu.be/LNxwWsG3VY4
    
    COD-Team Channel
    https://www.youtube.com/channel/UCWtXSYvBXU6YqzqBqNcH_Kw 
#>

# Enter Server Name you created in SetupAuditLog.ps1
$ServerName = 'DC2016'

# Enter the Name of the Event-Log you created in SetupAuditLog.ps1
$LogName = 'Maintenance'

#Remove-EventLog -ComputerName $ServerName -LogName $LogName 

# Start with a Default Source like Other, will also use when adding a new single Source Type. 
$Source = 'Other'

# Update your Souce List for headings you wish to capture.  
$params = @{
    ComputerName = $ServerName
    LogName = $LogName
    Source = 'Patching',
        'Anti-Virus',
        'Configuration Change',
        'Password Reset',
        'New User',
        'Disable User',
        'Continuous Monitoring',
        'Data Transfer'
}

If (-Not(Get-EventLog -ComputerName $ServerName -List | Where-Object Log -eq $LogName)) 
{
    Write-Host "Event Log Does not Exist, Creating $LogName"
    New-EventLog -ComputerName $ServerName -LogName $LogName -Source $Source
    New-EventLog @params
    Write-Host "Event Log $Logname Created"
}
ELSE 
{
    Write-Host "Event Log Exists, returning Sources" 
    
    Invoke-Command -ComputerName $ServerName -ErrorAction SilentlyContinue -ScriptBlock { If(-Not(test-path HKLM:\SYSTEM\CurrentControlSet\services\eventlog\$Using:LogName\$Using:Source)) {New-EventLog -ComputerName $Using:ServerName -LogName $Using:LogName -Source $Using:Source}}

    $Results = Invoke-Command -ComputerName $ServerName -ErrorAction SilentlyContinue -ScriptBlock {Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\eventlog\$Using:LogName\*"}
    $Results | Select-Object PSChildName
}

