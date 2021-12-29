<#
    .DESCRIPTION
        This Event-Maintenance.ps1 will create a new events on a Windows Server accessible from all workstations. 
        
                
    .PARAMETER NAME
        No Parameters necessary, but adjust a few viarables below. 
  
    .EXAMPLE
        Option 1
        1. Use the .cmd file or batch file to launch
        Can create shortcuts to the files on desktops from accessable server share

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

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Add New Event'
$form.Size = New-Object System.Drawing.Size(720,480)
$form.StartPosition = 'CenterScreen'

$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Point(500,400)
$OKButton.Size = New-Object System.Drawing.Size(75,23)
$OKButton.Text = 'OK'
$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $OKButton
$form.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Point(575,400)
$CancelButton.Size = New-Object System.Drawing.Size(75,23)
$CancelButton.Text = 'Cancel'
$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $CancelButton
$form.Controls.Add($CancelButton)

$label1 = New-Object System.Windows.Forms.Label
$label1.Location = New-Object System.Drawing.Point(10,20)
$label1.Size = New-Object System.Drawing.Size(280,20)
$label1.Text = 'Please select an Event:'
$form.Controls.Add($label1)

# Update Items as needed when changes are made from SetupAuditLog.ps1
$listBox = New-Object System.Windows.Forms.ListBox
$listBox.Location = New-Object System.Drawing.Point(10,40)
$listBox.Size = New-Object System.Drawing.Size(200,20)
$listBox.Height = 120
[void] $listBox.Items.Add('Patching')
[void] $listBox.Items.Add('Auditing')
[void] $listBox.Items.Add('Anti-Virus')
[void] $listBox.Items.Add('Configuration Change')
[void] $listBox.Items.Add('Password Reset')
[void] $listBox.Items.Add('New User')
[void] $listBox.Items.Add('Disable User')
[void] $listBox.Items.Add('Continuous Monitoring')
[void] $listBox.Items.Add('Data Transfer')
[void] $listBox.Items.Add('Other')

$form.Controls.Add($listBox)


$label2 = New-Object System.Windows.Forms.Label
$label2.Location = New-Object System.Drawing.Point(10,180)
$label2.Size = New-Object System.Drawing.Size(280,20)
$label2.Text = 'Please Enter Complete Description:'
$form.Controls.Add($label2)

$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Location = New-Object System.Drawing.Point(10,200)
$textBox.Size = New-Object System.Drawing.Size(650,20)
$textBox.Multiline = $true
$textBox.Height = 180

$form.Controls.Add($textBox)

$form.Topmost = $true

$result = $form.ShowDialog()

$Message = @"
Username $($env:USERNAME) - ComputerName $($env:COMPUTERNAME)
$($textBox.Text)
"@

# Update Items as needed when changes are made from SetupAuditLog.ps1, Generate your specifc EventIDs as needed
$EventID = Switch ($listBox.SelectedItem) {
    'Patching' {7001}
    'Anti-Virus' {7002}
    'Configuration Change' {7003}
    'Password Reset' {7004}
    'New User' {7005}
    'Disable User' {7006}
    'Continuous Monitoring' {7007}
    'Data Transfer' {7008}
    'Other' {7009}
    'Auditing' {7010}
    Default {7999}
}
if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    Write-EventLog -ComputerName $ServerName -LogName $LogName -Source $listBox.SelectedItem -EntryType Information -EventId $EventID -Message $Message
}