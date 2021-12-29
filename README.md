<strong>Bitlocker.ps1</strong> - Enumerate your entire Domain, returns bitlocker, TPM, BIOS information for each device. 

<strong>Domain.ps1</strong> - Enumerate all Windows Computers, returns infomration required for cybersecurity. Also returns information from Active Directory. 

<strong>TestDomain.ps1</strong> - Allows you to test your domain to ensure the domain.ps1 script will execute. 

### See Videos for more information

<strong>PowerShell Testing Domain Accessibility</strong>

        https://youtu.be/j_m6jr7uVmc

<strong>PowerShell for Active Directory</strong>

        https://youtu.be/8qKRF7SqlOk

<strong>PowerShell Cybersecurity for Standalone Computers</strong>

        https://youtu.be/4LSMP0gj1IQ

## Prerequisites Running Powershell Across Domain Workstations

### There are 4 main reasons you can't run scripts across a Domain

### 1. The workstation you are executing from must have Remote Server Administration Toos (RSAT) Installed
        https://www.microsoft.com/en-us/download/details.aspx?id=45520
   
   Additionally modules could be required 
   
        https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2019-ps

### 2. Firewall Rules, don't just disable your Windows Firewalls. You can do for each computer but I recommend using Group Policy from the Domain Controller.

  Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Windows Firewall with Advanced Settings >> Inbound Rules

  Right Click >> New Rule >> Predefinded = Windows Remote Management >> Next
  Select the Rule with Profile = Domain, Private >> Next "You can select Defaults till Complete

### 3. Must Enable Windows Remote Management with the 2 settings below

  Computer Configuration >> Policies >> Windows Settings >> Security Settings >> System Services >> Windows Remote Management (WS-Management) >> Define Policy Checked and set to Automatic

  Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Windows Remote Management(WinRM) >> WinRM Service >> Allow remote Server Management through WINRM = Enabled, IPv4 Filter = *, IPv6 Filter = *,

**NOTE: for the Group Policy, recommend creating New GPO and link to Domain Computers OU (Mine is Named Domain COmputers, yours might be different)**

  Group Policy Management Console > Right Click OU (Where the Domain Computers are located), Group Policy Update
        This will take 10-20 minutes to push across entire Domain.
        Might need to reboot to get WinRM Service Started after Group Policy propigates
    
  Manual
        From each computer, command prompt (Admin) "gpupdate /force" AND; 
        Reboot computers remotley "shutdown /r /m \\ComputerName"
  Other Troubleshooting
        Power, WinRM Service Running, Firewall, Network Profile = Domain (Not Public)

**Not Necessary but Recommended**

  Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Allow unencrypted traffic" to "Disabled"

  Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Allow Basic authentication" to "Disabled

  Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Disallow Digest authentication" to "Enabled".

  Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> "Allow Basic authentication" to "Disabled"

  Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> "Allow unencrypted traffic" to "Disabled".

  Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> "Disallow WinRM from storing RunAs credentials" to "Enabled".

