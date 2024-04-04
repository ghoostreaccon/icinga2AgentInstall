#
#
#Run this script as Admin and it will use this directory "C:/source"
#Tips you can use this command
#"powershell -ExecutionPolicy Bypass -File c:/source/icinga2-agent-install.ps1"
#
param([switch]$Elevated)
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
#Check if you are admin
if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
        Set-Location "c:\source"
    }
    exit
}
$path = "c:\source"
$icinga2msi = 'Icinga2-v2.13.6-x86_64.msi'
$nsclientmsi = 'NSCP.msi'
$nsclientmsiargumentlist = "/i", "$nsclientmsi", "/qn", "/norestart", "/lxv $path/nsclientmsi-install.log"
$iscinga2msiargumentlist = "/i", "$icinga2msi", "/qn", "/norestart", "/lxv $path/icinga2msi-install.log"
$hostname = [System.Net.Dns]::GetHostName()
$ticketcsvpath = "$path\ticket.csv"
$parent_zone = #your parent zone
$satdns = #your icinga2 sat dns if needed
$satname = #you icinga2 sat if needed
#validate a host name this is an expamle for check fj-ha-jif-s890
$regvalidate = '[A-Z]{2}-[A-Z]{2}-[A-Z]{3}-[A-Z]{1}[0-9]{3}' 

#validate hostname
if(!($hostname -match $regvalidate) ){ return "Invalid hostname'$hostname'" }
else { "Hostname '$hostname' is Valid" }

#Check if source folder exsist otherwise tries to create it
If(!(test-path -PathType container $path))
{
      New-Item -ItemType Directory -Path $path
      $Acl = Get-ACL $path
      $AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","FullControl","ContainerInherit,Objectinherit","none","Allow")
      $Acl.AddAccessRule($AccessRule)
      Set-Acl $path $Acl
      Set-Location $path
}

Set-Location $path
#Downloading the Icinga2 Agent version Icinga2-v2.13.6-x86_64.msi
if (-not(Test-Path -Path $icinga2msi -PathType Leaf)) {
     try {
         Set-Location $path
         Invoke-WebRequest -Uri 'https://packages.icinga.com/windows/Icinga2-v2.13.6-x86_64.msi'-OutFile $icinga2msi
         Write-Host "Icinga2 agent has been downloaded."
     }
     catch {
         throw $_.Exception.Message
     }
 }

 else {
     Write-Host "Cannot download the file, because a file with that name already exists."
 }

#Read-Host -Prompt "Press any key to continue to install Icinga2 agent or CTRL+C to quit"
#Installing the Icinga2 agent
$icinga2msi = "Icinga 2";
$installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $icinga2msi }) -ne $null
If(-Not $installed) {
	Write-Host "$($icinga2msi) is NOT installed.";
    Write-Host "installing $($icinga2msi)"
    start-process msiexec.exe -wait -argumentlist @($iscinga2msiargumentlist);
} 
else {
	Write-Host "$($icinga2msi) is installed."
}

#Configuring Icinga2 agent
Write-Output 'Setting up Icinga2 agent'
#Read-Host -Prompt "Press any key to continue download the Certs or CTRL+C to quit"
Set-Location 'C:\Program Files\ICINGA2\sbin\'

#one way to create the needed certificate.
./icinga2.exe pki new-cert --cn $hostname --key C:/ProgramData/icinga2/var/lib/icinga2/certs/$hostname.key --cert C:/ProgramData/icinga2/var/lib/icinga2/certs/$hostname.crt
./icinga2.exe pki save-cert --trustedcert C:/ProgramData/icinga2/var/lib/icinga2/certs/$satname.crt --host $satdns

#Read-Host -Prompt "Press any key to continue to configure Icinga2 or CTRL+C to quit"
try {
    $getticket = Import-Csv -Path $ticketcsvpath -Header hostname,ticketid
    foreach($ticket in $getticket)
    {    
        if ($ticket.hostname -eq $hostname)
        {
            ./icinga2.exe node setup --ticket $ticket.ticketid --cn $hostname --endpoint "$satname,$satdns" --zone $hostname  --parent_zone $parent_zone --parent_host $satdns --trustedcert "C:/ProgramData/icinga2/var/lib/icinga2/certs/$($satname).crt" --accept-commands --accept-config --disable-confd
            'icinga2' | restart-Service
        }
    }  
}
catch {
throw $_.Exception.Message
}

#Read-Host -Prompt "Press any key to continue to install Nsclient++ or CTRL+C to quit"
#Installing NSClinet++ you could use NRPE if needed.
$nsclientmsi = "NSClient++ (Win32)";
$installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $nsclientmsi }) -ne $null
If(-Not $installed) {
	Write-Host "$($nsclientmsi) is NOT installed.";
    Write-Host "installing $($nsclientmsi)"
    start-process msiexec.exe -wait -argumentlist @($nsclientmsiargumentlist);
    Move-Item "$path\nsclient.ini" -Destination "C:\Program Files\NSClient++" -force
    'nscp' | restart-Service
} 
else {
	Write-Host "$($nsclientmsi) is installed."
    $FolderName = "C:\Program Files\NSClient++\"
    
    if (Test-Path $FolderName) {
      Write-Host "$FolderName Exists removing it"
      'nscp' | Stop-Service
      Remove-Item $FolderName -Force
     }
    else
     {
      Write-Host "$FolderName Doesn't Exists"
      'nscp' | Stop-Service
     }

    start-process msiexec.exe -wait -argumentlist @("/x", "{4D976BBB-6318-478B-87BD-BEA0F6DC2F4F}", "/qb!", "/norestart", "/lxv $path/nsclientmsi-uninstall.log");
    start-process msiexec.exe -wait -argumentlist @($nsclientmsiargumentlist);

    Move-Item "$path\nsclient.ini" -Destination "C:\Program Files\NSClient++" -force
    'nscp' | restart-Service
}

#Check the services
$geticinga2service = 'icinga2' | Get-Service
$getnscpservice = 'nscp' | Get-Service
Write-Output 'Check if Icinga2-agent and Nsclient++ is running', $geticinga2service $getnscpservice
