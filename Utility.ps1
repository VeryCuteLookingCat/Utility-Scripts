$host.UI.RawUI.WindowTitle = "Windows Utility Script"
$Host.UI.RawUI.BackgroundColor = "Black"

function showMainMenu {
    while ($true) {
        clear-Host
        write-host "====== Windows Utility Script ======" -ForegroundColor Magenta
        write-host "[1]" -ForegroundColor Magenta -NoNewline; write-host " Baseline security policy (auto)"
        write-host "[2]" -ForegroundColor Magenta -NoNewline; write-host " Manage user accounts"
        write-host "[3]" -ForegroundColor Magenta -NoNewline; write-host " User rights assignments"
        write-host "[4]" -ForegroundColor Magenta -NoNewline; write-host " Network Shares"
        write-host "[5]" -ForegroundColor Magenta -NoNewline; write-host " Net Ports"
        write-host "[6]" -ForegroundColor Magenta -NoNewline; write-host " Driver Scan"
        write-host "[7]" -ForegroundColor Magenta -NoNewline; write-host " Hash File" 
        write-host "[8]" -ForegroundColor Magenta -NoNewline; write-host " Silly Credits"
        write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Exit"
        write-host "====================================" -ForegroundColor Magenta


        $choice = read-Host "Select option"
        switch ($choice) {
            1 { applyBaselinePolicy }
            2 { manageUsers }
            3 { userRightsAssignments }
            4 { networkSharing }
            5 { netPorts }
            6 { driverScan }
            7 { hashFile  }
            8 { Credits }
            0 { exit }
            default { write-Host "Invalid option"; pause }
        }
    }
}
function randomStr {
    param(
        [int]$length = 12
    )

    $lower = 'abcdefghijklmnopqrstuvwxyz'
    $upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $digit = '0123456789'
    $symbol = '!@#$%^&*()-_=+?'

    $mandatory = @(
        $lower[(Get-Random -Max $lower.Length)]
        $upper[(Get-Random -Max $upper.Length)]
        $digit[(Get-Random -Max $digit.Length)]
        $symbol[(Get-Random -Max $symbol.Length)]
    )

    $all = ($lower + $upper + $digit + $symbol).ToCharArray()

    $remaining = for ($i = 0; $i -lt ($length - 4); $i++) {
        $all[(Get-Random -Max $all.Length)]
    }

    -join ($mandatory + $remaining | Sort-Object {Get-Random})
}



function manageUsers {# to do: Reset Password, Add tag if user doesn't have password
 
    while ($true) {
        clear-Host 
        write-host "---------= User Managment =---------" -ForegroundColor Magenta
        write-host "[1]" -ForegroundColor Magenta -NoNewline; write-host " Delete User"
        write-host "[2]" -ForegroundColor Magenta -NoNewline; write-host " Add User"
        write-host "[3]" -ForegroundColor Magenta -NoNewline; write-host " Make Administrator"
        write-host "[4]" -ForegroundColor Magenta -NoNewline; write-host " Remove Administrator"
        write-host "[5]" -ForegroundColor Magenta -NoNewline; write-host " Disable User"
        write-host "[6]" -ForegroundColor Magenta -NoNewline; write-host " Enable User"
        write-host "[7]" -ForegroundColor Magenta -NoNewline; write-host " Reset Password"
        write-host "[8]" -ForegroundColor Magenta -NoNewline; write-host " Make All Users Password Expirable"
        write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Back -> Main Menu"
        write-host "[?]" -ForegroundColor Magenta -NoNewLine; write-host " Users:"
        write-host ""
        printUsers
        write-host ""
        write-host "------------------------------------" -ForegroundColor Magenta


        $choice = read-Host "Select option"
        switch ($choice) {
            1 { deleteUser }
            2 { addUser }
            3 { makeAdmin }
            4 { removeAdmin  }
            5 { disableUser }
            6 { enableUser }
            7 { resetUserPassword }
            8 { expirePasswords }
            0 { return showMainMenu }
            default { write-Host "Invalid option"; pause }
        }
    }

}
function userRightsAssignments {

    while ($true) {
        clear-Host 
        write-host "----= User  Rights Assignments =----" -ForegroundColor Magenta
        write-host "[1]" -ForegroundColor Magenta -NoNewline; write-host " Open Secpol.msc"
        write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Back -> Main Menu"
        write-host "[?]" -ForegroundColor Magenta -NoNewLine; write-host " Users:"
        write-host ""
        printUserAssignments
        write-host ""
        write-host "[?] Checklist (Verify Manually in Secpol.msc):" -ForegroundColor Magenta
        write-host "[ ] Guests denied local logon (SeDenyInteractiveLogonRight)"
        write-host "[ ] Guests denied remote logon (SeDenyRemoteInteractiveLogonRight)"
        write-host "[ ] Only Administrators have SeDebugPrivilege"
        write-host "[ ] Only Administrators have Backup/Restore privileges"
        write-host "[ ] RDP Logon (SeRemoteInteractiveLogonRight) only allowed for Admins + Remote Desktop Users"
        write-host "[ ] Service Logon (SeServiceLogonRight) only used by actual service accounts"
        write-host "[ ] Batch Logon (SeBatchLogonRight) is empty"
        write-host "[ ] No unknown or random SIDs assigned to ANY privilege"
        write-host ""

        write-host "------------------------------------" -ForegroundColor Magenta

        $choice = read-Host "Select option"
        switch ($choice) {
            1 { Start-Process "secpol.msc" }
            0 { return showMainMenu }
            default { write-Host "Invalid option"; pause }
        }
    }
}
function networkSharing {

    while ($true) {
        clear-Host 
        write-host "--------= Network  Sharing =--------" -ForegroundColor Magenta
        write-host "[1]" -ForegroundColor Magenta -NoNewline; write-host " Remove Share"
        write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Back -> Main Menu"
        write-host "[?]" -ForegroundColor Magenta -NoNewLine; write-host " Shares:"
        write-host ""
        printShares
        write-host ""
        write-host "------------------------------------" -ForegroundColor Magenta

        $choice = read-Host "Select option"
        switch ($choice) {
            1 { 
                $name = read-Host "Enter Share name"
                if ($name -eq "0") { return networkSharing }

                try {
                    Remove-SmbShare -Name $choice -Force -ErrorAction Stop
                    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Removed share: $choice"
                }
                catch {
                    write-host "[-]" -ForegroundColor Magenta -NoNewline; write-host " Failed or share does not exist."
                }
                pause
                return networkSharing

            }
            0 { return showMainMenu }
            default { write-Host "Invalid option"; pause }
        }
    }
}
function netPorts {
    clear-Host
    write-host "---------= Network  Ports =---------" -ForegroundColor Magenta
    write-host "[?] Active Listening Ports:" -ForegroundColor Magenta
    write-host ""
    $portMap = @{
        21="FTP"; 22="SSH"; 23="Telnet"; 25="SMTP"; 53="DNS";
        67="DHCP Server"; 68="DHCP Client"; 69="TFTP"; 80="HTTP";
        110="POP3"; 135="RPC"; 137="NetBIOS-NS"; 138="NetBIOS-DGM";
        139="NetBIOS-SSN"; 143="IMAP"; 389="LDAP"; 443="HTTPS";
        445="SMB"; 512="exec"; 513="login"; 514="shell";
        587="SMTPS"; 631="CUPS"; 1433="MSSQL"; 1434="MSSQL-Browser";
        3306="MySQL"; 3389="RDP"; 5432="PostgreSQL"; 5900="VNC";
        6379="Redis"; 8080="HTTP-Alt"; 25565="Minecraft";
    }

    $dangerous = @(21,23,69,512,513,514,3306,5432,6379,5900)

    $connections = Get-NetTCPConnection -State Listen | Sort-Object LocalPort

    foreach ($conn in $connections) {
        $owningPid = $conn.OwningProcess
        try { $procName = (Get-Process -Id $owningPid).Name }
        catch { $procName = "Unknown" }

        $port = $conn.LocalPort
        $desc = $portMap[$port]
        if (-not $desc) { $desc = "Unknown/Custom" }

        # threat logic
        if ($dangerous -contains $port) {
            write-host "[!]" -ForegroundColor Red -NoNewline
            write-host " Port $port ($desc)  ->  $procName (PID $owningPid)"
        }
        elseif ($desc -eq "Unknown/Custom" -and $port -lt 49152) {
            write-host "[?]" -ForegroundColor Yellow -NoNewline
            write-host " Port $port ($desc)  ->  $procName (PID $owningPid)"
        }
        else {
            write-host "[-] Port $port ($desc)  ->  $procName (PID $owningPid)"
        }
    }

    write-host ""
    write-host "------------------------------------" -ForegroundColor Magenta
    pause
    return showMainMenu
}
function driverScan {
    clear-Host
    write-host "----------= Driver  Scan =----------" -ForegroundColor Magenta
    write-host "[?] Scanning system drivers..." -ForegroundColor Magenta
    write-host ""

    $drivers = Get-WmiObject Win32_SystemDriver | Sort-Object Name

    foreach ($d in $drivers) {
        $path = $d.PathName
        $state = $d.State
        $mode = $d.StartMode

        $flag = $false

        if (-not $path) { $flag = $true }

        if ($path -and $path -notmatch "System32|systemroot|SysWOW64") { $flag = $true }

        if ($state -eq "Running" -and $path -notmatch "System32") { $flag = $true }

        if ($flag) {
            write-host "[!]" -ForegroundColor Magenta -NoNewline
            write-host " $($d.Name)  |  State: $state  |  Mode: $mode"
            write-host "     Path: $path"
        }
        else {
            write-host "[-]" -ForegroundColor Magenta -NoNewline write-host"  $($d.Name) | State: $state | Mode: $mode"
            write-host ""
        }
    }

    write-host ""
    write-host "------------------------------------" -ForegroundColor Magenta
    pause
    return showMainMenu
}


function hashFile {
    clear-Host 
    write-host "---------=  File Hashing  =---------" -ForegroundColor Magenta
    write-host "[?]" -ForegroundColor Magenta -NoNewline; write-host " Enter The File Directory to Get The Hashes"
    write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Back -> Main Menu"
    $fileDir = read-Host("File Directory")
    if($fileDir -eq "0") { return showMainMenu }

    $fileDir = $fileDir.Trim('"').Trim()
    if (-not (Test-Path $fileDir -PathType Leaf)) {
        write-host "[-]" -ForegroundColor Magenta -NoNewline; write-host " Invalid file path or not a file."
        pause
        return hashFile
    }

    clear-Host 
    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " File Found: $fileDir"
    write-host "[?] Calculating Hashes...`n" -ForegroundColor Magenta

    $algorithms = @("SHA256", "SHA1", "MD5", "SHA384", "SHA512")

    foreach ($algo in $algorithms) {
        try {
            $h = Get-FileHash -Path $fileDir -Algorithm $algo
            write-host "[?]" -ForegroundColor Magenta -NoNewline; write-host " $($algo):" 
            write-host "    $($h.Hash)"
            write-host ""
        }
        catch {
            write-host "[-]" -ForegroundColor Magenta -NoNewline; write-host " Failed to compute $algo"
        }
    }

    pause
    showMainMenu
}
function Credits {
    clear-Host
    write-host "-----------=  Credits  =-----------" -ForegroundColor Magenta
    write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Github ( VeryCuteLookingCat ) - Helped with UI"
    write-host "https://github.com/veryCuteLookingCat"
    write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " My Cat - Wrote entire backend"
    write-host "N/A"
    write-host "-----------------------------------" -ForegroundColor Magenta
    pause
    return showMainMenu

}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#Baseline security
function safeDisableService($name) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) {
        Set-Service -Name $name -StartupType Disabled
        Stop-Service -Name $name -Force
    }
}
function applyBaselinePolicy {

    clear-Host
    write-host "[?] Starting..." -ForegroundColor Magenta

    $filePath = "$env:TEMP\BasePolicy.inf"
    secedit /export /cfg "$filePath" /areas SECURITYPOLICY USER_RIGHTS GROUP_MGMT | Out-Null

    # ===========================
    # System Access (Passwords)
    # ===========================
    setInfValue $filePath "System Access" "PasswordHistorySize" "5"
    setInfValue $filePath "System Access" "MaximumPasswordAge" "90"
    setInfValue $filePath "System Access" "MinimumPasswordAge" "30"
    setInfValue $filePath "System Access" "MinimumPasswordLength" "12"
    setInfValue $filePath "System Access" "PasswordComplexity" "1"
    setInfValue $filePath "System Access" "ClearTextPassword" "0"
    setInfValue $filePath "System Access" "LockoutBadCount" "5"
    setInfValue $filePath "System Access" "ResetLockoutCount" "15"
    setInfValue $filePath "System Access" "LockoutDuration" "15"

    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Modified System Access"

    # ===========================
    # Security Options
    # ===========================
    setInfValue $filePath "Security Options" "DisableCAD" "0"
    setInfValue $filePath "Security Options" "EnableAdminAccount" "0"
    setInfValue $filePath "Security Options" "EnableGuestAccount" "0"
    setInfValue $filePath "Security Options" "LmCompatibilityLevel" "5"
    setInfValue $filePath "Security Options" "NoLMHash" "1"
    setInfValue $filePath "Security Options" "AuditBaseObjects" "1"
    setInfValue $filePath "Security Options" "ForceUnlockLogon" "1"
    setInfValue $filePath "Security Options" "FilterAdministratorToken" "1"
    setInfValue $filePath "Security Options" "ConsentPromptBehaviorAdmin" "2"
    setInfValue $filePath "Security Options" "ConsentPromptBehaviorUser" "1"
    setInfValue $filePath "Security Options" "PromptOnSecureDesktop" "1"
    setInfValue $filePath "Security Options" "LSAAnonymousNameLookup" "0"
    setInfValue $filePath "Security Options" "RestrictAnonymous" "1"
    setInfValue $filePath "Security Options" "RestrictAnonymousSAM" "1"
    setInfValue $filePath "Security Options" "RequireSignOrSeal" "1"
    setInfValue $filePath "Security Options" "RequireStrongKey" "1"
    setInfValue $filePath "Security Options" "ForceLogoffWhenHourExpires" "1"
    setInfValue $filePath "Security Options" "NullSessionPipes" ""
    setInfValue $filePath "Security Options" "NullSessionShares" ""
    setInfValue $filePath "Security Options" "RestrictNullSessAccess" "1"
    setInfValue $filePath "Security Options" "DriverSigningPolicy" "2"
    setInfValue $filePath "Security Options" "DriverSigningBehavior" "2"
    setInfValue $filePath "Security Options" "SMBIdleDisconnectTimeout" "15"
    setInfValue $filePath "Security Options" "DontAllowRemoteRegistry" "1"
    setInfValue $filePath "Security Options" "CachedLogonsCount" "0"
    setInfValue $filePath "Security Options" "NtlmMinClientSec" "536870912"
    setInfValue $filePath "Security Options" "NtlmMinServerSec" "536870912"
    setInfValue $filePath "Security Options" "EnablePlainTextPassword" "0"
    setInfValue $filePath "Security Options" "CodeSigningForDrivers" "1"
    setInfValue $filePath "Security Options" "DisablePasswordCaching" "1"
    setInfValue $filePath "Security Options" "LegalNoticeCaption" "Authorized Use Only"
    setInfValue $filePath "Security Options" "LegalNoticeText" "This system is for authorized use only."
    setInfValue $filePath "Security Options" "EveryoneIncludesAnonymous" "0"
    setInfValue $filePath "Security Options" "AllowAnonymousSIDNameTranslation" "0"
    setInfValue $filePath "Security Options" "NewAdministratorName" "admin-secure"
    setInfValue $filePath "Security Options" "NewGuestName" "guest-disabled"



    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Modified Security Options"



    # ===========================
    # Audit Policy
    # ===========================
    setInfValue $filePath "Audit Policy" "AuditLogonEvents" "3"
    setInfValue $filePath "Audit Policy" "AuditAccountLogon" "3"
    setInfValue $filePath "Audit Policy" "AuditPrivilegeUse" "3"
    setInfValue $filePath "Audit Policy" "AuditPolicyChange" "3"
    setInfValue $filePath "Audit Policy" "AuditSystemEvents" "3"
    setInfValue $filePath "Audit Policy" "AuditAccountManage" "3"
    setInfValue $filePath "Audit Policy" "AuditDSAccess" "3"
    setInfValue $filePath "Audit Policy" "AuditObjectAccess" "3"
    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Modified Audit Policy"

    # ===========================
    # APPLY CONFIG
    # ===========================
    secedit /configure /db "C:\Windows\security\database\local.sdb" `
        /cfg "$filePath" `
        /areas SECURITYPOLICY USER_RIGHTS GROUP_MGMT | Out-Null

    gpupdate /force | Out-Null
    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Imported Securit Policy's"

    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name "Start" -Value 4
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging" -Name "LogDroppedPackets" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging" -Name "LogSuccessfulConnections" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Value 0    
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds " -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableAnonymousSIDNameTranslation" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictReceivingNTLMTraffic" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AllowInsecureGuestAuth" -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin"
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClipboardRedirection" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell" -Name "ExecutionPolicy" -Value "Restricted"
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell" -Name "EnableScripts" -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd" -Name "AdmPwdEnabled" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd" -Name "PasswordComplexity" -Value 4


    New-Item -Path "Registry::HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force | Out-Null
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name Enabled -Value 0

    New-Item -Path "Registry::HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force | Out-Null
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name Enabled -Value 0


    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Modified Registry"

    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -NoRestart

    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Disabled optional features"

    schtasks /Change /TN "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
    schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable

    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Removed scheduled tasks"

    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow

    netsh advfirewall set allprofiles settings inboundusernotification enable
    netsh advfirewall set allprofiles logging name "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
    netsh advfirewall set allprofiles logging maxfilesize 4096

    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Enabled firewall"

    Disable-PSRemoting -Force
    winrm delete winrm/config/Listener?Address=*+Transport=HTTP 2>$null
    safeDisableService "WinRM"
    safeDisableService "RemoteAccess"
    safeDisableService "SNMP"
    safeDisableService "Telnet"
    safeDisableService "BTAGService"
    safeDisableService "bthserv"
    safeDisableService "PeerDistSvc"
    safeDisableService "Spooler"
    safeDisableService "SessionEnv"
    safeDisableService "WDSServer"
    safeDisableService "vmicguestinterface"
    safeDisableService "vmicshutdown"
    safeDisableService "vmicheartbeat"



    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Disabled useless services's"
    
    if (Get-Command Set-SmbClientConfiguration -ErrorAction SilentlyContinue) {
        Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force
    }
    if (Get-Command dnscmd.exe -ErrorAction SilentlyContinue) {
        dnscmd /config /NoRecursion 1 2>$null
    }
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    Set-MpPreference -DisableScriptScanning $false
    Set-MpPreference -MAPSReporting 2
    Set-MpPreference -SubmitSamplesConsent 2
    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Disabled useless services's"
    try {
        Remove-LocalGroupMember -Group "Guests" -Member "guest-disabled" -ErrorAction Stop
    } catch {}



    write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Basline Security Applied!"
    pause
}
function setInfValue {
    param(
        [string]$file,
        [string]$section,
        [string]$key,
        [string]$value
    )

    if (-not (Test-Path $file)) {
        throw "INF file not found: $file"
    }

    $content = Get-Content $file
    $newContent = @()
    $inSection = $false
    $keyWritten = $false

    for ($i = 0; $i -lt $content.Count; $i++) {

        if ($content[$i] -match "^\[$section\]$") {
            $inSection = $true
            $newContent += $content[$i]
            continue
        }

        if ($inSection -and $content[$i] -match "^\[.*\]$") {
            if (-not $keyWritten) {
                $newContent += "$key = $value"
                $keyWritten = $true
            }
            $inSection = $false
        }

        if ($inSection -and $content[$i] -match "^$key\s*=") {
            $newContent += "$key = $value"
            $keyWritten = $true
            continue
        }

        $newContent += $content[$i]
    }

    if (-not $keyWritten) {
        $newContent += ""
        $newContent += "[$section]"
        $newContent += "$key = $value"
    }

    Set-Content -Path $file -Value $newContent -Encoding ASCII
}

#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# USER MANAGMENT
function printUsers {
    $users = Get-LocalUser
    $admins = Get-LocalGroupMember -Group Administrators

    foreach ($u in $users) {
        $tags = @()

        if ($admins | Where-Object { $_.Name.Split('\')[-1] -eq $u.Name }) { $tags += "Elevated" }
        if (-not $u.Enabled) { $tags += "Disabled" }
        if ($u.PasswordNeverExpires) { $tags += "Password Never Expires" }
        if (-not $u.UserMayChangePassword) { $tags += "Cannot change password" }
        $info = net user $u.Name
        if ($info -match "Account\s+locked\s+Yes") { $tags += "Account Locked" }

        write-host "$($u.Name) = $($tags -join ' - ')"
    }
}
function deleteUser {       
    while ($true) {
        clear-Host 
        write-host "---------=  Delete  User  =---------" -ForegroundColor Magenta
        write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Enter The Username You Wish to delete"

        write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Back -> Manage Users"
        write-host "[?]" -ForegroundColor Magenta -NoNewLine; write-host " Users:"
        write-host ""
        printUsers
        write-host ""
        write-host "------------------------------------" -ForegroundColor Magenta


        $choice = read-Host "Enter Username"
        if($choice -eq "0") { return manageUsers }
        $users = Get-LocalUser
        foreach ($u in $users) {
            if($u.Name -eq $choice) {

                $confirmation  = read-Host "Are you sure you want to delete $($u.Name)? (Y/N)"

                if($confirmation -eq "Y" -or $confirmation -eq "y" ) { 

                    Remove-LocalUser -Name $u.Name
                    write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Deleted User: $($u.Name)"
                    pause
                    return manageUsers
                } else {
                    write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " Confirmation Denied."
                    pause
                    return deleteUser

                }

            }
        }

        write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " User does not exist."

    }

}
function addUser {
    clear-Host 
    write-host "-----------=  Add User  =-----------" -ForegroundColor Magenta
    write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Back -> Manage Users"
    
    write-host "[?]" -ForegroundColor Magenta -NoNewLine; write-host " Users:"
    write-host ""
    printUsers
    write-host ""
    write-host "------------------------------------"
    
    $choice = read-Host "Enter Username"
    if($choice -eq "0") { return manageUsers }
    
    $confirmation = read-Host "Are you sure you want to create $($choice)? (Y/N)"
    if($confirmation -eq "Y" -or $confirmation -eq "y" ) { 
        $password = randomStr
        $secure = ConvertTo-SecureString $password -AsPlainText -Force # Because powershell stinks

        New-LocalUser -Name $choice -Password $secure

        write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Created User: $($choice)"
        write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Password: $($password)"
        pause
        return manageUsers
    } else {
        write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " Confirmation Denied."
        pause
        return addUser
    }
}
function makeAdmin {

    clear-Host 
    write-host "----------=  Make Admin  =----------" -ForegroundColor Magenta
    write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Back -> Manage Users"
    
    write-host "[?]" -ForegroundColor Magenta -NoNewLine; write-host " Users:"
    write-host ""
    printUsers
    write-host ""
    write-host "------------------------------------"
    
    $choice = read-Host "Enter Username"
    if($choice -eq "0") { return manageUsers }
    
    $users = Get-LocalUser
    $admins = Get-LocalGroupMember -Group Administrators
    foreach ($u in $users) {
        if($u.Name -eq $choice) {
            
            if ($admins | Where-Object { $_.Name.Split('\')[-1] -eq $u.Name }) { # if User is already elevated
                write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " User is already elevated."
                pause
                return makeAdmin
            }

            $confirmation = read-Host "Are you sure you want to elevate $($choice)? (Y/N)"
            if($confirmation -eq "Y" -or $confirmation -eq "y" ) { 

                Add-LocalGroupMember -Group "Administrators" -Member $u.Name
                write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Elevated User: $($u.Name)"

                pause
                return manageUsers
            } else {
                write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " Confirmation Denied."
                pause
                return makeAdmin
            }

        }
    }
    write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " User not found."
    pause
    return makeAdmin
}
function removeAdmin {

    clear-Host 
    write-host "---------=  Remove Admin  =---------" -ForegroundColor Magenta
    write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Back -> Manage Users"
    
    write-host "[?]" -ForegroundColor Magenta -NoNewLine; write-host " Users:"
    write-host ""
    printUsers
    write-host ""
    write-host "------------------------------------"
    
    $choice = read-Host "Enter Username"
    if($choice -eq "0") { return manageUsers }
    
    $admins = Get-LocalGroupMember -Group Administrators

    $u = Get-LocalUser -Name $choice -ErrorAction SilentlyContinue
    if ($u) {
            
        if ($admins | Where-Object { $_.Name.Split('\')[-1] -eq $u.Name }) { # if User is elevated            

            $confirmation = read-Host "Are you sure you want to remove elevation from $($choice)? (Y/N)"
            if($confirmation -eq "Y" -or $confirmation -eq "y" ) { 

                Remove-LocalGroupMember -Group "Administrators" -Member $u.Name
                write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Removed Elevated User: $($u.Name)"

                pause
                return manageUsers
            } else {
                write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " Confirmation Denied."
                pause
                return makeAdmin
            }

        } else {

            write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " User lacks Elevation."
            pause
            return makeAdmin
        }
    }
    write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " User not found."
    pause
    return removeAdmin
}
function enableUser {

    clear-Host 
    write-host "---------=  Enable  User  =---------" -ForegroundColor Magenta
    write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Back -> Manage Users"
    
    write-host "[?]" -ForegroundColor Magenta -NoNewLine; write-host " Users:"
    write-host ""
    printUsers
    write-host ""
    write-host "------------------------------------"

    
    $choice = read-Host "Enter Username"
    if($choice -eq "0") { return manageUsers }
    
    $u = Get-LocalUser -Name $choice -ErrorAction SilentlyContinue
    if ($u) {

        $confirmation = read-Host "Are you sure you want to enable $($choice)? (Y/N)"
        if($confirmation -eq "Y" -or $confirmation -eq "y" ) { 
            
            Enable-LocalUser -Name $u.Name

            write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Enabled User: $($u.Name)"

            pause
            return manageUsers
        } else {
            write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " Confirmation Denied."
            pause
            return disableUser
        }
    }
    write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " User not found."
    pause
    return disableUser
}
function disableUser {

    clear-Host 
    write-host "---------=  Disable User  =---------" -ForegroundColor Magenta
    write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Back -> Manage Users"
    
    write-host "[?]" -ForegroundColor Magenta -NoNewLine; write-host " Users:"
    write-host ""
    printUsers
    write-host ""
    write-host "------------------------------------"


    $choice = read-Host "Enter Username"
    if($choice -eq "0") { return manageUsers }
    
    $u = Get-LocalUser -Name $choice -ErrorAction SilentlyContinue
    if ($u) {

        $confirmation = read-Host "Are you sure you want to disable $($choice)? (Y/N)"
        if($confirmation -eq "Y" -or $confirmation -eq "y" ) { 
            
            Disable-LocalUser -Name $u.Name

            write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Disabled User: $($u.Name)"

            pause
            return manageUsers
        } else {
            write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " Confirmation Denied."
            pause
            return disableUser
        }
        
    }
    write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " User not found."
    pause
    return disableUser
}
function expirePasswords {
    clear-Host
    write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Starting..."
    $users = Get-LocalUser
    foreach ($u in $users) {
        if($u.Name -eq "Guest") { continue }
        Set-LocalUser -Name $u.Name -PasswordNeverExpires $false
        Set-LocalUser -Name $u.Name -UserMayChangePassword $true
        write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Made $($u.Name)'s password Expireable and Changeable."
    }
    write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Done!"
    pause
    return manageUsers

}
function resetUserPassword {

    clear-Host 
    write-host "--------=  Reset Password  =--------" -ForegroundColor Magenta
    write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Back -> Manage Users"
    write-host "[?]" -ForegroundColor Magenta -NoNewLine; write-host " Users:"
    write-host ""
    printUsers
    write-host ""
    write-host "------------------------------------"


    $choice = read-Host "Enter Username"
    if($choice -eq "0") { return manageUsers }
    
    $u = Get-LocalUser -Name $choice -ErrorAction SilentlyContinue
    if ($u) {

        $confirmation = read-Host "Are you sure you want to reset $($choice)'s password? (Y/N)"
        if($confirmation -eq "Y" -or $confirmation -eq "y" ) { 
            
            $password = randomStr
            $secure = ConvertTo-SecureString $password -AsPlainText -Force
            Set-LocalUser -Name $u.Name -Password $secure

            write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " Reset users password: $($u.Name)"
            write-host "[+]" -ForegroundColor Magenta -NoNewLine; write-host " New Password: $password"

            pause
            return manageUsers
        } else {
            write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " Confirmation Denied."
            pause
            return resetUserPassword
        }
        
    }
    write-host "[-]" -ForegroundColor Magenta -NoNewLine; write-host " User not found."
    pause
    return resetUserPassword
}
#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# USER RIGHTS ASSIGNMENTS

function printUserAssignments {
    $temp = "$env:TEMP\rights.inf"
    secedit /export /cfg $temp | Out-Null
    $rights = Get-Content $temp

    $privMap = @{
        "SeInteractiveLogonRight"          = "AllowLocal"
        "SeDenyInteractiveLogonRight"      = "DenyLocal"
        "SeRemoteInteractiveLogonRight"    = "AllowRDP"
        "SeDenyRemoteInteractiveLogonRight"= "DenyRDP"
        "SeServiceLogonRight"              = "ServiceLogon"
        "SeBatchLogonRight"                = "BatchLogon"
        "SeBackupPrivilege"                = "Backup"
        "SeRestorePrivilege"               = "Restore"
        "SeDebugPrivilege"                 = "Debug"
    } # Contains all assignments in secpol
    $assignments = @{} # stores all the assignments by username
    $localUsers = Get-LocalUser

    foreach ($priv in $privMap.Keys) {
        $line = $rights | Where-Object { $_ -match "^$priv" }
        if (!$line) { continue }

        $sids = $line.Split("=")[1].Trim().Split(",")

        foreach ($entry in $sids) {

            $clean = $entry.Trim()
            $clean = $clean.TrimStart('*')

            if ($clean -match '^S-\d-\d+-.+') {
                try {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($clean)
                    $name = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                    $username = $name.Split('\')[-1]
                }
                catch {
                    continue
                }
            }
            else {
                $username = $clean
            }

            if (-not $assignments.ContainsKey($username)) {
                $assignments[$username] = @()
            }

            $assignments[$username] += $privMap[$priv]
        }
    }
    foreach($username in $assignments.Keys) {

        write-host "$($username) = $($assignments[$username] -join ' - ')"
    }
}

function printShares {

    $default = @("ADMIN$", "C$", "IPC$", "PRINT$", "FAX$")
    $shares = Get-SmbShare

    foreach ($s in $shares) {
        if ($default -contains $s.Name) {
            write-host "$($s.Name) = Default" 
        }
        else {
            write-host "[!]" -ForegroundColor Magenta -NoNewline
            write-host " $($s.Name) -> $($s.Path)" 
        }
    }
}

showMainMenu