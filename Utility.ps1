$host.UI.RawUI.WindowTitle = "Windows Utility Script"
$Host.UI.RawUI.BackgroundColor = "Black"

function showMainMenu {
    while ($true) {
        clear-Host
        write-host "====== Windows Utility Script ======" -ForegroundColor Magenta
        write-host "[1]" -ForegroundColor Magenta -NoNewline; write-host " Baseline security policy (auto)"
        write-host "[2]" -ForegroundColor Magenta -NoNewline; write-host " Manage user accounts"
        write-host "[3]" -ForegroundColor Magenta -NoNewline; write-host " User rights assignments"
        write-host "[4]" -ForegroundColor Magenta -NoNewline; write-host " Audit policy"
        write-host "[5]" -ForegroundColor Magenta -NoNewline; write-host " Services and startup"
        write-host "[6]" -ForegroundColor Magenta -NoNewline; write-host " Firewall and network"
        write-host "[7]" -ForegroundColor Magenta -NoNewline; write-host " Hash File" 
        write-host "[8]" -ForegroundColor Magenta -NoNewline; write-host " Silly Credits"
        write-host "[0]" -ForegroundColor Magenta -NoNewline; write-host " Exit"
        write-host "====================================" -ForegroundColor Magenta


        $choice = read-Host "Select option"
        switch ($choice) {
            1 { applyBaselinePolicy }
            2 { manageUsers }
            3 { userRightsAssignments }
            4 {  }
            5 {  }
            6 {  }
            7 { hashFile  }
            8 { Credits }
            0 { break }
            default { write-Host "Invalid option"; pause }
        }
    }
}
function randomStr {
    param (
        [int]$Length = 12,
        [string]$Characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?.'
    )

    $charArray = $Characters.ToCharArray()
    $RandomString = -join (0..($Length - 1) | ForEach-Object { Get-Random -InputObject $charArray })
    return $RandomString
}


function applyBaselinePolicy {

        clear-Host
        write-host "[?]" -ForegroundColor Magenta -NoNewline; write-host " Starting..."
        write-host "[+]" -ForegroundColor Magenta -NoNewline; write-host " Done!"
        pause

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
        write-host "------------------------------------" -ForegroundColor Magenta


        $choice = read-Host "Select option"
        switch ($choice) {
            1 { Start-Process "secpol.msc" }
            0 { return showMainMenu }
            default { write-Host "Invalid option"; pause }
        }
    }
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

showMainMenu