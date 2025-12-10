#!/bin/bash

MAGENTA="\033[95m"
RESET="\033[0m"

showMainMenu() {
    while true; do
        clear
        echo -e "${MAGENTA}====== Linux Utility Script ======${RESET}"
        echo -e "${MAGENTA}[1]${RESET} Apply baseline hardening"
        echo -e "${MAGENTA}[2]${RESET} Manage user accounts"
        echo -e "${MAGENTA}[3]${RESET} Review privilege assignments"
        echo -e "${MAGENTA}[4]${RESET} Audit system security"
        echo -e "${MAGENTA}[5]${RESET} Manage services & startup"
        echo -e "${MAGENTA}[6]${RESET} Firewall & network configuration"
        echo -e "${MAGENTA}[7]${RESET} File hashing utility"
        echo -e "${MAGENTA}[8]${RESET} Credits"
        echo -e "${MAGENTA}[0]${RESET} Exit"
        echo -e "${MAGENTA}====================================${RESET}"

        read -p "Select option: " choice

        case "$choice" in
            1) applyBaselinePolicy ;;
            2) manageUsers ;;
            3) userRightsAssignments ;;
            4) auditPolicy ;;
            5) manageServices ;;
            6) firewallAndNetwork ;;
            7) hashFile ;;
            8) Credits ;;
            0) exit ;;
            *) echo "Invalid option"; read -p "Press enter to continue" ;;
        esac
    done
}
manageUsers() {
    while true; do
        clear
        echo -e "${MAGENTA}---------= User Management =---------${RESET}"
        echo -e "${MAGENTA}[1]${RESET} Delete User"
        echo -e "${MAGENTA}[2]${RESET} Add User"
        echo -e "${MAGENTA}[3]${RESET} Make Administrator"
        echo -e "${MAGENTA}[4]${RESET} Remove Administrator"
        echo -e "${MAGENTA}[5]${RESET} Disable User"
        echo -e "${MAGENTA}[6]${RESET} Enable User"
        echo -e "${MAGENTA}[7]${RESET} Reset Password"
        echo -e "${MAGENTA}[8]${RESET} Make Passwords Expirable"
        echo -e "${MAGENTA}[0]${RESET} Back -> Main Menu"
        echo -e "${MAGENTA}[?]${RESET} Users:"
        echo ""

        printUsers;;

        echo ""
        echo -e "${MAGENTA}-------------------------------------${RESET}"

        read -p "Select option: " u
        case "$u" in
            1) deleteUser ;;
            2) addUser ;;
            3) makeAdmin ;;
            4) removeAdmin ;;
            5) disableUser ;;
            6) enableUser ;;
            7) resetUserPassword ;;
            8) expirePasswords ;;
            0) return ;;
        esac
    done
}
Credits() {
    clear
    echo -e "${MAGENTA}---------= User Management =---------${RESET}"
    echo -e "${MAGENTA}[+]${RESET} Github ( VeryCuteLookingCat ) - Helped with UI"
    echo -e "https://github.com/veryCuteLookingCat"
    echo -e "${MAGENTA}[+]${RESET} My Cat - Wrote entire backend"
    echo -e "N/A"
    echo -e "${MAGENTA}-------------------------------------${RESET}"
}
printUsers() {
    users=$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd)

    echo ""
    for user in $users; do
        tags=()

        if id -nG "$user" | grep -Eq "(sudo|adm)"; then
            tags+=("Elevated")
        fi

        shadow=$(grep "^$user:" /etc/shadow)
        pwField=$(echo "$shadow" | cut -d: -f2)

        if [[ $pwField == '!'* ]] || [[ $pwField == '*' ]]; then
            tags+=("Disabled")
        fi

        expireField=$(echo "$shadow" | cut -d: -f5)
        if [[ $expireField -eq -1 ]]; then
            tags+=("Password Never Expires")
        fi

        minDays=$(echo "$shadow" | cut -d: -f4)
        if [[ $minDays -ge 99999 ]]; then
            tags+=("Cannot Change Password")
        fi

        status=$(passwd -S "$user" | awk '{print $2}')
        if [[ $status == "L" ]]; then
            tags+=("Account Locked")
        fi

        if [[ ${#tags[@]} -eq 0 ]]; then
            echo "$user = No Flags"
        else
            echo "$user = ${tags[*]}"
        fi
    done
    echo ""
}
deleteUser() {
    read -p "Enter username to delete (0 to cancel): " u
    [[ "$u" == "0" ]] && return
    sudo deluser "$u"
    read -p "User deleted. Press enter..."
}
addUser() {
    read -p "Enter new username (0 to cancel): " u
    [[ "$u" == "0" ]] && return

    password=$(openssl rand -base64 12)
    sudo adduser --disabled-password --gecos "" "$u"
    echo "$u:$password" | sudo chpasswd

    echo "Created user: $u"
    echo "Password: $password"
    read -p "Press enter..."
}
makeAdmin() {
    read -p "Enter username: " u
    sudo usermod -aG sudo "$u"
    echo "$u is now admin."
    read -p "Press enter..."
}
removeAdmin() {
    read -p "Enter username: " u
    sudo deluser "$u" sudo
    echo "$u is no longer admin."
    read -p "Press enter..."
}
disableUser() {
    read -p "Enter username: " u
    sudo usermod -L "$u"
    echo "Disabled $u"
    read -p "Press enter..."
}
enableUser() {
    read -p "Enter username: " u
    sudo usermod -U "$u"
    echo "Enabled $u"
    read -p "Press enter..."
}
resetUserPassword() {
    read -p "Enter username: " u
    password=$(openssl rand -base64 12)
    echo "$u:$password" | sudo chpasswd
    echo "New password for $u: $password"
    read -p "Press enter..."
}
expirePasswords() {
    for u in $(cut -d: -f1 /etc/passwd); do
        sudo chage -M 90 "$u" 2>/dev/null
    done
    echo "All users now have expiring passwords."
    read -p "Press enter..."
}




showMainMenu