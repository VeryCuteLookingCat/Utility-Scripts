MAGENTA="\033[95m"
RESET="\033[0m"

showMainMenu() {
    while true; do
        clear
        echo -e "${MAGENTA}====== Linux Utility Script ======${RESET}"
        echo -e "${MAGENTA}[1]${RESET} Baseline security policy (auto)"
        echo -e "${MAGENTA}[2]${RESET} Manage user accounts"
        echo -e "${MAGENTA}[3]${RESET} User rights assignments"
        echo -e "${MAGENTA}[4]${RESET} Audit policy"
        echo -e "${MAGENTA}[5]${RESET} Services and startup"
        echo -e "${MAGENTA}[6]${RESET} Firewall and network"
        echo -e "${MAGENTA}[7]${RESET} Hash File"
        echo -e "${MAGENTA}[8]${RESET} Silly Credits"
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

        cut -d':' -f1 /etc/passwd | sort
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