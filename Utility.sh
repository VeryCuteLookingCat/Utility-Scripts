#!/bin/bash

MAGENTA="\033[95m"
RESET="\033[0m"

if [[ $EUID -ne 0 ]]; then
    echo -e "${MAGENTA}[!]{$RESET} This script must be run as root."
    echo "Run using: sudo ./Utility.sh"
    exit 1
fi

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
applyBaselinePolicy() {

    sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 10/' /etc/login.defs
    sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
    echo -e "${MAGENTA}[+]${RESET} Login settings updated."
    
    if grep -q "ucredit=-1" /etc/pam.d/common-password; then
        sudo sed -i '/ucredit=-1/d' /etc/pam.d/common-password 
    fi
    echo "ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" | sudo tee -a /etc/pam.d/common-password

    sudo passwd -l root
    echo -e "${MAGENTA}[+]${RESET} Root account disabled. To enable it again: 'sudo passwd root'"

    
    sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sudo sed -i 's/^LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config
    sudo sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    sudo sed -i 's/^UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    echo -e "${MAGENTA}[+]${RESET} SSH Security settings updated."
    
    echo "Authorized users only. All activities are monitored." | sudo tee /etc/issue.net
    sudo sed -i 's/^#Banner none/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    echo -e "${MAGENTA}[+]${RESET} SSH banner configured."



    echo "net.ipv4.conf.all.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv4.ip_forward = 0" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.all.send_redirects = 0" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv4.tcp_syncookies = 1" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.all.rp_filter = 1" | sudo tee -a /etc/sysctl.conf
    echo "fs.suid_dumpable = 0" | sudo tee -a /etc/sysctl.conf
    echo "kernel.exec-shield = 1" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p
    echo -e "${MAGENTA}[+]${RESET} SYSctl settings updated."
    sudo sysctl -a
    echo -e "${MAGENTA}[+]${RESET} SYSctl changes verified."

    echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p
    echo -e "${MAGENTA}[+]${RESET} IPv6 has been disabled."

    sudo visudo -c  # Check sudoers file for syntax errors
    sudo sed -i 's/NOPASSWD.*/ALL=(ALL) ALL/' /etc/sudoers
    echo -e "${MAGENTA}[+]${RESET} Sudoers file updated to require passwords."


    sudo ufw enable
    echo -e "${MAGENTA}[+]${RESET} UFW firewall enabled."
    sudo ufw allow OpenSSH
    sudo ufw allow 'Nginx Full'
    sudo ufw deny 3389
    sudo ufw deny 445
    sudo ufw deny 139
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    echo -e "${MAGENTA}[+]${RESET} UFW rules configured (SSH, HTTP/HTTPS allowed)."

    # 
    sudo systemctl disable cups
    sudo systemctl disable avahi-daemon
    sudo systemctl stop cups
    sudo systemctl stop avahi-daemon
    echo -e "${MAGENTA}[+]${RESET} Disabled unnecessary services (cups, avahi-daemon)."

    sudo systemctl enable apparmor
    sudo systemctl start apparmor
    echo -e "${MAGENTA}[+]${RESET} AppArmor is enabled and running."

    echo "install dccp /bin/true" | sudo tee -a /etc/modprobe.d/disable_modules.conf
    echo "install rds /bin/true" | sudo tee -a /etc/modprobe.d/disable_modules.conf
    echo "install sctp /bin/true" | sudo tee -a /etc/modprobe.d/disable_modules.conf
    sudo sysctl -p
    echo -e "${MAGENTA}[+]${RESET} Unnecessary kernel modules disabled."

    sudo apt-get install fail2ban
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
    echo -e "${MAGENTA}[+]${RESET} Fail2Ban installed and running."


    echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" | sudo tee -a /etc/fstab
    sudo mount -o remount /tmp
    echo -e "${MAGENTA}[+]${RESET} /tmp mounted with security flags (noexec, nosuid, nodev)."

    sudo apt-get install unattended-upgrades
    sudo dpkg-reconfigure --priority=low unattended-upgrades
    echo -e "${MAGENTA}[+]${RESET} Automatic security updates configured."

    sudo find /etc/cron* /var/spool/cron/crontabs -type f
    sudo chmod 600 /etc/crontab /etc/cron.d/*
    echo -e "${MAGENTA}[+]${RESET} Cron job security hardening applied."


    sudo apt-get autoremove -y
    sudo apt-get clean
    echo -e "${MAGENTA}[+]${RESET} Unnecessary packages removed and cache cleaned."

    sudo apt-get install auditd
    sudo systemctl enable auditd
    sudo systemctl start auditd
    echo -e "${MAGENTA}[+]${RESET} Auditd installed and running for system auditing."

    sudo chmod 644 /etc/passwd
    sudo chmod 640 /etc/shadow
    sudo chmod 440 /etc/sudoers
    echo -e "${MAGENTA}[+]${RESET} Critical system file permissions set correctly."

    sudo chmod 600 /var/log/auth.log
    sudo chmod 640 /var/log/syslog
    sudo chmod 755 /etc
    echo -e "${MAGENTA}[+]${RESET} Log file permissions secured."

    sudo apt-get install ntp
    sudo systemctl enable ntp
    sudo systemctl start ntp
    echo -e "${MAGENTA}[+]${RESET} NTP configured and running."

    gnome-terminal -- bash -c "
        echo -e '${MAGENTA}[+]${RESET} Updating package list...';
        sudo apt-get update -y;

        echo -e '${MAGENTA}[+]${RESET} Upgrading packages...';
        sudo apt-get upgrade -y;

        echo -e '${MAGENTA}[+]${RESET} Upgrading distribution...';
        sudo apt-get dist-upgrade -y;

        echo -e '${MAGENTA}[+]${RESET} Removing unnecessary packages...';
        sudo apt-get autoremove -y;
        sudo apt-get clean;

        echo -e '${MAGENTA}[+]${RESET} Checking for kernel updates...';
        sudo apt-get install --install-recommends linux-generic;

        echo -e '${MAGENTA}[+]${RESET} Checking if a reboot is required...';
        if [ -f /var/run/reboot-required ]; then
            echo -e '${MAGENTA}[!]${RESET} A reboot is required to complete the update.';
        else
            echo -e '${MAGENTA}[+]${RESET} System is fully updated. No reboot needed.';
        fi;

        echo -e '${MAGENTA}[+]${RESET} System update complete!';
        read -p 'Finished system updates!';
    "
    read -p 'Finished!';

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
    if id "$u" &>/dev/null; then
        sudo deluser "$u"
        read -p "User deleted. Press enter..."
    else
        read -p "User not found. Press enter..."
        deleteUser()
    fi
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
    if id "$u" &>/dev/null; then
        sudo usermod -aG sudo "$u"
        echo "$u is now admin."
        read -p "Press enter..."
    else
        read -p "User not found. Press enter..."
        makeAdmin()
    fi
}
removeAdmin() {
    read -p "Enter username: " u
    if id "$u" &>/dev/null; then
        sudo deluser "$u" sudo
        echo "$u is no longer admin."
        read -p "Press enter..."
    else
        read -p "User not found. Press enter..."
        removeAdmin()
    fi
}
disableUser() {
    read -p "Enter username: " u
    if id "$u" &>/dev/null; then
        sudo usermod -L "$u"
        echo "Disabled $u"
        read -p "Press enter..."
    else
        read -p "User not found. Press enter..."
        disableUser()
    fi
}
enableUser() {
    read -p "Enter username: " u
    if id "$u" &>/dev/null; then
        sudo usermod -U "$u"
        echo "Enabled $u"
        read -p "Press enter..."
    else
        read -p "User not found. Press enter..."
        enableUser()
    fi
}
resetUserPassword() {
    read -p "Enter username: " u
    if id "$u" &>/dev/null; then
        password=$(openssl rand -base64 12)
        echo "$u:$password" | sudo chpasswd
        echo "New password for $u: $password"
        read -p "Press enter..."
    else
        read -p "User not found. Press enter..."
        resetUserPassword()
    fi
}
expirePasswords() {
    for u in $(cut -d: -f1 /etc/passwd); do
        sudo chage -M 90 "$u" 2>/dev/null
    done
    echo "All users now have expiring passwords."
    read -p "Press enter..."
}




showMainMenu
