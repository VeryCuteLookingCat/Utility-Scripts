#!/bin/bash

MAGENTA="\033[95m"
RESET="\033[0m"

if [[ $EUID -ne 0 ]]; then
    echo -e "${MAGENTA}[!]${RESET} This script must be run as root."
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
    echo -e "${MAGENTA}[+]${RESET} Starting hardening.."

    # Helpers
    setSysctl() {
        local key="$1"
        local value="$2"
        if grep -q "^[[:space:]]*${key}[[:space:]]*=" /etc/sysctl.conf; then
            sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" /etc/sysctl.conf
        else
            echo "${key} = ${value}" >> /etc/sysctl.conf
        fi
    }
    addPamLine() {
        local file="$1"
        local line="$2"
        grep -qxF "$line" "$file" || echo "$line" >> "$file"
    }

    # the real guts
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    echo -e "${MAGENTA}[+]${RESET} Login settings updated."

    if [ -f /etc/pam.d/common-password ]; then
        if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
            sed -i 's/^password\s\+requisite\s\+pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 minlen=12/' /etc/pam.d/common-password
        else
            echo "password requisite pam_pwquality.so retry=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 minlen=12" >> /etc/pam.d/common-password
        fi
        echo -e "${MAGENTA}[+]${RESET} PAM password complexity enforced."
    else
        echo -e "${MAGENTA}[!]${RESET} /etc/pam.d/common-password not found, skipping PAM complexity."
    fi
    if [ -f /etc/pam.d/common-auth ]; then
        addPamLine /etc/pam.d/common-auth "auth required pam_faillock.so preauth silent deny=5 unlock_time=300"
        addPamLine /etc/pam.d/common-auth "auth [success=1 default=bad] pam_unix.so"
        addPamLine /etc/pam.d/common-auth "auth [default=die] pam_faillock.so authfail"
        addPamLine /etc/pam.d/common-auth "account required pam_faillock.so"
        echo -e "${MAGENTA}[+]${RESET} PAM lockout policy applied."
    else
        echo -e "${MAGENTA}[!]${RESET} PAM common-auth not found, skipping lockout policy."
    fi

    passwd -l root >/dev/null 2>&1 || true
    echo -e "${MAGENTA}[+]${RESET} Root account password locked (sudo is still usable)."

    if [ -f /etc/ssh/sshd_config ]; then
        sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config
        sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
        sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config

        # Banner
        echo "Authorized users only. All activities are monitored." > /etc/issue.net
        if grep -q "^#Banner none" /etc/ssh/sshd_config; then
            sed -i 's|^#Banner none|Banner /etc/issue.net|' /etc/ssh/sshd_config
        elif ! grep -q "^Banner " /etc/ssh/sshd_config; then
            echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
        fi

        sshService=""
        if systemctl list-unit-files | grep -q '^ssh\.service'; then
            sshService="ssh"
        elif systemctl list-unit-files | grep -q '^sshd\.service'; then
            sshService="sshd"
        fi

        if [ -n "$sshService" ]; then
            systemctl restart "$sshService" || echo -e "${MAGENTA}[!]${RESET} Failed to restart ${sshService}, check config syntax."
        else
            echo -e "${MAGENTA}[!]${RESET} No ssh/sshd systemd service found, skipping restart."
        fi

        echo -e "${MAGENTA}[+]${RESET} SSH security settings updated."
    else
        echo -e "${MAGENTA}[!]${RESET} /etc/ssh/sshd_config not found, skipping SSH hardening."
    fi

    setSysctl "net.ipv4.conf.all.accept_redirects" 0
    setSysctl "net.ipv4.conf.default.accept_redirects" 0
    setSysctl "net.ipv4.conf.all.send_redirects" 0
    setSysctl "net.ipv4.conf.default.send_redirects" 0
    setSysctl "net.ipv4.conf.all.rp_filter" 1
    setSysctl "net.ipv4.conf.default.rp_filter" 1
    setSysctl "net.ipv4.tcp_syncookies" 1
    setSysctl "fs.suid_dumpable" 0

    setSysctl "net.ipv6.conf.all.disable_ipv6" 1
    setSysctl "net.ipv6.conf.default.disable_ipv6" 1
    setSysctl "net.ipv6.conf.lo.disable_ipv6" 1

    sysctl -p >/dev/null 2>&1 || echo -e "${MAGENTA}[!]${RESET} sysctl -p reported warnings, review /etc/sysctl.conf."
    echo -e "${MAGENTA}[+]${RESET} Kernel network hardening applied."

    if grep -Rq "NOPASSWD" /etc/sudoers /etc/sudoers.d 2>/dev/null; then
        cp /etc/sudoers /etc/sudoers.bak.$(date +%s)
        sed -i 's/\(ALL\)[[:space:]]*NOPASSWD:/\1:/' /etc/sudoers
        for f in /etc/sudoers.d/*; do
            [ -f "$f" ] || continue
            sed -i 's/\(ALL\)[[:space:]]*NOPASSWD:/\1:/' "$f"
        done
        visudo -c >/dev/null 2>&1 || echo -e "${MAGENTA}[!]${RESET} visudo check failed, sudoers may be invalid!"
        echo -e "${MAGENTA}[+]${RESET} Sudoers updated to require passwords (where possible)."
    else
        echo -e "${MAGENTA}[+]${RESET} No NOPASSWD rules found in sudoers."
    fi

    if ! command -v ufw >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1
        apt-get install -y ufw >/dev/null 2>&1
    fi

    ufw --force enable >/dev/null 2>&1
    echo -e "${MAGENTA}[+]${RESET} UFW firewall enabled."

    if ufw app list 2>/dev/null | grep -q "OpenSSH"; then
        ufw allow OpenSSH >/dev/null 2>&1
    else
        ufw allow 22/tcp >/dev/null 2>&1
    fi

    if ufw app list 2>/dev/null | grep -q "Nginx Full"; then
        ufw allow 'Nginx Full' >/dev/null 2>&1
    fi

    ufw deny 3389 >/dev/null 2>&1 || true
    ufw deny 445  >/dev/null 2>&1 || true
    ufw deny 139  >/dev/null 2>&1 || true

    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    echo -e "${MAGENTA}[+]${RESET} UFW rules configured."

    for svc in cups avahi-daemon; do
        if systemctl list-unit-files | grep -q "^${svc}\.service"; then
            systemctl disable "$svc" >/dev/null 2>&1 || true
            systemctl stop "$svc"    >/dev/null 2>&1 || true
        fi
    done
    echo -e "${MAGENTA}[+]${RESET} Unnecessary services (cups, avahi) handled if present."

    if command -v aa-status >/dev/null 2>&1 || [ -d /etc/apparmor.d ]; then
        systemctl enable apparmor >/dev/null 2>&1 || true
        systemctl start apparmor  >/dev/null 2>&1 || true
        echo -e "${MAGENTA}[+]${RESET} AppArmor enabled (where available)."
    else
        echo -e "${MAGENTA}[!]${RESET} AppArmor not installed/configured on this system."
    fi

    mkdir -p /etc/modprobe.d
    for mod in dccp rds sctp; do
        if ! grep -q "^install ${mod} /bin/true" /etc/modprobe.d/disable_modules.conf 2>/dev/null; then
            echo "install ${mod} /bin/true" >> /etc/modprobe.d/disable_modules.conf
        fi
    done
    echo -e "${MAGENTA}[+]${RESET} Kernel modules dccp/rds/sctp disabled."

    if ! command -v fail2ban-client >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1
        apt-get install -y fail2ban >/dev/null 2>&1 || echo -e "${MAGENTA}[!]${RESET} Failed to install fail2ban."
    fi
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl start  fail2ban >/dev/null 2>&1 || true
    echo -e "${MAGENTA}[+]${RESET} Fail2Ban installed/started (if available)."

    if ! grep -qE '^[^#]*[[:space:]]/tmp[[:space:]]+tmpfs' /etc/fstab; then
        echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        # Try remounting, but don't die if it fails
        mount -o remount /tmp 2>/dev/null || echo -e "${MAGENTA}[!]${RESET} Could not remount /tmp, reboot may be required."
    fi
    echo -e "${MAGENTA}[+]${RESET} /tmp entry ensured in fstab."

    if ! dpkg -l | grep -q "^ii  unattended-upgrades "; then
        apt-get update -y >/dev/null 2>&1
        apt-get install -y unattended-upgrades >/dev/null 2>&1
    fi
    echo -e "${MAGENTA}[+]${RESET} Automatic security updates package present."

    [ -f /etc/crontab ] && chmod 600 /etc/crontab
    [ -d /etc/cron.d ]  && chmod 600 /etc/cron.d/* 2>/dev/null || true
    echo -e "${MAGENTA}[+]${RESET} Cron job permissions hardened."

    apt-get autoremove -y  >/dev/null 2>&1
    apt-get clean          >/dev/null 2>&1
    echo -e "${MAGENTA}[+]${RESET} Unnecessary packages removed and cache cleaned."

    if ! dpkg -l | grep -q "^ii  auditd "; then
        apt-get update -y >/dev/null 2>&1
        apt-get install -y auditd >/dev/null 2>&1 || echo -e "${MAGENTA}[!]${RESET} Failed to install auditd."
    fi
    systemctl enable auditd >/dev/null 2>&1 || true
    systemctl start  auditd >/dev/null 2>&1 || true
    echo -e "${MAGENTA}[+]${RESET} Auditd installed and running (if available)."

    [ -f /etc/passwd ] && chmod 644 /etc/passwd
    [ -f /etc/shadow ] && chmod 640 /etc/shadow
    [ -f /etc/sudoers ] && chmod 440 /etc/sudoers
    echo -e "${MAGENTA}[+]${RESET} Critical system file permissions set."

    [ -f /var/log/auth.log ] && chmod 600 /var/log/auth.log
    [ -f /var/log/syslog ]   && chmod 640 /var/log/syslog
    echo -e "${MAGENTA}[+]${RESET} Log file permissions secured."

    if command -v timedatectl >/dev/null 2>&1; then
        timedatectl set-ntp true >/dev/null 2>&1 || true
        echo -e "${MAGENTA}[+]${RESET} Systemd time sync enabled."
    else
        echo -e "${MAGENTA}[!]${RESET} timedatectl not available; time sync not configured."
    fi

    echo -e "${MAGENTA}[+]${RESET} Updating package list..."
    apt-get update -y

    echo -e "${MAGENTA}[+]${RESET} Upgrading packages..."
    apt-get upgrade -y

    echo -e "${MAGENTA}[+]${RESET} Dist-upgrade (kernel etc)..."
    apt-get dist-upgrade -y

    apt-get autoremove -y
    apt-get clean

    if [ -f /var/run/reboot-required ]; then
        echo -e "${MAGENTA}[!]${RESET} Reboot is required to complete updates."
    else
        echo -e "${MAGENTA}[+]${RESET} System fully updated; no reboot required."
    fi

    echo -e "${MAGENTA}[+]${RESET} Baseline hardening complete."
    read -p "Finished! Press enter..."
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

        printUsers

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
        deluser "$u"
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
    adduser --disabled-password --gecos "" "$u"
    echo "$u:$password" | chpasswd

    echo "Created user: $u"
    echo "Password: $password"
    read -p "Press enter..."
}
makeAdmin() {
    read -p "Enter username: " u
    if id "$u" &>/dev/null; then
        usermod -aG sudo "$u"
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
        deluser "$u" sudo
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
        usermod -L "$u"
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
        usermod -U "$u"
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
        echo "$u:$password" | chpasswd
        echo "New password for $u: $password"
        read -p "Press enter..."
    else
        read -p "User not found. Press enter..."
        resetUserPassword()
    fi
}
expirePasswords() {
    for u in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
        chage -M 90 "$u"
    done
    echo "All users now have expiring passwords."
    read -p "Press enter..."
}




showMainMenu
