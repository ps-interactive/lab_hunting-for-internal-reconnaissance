import os
import sys
import subprocess
import re
from pathlib import Path
import pwd
# ---------------------------- Challenge 1 Functions ----------------------------

def challenge1_step2_new_users_groups():
    """Challenge 1, Step 2: Check for unauthorized new users or groups."""
    # Default and additional valid Ubuntu users and groups
    valid_users = {
        "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
        "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
        "nobody", "systemd-network", "systemd-resolve", "syslog", "_apt",
        "messagebus", "uuidd", "systemd-timesync", "srw134", "landscape", "tss",
        "ntp", "pollinate", "sshd", "usbmux", "fwupd-refresh", "lxd", "tcpdump", "ec2-instance-connect", "_chrony", "dnsmasq", "ubuntu"
    }
    valid_groups = {
        "root", "daemon", "bin", "sys", "adm", "tty", "disk", "lp", "mail",
        "news", "uucp", "man", "proxy", "kmem", "dialout", "fax", "voice",
        "cdrom", "floppy", "tape", "sudo", "audio", "dip", "www-data",
        "backup", "operator", "list", "irc", "src", "gnats", "shadow",
        "utmp", "video", "sasl", "plugdev", "staff", "games", "users",
        "nogroup", "input", "systemd-journal", "systemd-network",
        "systemd-resolve", "crontab", "messagebus", "uuidd", "systemd-timesync",
        "landscape", "lxd", "render", "tcpdump", "kvm", "syslog", "ntp",
        "fwupd-refresh", "sgx", "tss", "srw134", "_ssh", "netdev", "_chrony", "admin", "ubuntu", "docker"
    }

    try:
        # Extract the list of current users
        result_users = subprocess.run(
            "awk -F':' '{ print $1}' /etc/passwd | sort",
            shell=True,
            stdout=subprocess.PIPE,
            text=True,
            check=True
        )
        current_users = set(result_users.stdout.splitlines())

        # Extract the list of current groups
        result_groups = subprocess.run(
            "awk -F':' '{ print $1}' /etc/group | sort",
            shell=True,
            stdout=subprocess.PIPE,
            text=True,
            check=True
        )
        current_groups = set(result_groups.stdout.splitlines())

        # Identify non-default users and groups
        non_default_users = current_users - valid_users
        non_default_groups = current_groups - valid_groups

        # Save the non-default users and groups to files
        with open("non_default_users.txt", "w") as f:
            for user in non_default_users:
                f.write(f"{user} (Non-Default)\n")

        with open("non_default_groups.txt", "w") as f:
            for group in non_default_groups:
                f.write(f"{group} (Non-Default)\n")

        # Display non-default users and groups
        if non_default_users:
            print("Non-Default Users:")
            for user in non_default_users:
                print(f"{user} (Non-Default)")

        if non_default_groups:
            print("\nNon-Default Groups:")
            for group in non_default_groups:
                print(f"{group} (Non-Default)")

        if not non_default_users and not non_default_groups:
            print("No non-default users or groups found.")

        print("Non-default users and groups have been saved to 'non_default_users.txt' and 'non_default_groups.txt'.")

    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e.cmd}")
    except Exception as e:
        print(f"Error listing users or groups: {e}")


def challenge1_step3_sudoers_file():
    """Challenge 1, Step 3: Examine the /etc/sudoers file and /etc/sudoers.d directory for unauthorized entries."""
    try:
        # Read the sudoers file
        result = subprocess.run(
            ["sudo", "cat", "/etc/sudoers"],
            stdout=subprocess.PIPE,
            text=True,
            check=True
        )
        sudoers_content = result.stdout

        # Define regex patterns for default permissible lines
        permissible_patterns = [
            r"^Defaults\s+env_reset$",
            r"^Defaults\s+mail_badpass$",
            r"^Defaults\s+secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\"$",
            r"^Defaults\s+use_pty$",
            r"^root\s+ALL=\(ALL:ALL\)\s+ALL$",
            r"^%admin\s+ALL=\(ALL\)\s+ALL$",
            r"^%sudo\s+ALL=\(ALL:ALL\)\s+ALL$",
            r"^@includedir\s+/etc/sudoers\.d$"
        ]

        # Check for unauthorized entries in the sudoers content
        unauthorized_entries = []

        # Split content into lines and analyze each line
        for line in sudoers_content.splitlines():
            # Ignore comments and blank lines
            stripped_line = line.strip()
            if stripped_line.startswith("#") or not stripped_line:
                continue

            # Check if the line matches any of the permissible patterns
            if not any(re.match(pattern, stripped_line) for pattern in permissible_patterns):
                unauthorized_entries.append(line)

        # Output any unauthorized entries found
        if unauthorized_entries:
            print("Unauthorized entries found in '/etc/sudoers':")
            for entry in unauthorized_entries:
                print(entry)
        else:
            print("No unauthorized entries found in '/etc/sudoers'.")

        # Verify the contents of /etc/sudoers.d directory
        sudoers_d_path = "/etc/sudoers.d"
        sudoers_d_entries = os.listdir(sudoers_d_path)
        unauthorized_files = [entry for entry in sudoers_d_entries if entry not in ["90-cloud-init-users", "README"]]


        if unauthorized_files:
            print("Unauthorized files found in '/etc/sudoers.d':")
            for entry in unauthorized_files:
                print(entry)
        else:
            print("No unauthorized files found in '/etc/sudoers.d'.")

    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e.cmd}")
    except Exception as e:
        print(f"Error accessing /etc/sudoers or /etc/sudoers.d: {e}")

def challenge1_step4_setuid_setgid_files():
    """Challenge 1, Step 4: Search for unexpected Setuid and Setgid files, excluding standard system files."""
    try:
        # List of expected Setuid and Setgid files on Ubuntu, including Snap and PAM-related entries
        expected_files = {
            "/usr/bin/chage", "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/gpasswd", "/usr/bin/mount",
            "/usr/bin/newgrp", "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/umount", "/usr/bin/sudo",
            "/usr/bin/crontab", "/usr/bin/expiry", "/usr/bin/pkexec", "/usr/bin/fusermount3",
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/lib/openssh/ssh-keysign",
            "/usr/lib/x86_64-linux-gnu/utempter/utempter", "/usr/libexec/polkit-agent-helper-1",
            "/snap/core18/2829/bin/mount", "/snap/core18/2829/bin/ping", "/snap/core18/2829/bin/su",
            "/snap/core18/2829/bin/umount", "/snap/core18/2829/sbin/pam_extrausers_chkpwd",
            "/snap/core18/2829/sbin/unix_chkpwd", "/snap/core18/2829/usr/bin/chage",
            "/snap/core18/2829/usr/bin/chfn", "/snap/core18/2829/usr/bin/chsh", "/snap/core18/2829/usr/bin/expiry",
            "/snap/core18/2829/usr/bin/gpasswd", "/snap/core18/2829/usr/bin/newgrp", "/snap/core18/2829/usr/bin/passwd",
            "/snap/core18/2829/usr/bin/ssh-agent", "/snap/core18/2829/usr/bin/sudo", "/snap/core18/2829/usr/bin/wall",
            "/snap/core18/2829/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/snap/core18/2829/usr/lib/openssh/ssh-keysign",
            "/snap/snapd/21759/usr/lib/snapd/snap-confine", "/snap/core20/2379/usr/bin/chage",
            "/snap/core20/2379/usr/bin/chfn", "/snap/core20/2379/usr/bin/chsh", "/snap/core20/2379/usr/bin/expiry",
            "/snap/core20/2379/usr/bin/gpasswd", "/snap/core20/2379/usr/bin/mount", "/snap/core20/2379/usr/bin/newgrp",
            "/snap/core20/2379/usr/bin/passwd", "/snap/core20/2379/usr/bin/ssh-agent", "/snap/core20/2379/usr/bin/su",
            "/snap/core20/2379/usr/bin/sudo", "/snap/core20/2379/usr/bin/umount", "/snap/core20/2379/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
            "/snap/core20/2379/usr/lib/openssh/ssh-keysign", "/snap/core20/2379/usr/sbin/pam_extrausers_chkpwd",
            "/snap/core20/2379/usr/sbin/unix_chkpwd", "/usr/lib/snapd/snap-confine", "/usr/bin/ssh-agent",
            "/snap/core20/1822/usr/bin/chage", "/snap/core20/1822/usr/bin/chfn", "/snap/core20/1822/usr/bin/chsh",
            "/snap/core20/1822/usr/bin/expiry", "/snap/core20/1822/usr/bin/gpasswd", "/snap/core20/1822/usr/bin/mount",
            "/snap/core20/1822/usr/bin/newgrp", "/snap/core20/1822/usr/bin/passwd", "/snap/core20/1822/usr/bin/su",
            "/snap/core20/1822/usr/bin/sudo", "/snap/core20/1822/usr/bin/umount", "/snap/core20/1822/usr/bin/wall",
            "/snap/core20/1822/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/snap/core20/1822/usr/lib/openssh/ssh-keysign",
            "/snap/core20/1822/usr/lib/snapd/snap-confine", "/snap/core20/1822/usr/bin/ssh-agent",
            "/snap/core20/1822/usr/sbin/pam_extrausers_chkpwd", "/snap/core20/1822/usr/sbin/unix_chkpwd",
            "/usr/sbin/unix_chkpwd", "/usr/sbin/pam_extrausers_chkpwd", "/usr/bin/at"
        }


        # Run the find command, excluding problematic directories like /proc, /sys, and /dev
        result = subprocess.run(
            "sudo find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -perm /6000 -type f -exec ls -ld {} \\;",
            shell=True,
            stdout=subprocess.PIPE,
            text=True,
            check=True
        )

        # Filter out expected files from the results
        unexpected_files = []
        for line in result.stdout.splitlines():
            # Extract the file path (last item in the line)
            file_path = line.split()[-1]
            if file_path not in expected_files:
                unexpected_files.append(line)

        # Output unexpected Setuid and Setgid files found
        if unexpected_files:
            print("Unexpected Setuid and Setgid files found (excluding standard system files):")
            for entry in unexpected_files:
                print(entry)
            with open("setuid_setgid_files.txt", "w") as f:
                f.write("\n".join(unexpected_files))
            print("Unexpected files have been saved to 'setuid_setgid_files.txt'.")
        else:
            print("No unexpected Setuid or Setgid files found.")

    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e.cmd}")
    except Exception as e:
        print(f"Error finding Setuid and Setgid files: {e}")

def challenge1_step5_ssh_keys():
    """Challenge 1, Step 5: Inspect .ssh directories for unauthorized keys."""
    output_file = "ssh_keys.txt"
    with open(output_file, "w") as f:
        user_dirs = list(Path("/home").glob("*/")) + [Path("/root")]

        for user_dir in user_dirs:
            ssh_dir = user_dir / ".ssh"
            if ssh_dir.exists():
                try:
                    for item in ssh_dir.iterdir():
                        log_entry = f"User: {user_dir.name} | File: {item}"
                        print(log_entry)
                        f.write(log_entry + "\n")
                except Exception as e:
                    print(f"Error accessing {ssh_dir}: {e}")
    print(f"SSH keys and configurations have been saved to '{output_file}'.")

def challenge1_step6_failed_logins():
    try:
        # Use journalctl with grep to find lines that contain "Failed" for error-level messages
        result = subprocess.run(
            "sudo journalctl -p err --no-pager | grep 'Failed'",
            stdout=subprocess.PIPE,
            text=True,
            shell=True  # Enables use of shell to allow piping
        )
        
        failed_logins = result.stdout
        print("Failed login attempts:")
        print(failed_logins)
        
    except Exception as e:
        print(f"Error analyzing authentication logs: {e}")


def challenge1_step7_system_logs():
    try:
        # Search syslog for error, fail, warning, or critical messages
        result = subprocess.run(
            "sudo journalctl -p err..crit | grep 'ERROR\|FAIL\|WARNING\|CRITICAL'",
            shell=True,
            stdout=subprocess.PIPE,
            text=True,
            check=True
        )
        syslog_errors = result.stdout
        with open("syslog_errors.txt", "w") as f:
            f.write(syslog_errors)
        print("System log entries with errors or warnings:")
        print(syslog_errors)
        print("Entries have been saved to 'syslog_errors.txt'.")
    except subprocess.CalledProcessError as e:
        print("No matching entries found in syslog.")
    except Exception as e:
        print(f"Error reviewing system logs: {e}")


def challenge1_step8_hidden_files():
    """Challenge 1, Step 10: Search for uncommon hidden files in user directories."""
    output_file = "uncommon_hidden_files.txt"

    # Expanded list of common hidden files in Linux home directories
    common_hidden_files = {
        ".bashrc", ".profile", ".bash_logout", ".bash_history",
        ".ssh", ".cache", ".config", ".local", ".viminfo",
        ".sudo_as_admin_successful"
    }

    with open(output_file, "w") as f:
        try:
            # Find hidden files in /home and /root directories
            result = subprocess.run(
                ["find", "/home", "/root", "-name", ".*", "-type", "f"],
                stdout=subprocess.PIPE,
                text=True
            )
            hidden_files = result.stdout.splitlines()

            # Filter out commonly found hidden files
            uncommon_hidden_files = [
                file for file in hidden_files if os.path.basename(file) not in common_hidden_files
            ]

            # Display and save the uncommon hidden files
            print("Uncommon hidden files found in user directories:")
            for file in uncommon_hidden_files:
                print(file)
                f.write(file + "\n")

        except Exception as e:
            print(f"Error searching for hidden files: {e}")

    print(f"Uncommon hidden files have been saved to '{output_file}'.")


def challenge1_step9_sensitive_file_access():

    output_file = "bash_history_user_commands.txt"
    with open(output_file, "a") as f:
        user_dirs = list(Path("/home").glob("*/")) + [Path("/root")]

        for user_dir in user_dirs:
            username = user_dir.name
            history_file = user_dir / ".bash_history"
            if history_file.exists():
                try:
                    with history_file.open() as file:
                        for line in file:
                            if "/etc/passwd" in line or "/etc/shadow" in line:
                                log_entry = f"User: {username} | Command: {line.strip()}"
                                print(log_entry)
                                f.write(log_entry + "\n")
                except Exception as e:
                    print(f"Error accessing {history_file}: {e}")
    print(f"Commands accessing sensitive files have been appended to '{output_file}'.")


def challenge1_step10_cron_jobs_services():
    """Challenge 1, Step 13: Investigate cron jobs and system services for persistence."""
    try:
        # Dictionary to hold cron jobs for each user
        all_cron_jobs = {}

        # Get a list of all users on the system
        users = [user.pw_name for user in pwd.getpwall() if user.pw_uid >= 1000]

        # Check cron jobs for each user
        for user in users:
            try:
                result_cron = subprocess.run(
                    ["crontab", "-l", "-u", user],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                if result_cron.returncode == 0:
                    all_cron_jobs[user] = result_cron.stdout
                else:
                    all_cron_jobs[user] = "No cron jobs found."
            except Exception as e:
                all_cron_jobs[user] = f"Error retrieving cron jobs: {e}"

        # Display all user-specific cron jobs
        print("User-specific cron jobs:")
        for user, cron_jobs in all_cron_jobs.items():
            print(f"\nCron jobs for user {user}:")
            print(cron_jobs)

        # Check system-wide cron jobs in /etc/crontab
        print("\nSystem-wide cron jobs in /etc/crontab:")
        try:
            with open("/etc/crontab") as f:
                system_cron_jobs = f.read()
                print(system_cron_jobs)
        except Exception as e:
            print(f"Error reading /etc/crontab: {e}")

        # Check system-wide cron jobs in /etc/cron.d/
        print("\nSystem-wide cron jobs in /etc/cron.d/:")
        try:
            cron_d_jobs = subprocess.run(
                ["cat", "/etc/cron.d/*"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            ).stdout
            print(cron_d_jobs)
        except Exception as e:
            print(f"Error reading /etc/cron.d/: {e}")

    except Exception as e:
        print(f"Error checking cron jobs and services: {e}")

# ---------------------------- Challenge 2 Functions ----------------------------

def challenge2_step1_network_commands():
    """Challenge 2, Step 1: Search bash history for network scanning commands."""
    output_file = "bash_history_network_commands.txt"
    with open(output_file, "a") as f:
        user_dirs = list(Path("/home").glob("*/")) + [Path("/root")]

        for user_dir in user_dirs:
            username = user_dir.name
            history_file = user_dir / ".bash_history"
            if history_file.exists():
                try:
                    with history_file.open() as file:
                        for line in file:
                            if any(cmd in line for cmd in ["nmap", "netstat", "ping"]):
                                log_entry = f"User: {username} | Command: {line.strip()}"
                                print(log_entry)
                                f.write(log_entry + "\n")
                except Exception as e:
                    print(f"Error accessing {history_file}: {e}")
    print(f"Network scanning commands have been appended to '{output_file}'.")

def challenge2_step2_active_connections():
    """Challenge 2, Step 2: Investigate active network connections and open ports."""
    try:
        # List all active network connections and open ports
        result = subprocess.run(
            ["netstat", "-tulnp"],
            stdout=subprocess.PIPE,
            text=True
        )
        connections = result.stdout
        print("Active network connections and open ports:")
        print(connections)
    except Exception as e:
        print(f"Error listing network connections: {e}")

def challenge2_step4_arp_cache():
    try:
        # Get ARP cache entries
        result = subprocess.run(
            ["arp", "-a"],
            stdout=subprocess.PIPE,
            text=True
        )
        arp_cache = result.stdout
        with open("arp_cache.txt", "w") as f:
            f.write(arp_cache)
        print("ARP cache entries:")
        print(arp_cache)
        print("ARP cache has been saved to 'arp_cache.txt'.")
    except Exception as e:
        print(f"Error analyzing ARP cache: {e}")

def challenge2_step3_listening_services():
    try:
        # List all listening TCP ports and associated processes
        result = subprocess.run(
            ["sudo", "lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"],
            stdout=subprocess.PIPE,
            text=True
        )
        listening_services = result.stdout
        with open("listening_services.txt", "w") as f:
            f.write(listening_services)
        print("Listening services:")
        print(listening_services)
        print("Listening services have been saved to 'listening_services.txt'.")
    except Exception as e:
        print(f"Error checking listening services: {e}")

def challenge2_step5_firewall_logs():
    try:
        # Search firewall logs for dropped packets
        result = subprocess.run(
            "sudo journalctl | grep 'DROP'",
            stdout=subprocess.PIPE,
            text=True
        )
        firewall_logs = result.stdout
        with open("firewall_logs.txt", "w") as f:
            f.write(firewall_logs)
        print("Firewall log entries for dropped packets or blocked scans:")
        print(firewall_logs)
        print("Firewall logs have been saved to 'firewall_logs.txt'.")
    except Exception as e:
        print(f"Error checking firewall logs: {e}")

def challenge2_step6_temp_directories():
    """Challenge 2, Step 8: Search temporary directories for uploaded reconnaissance tools."""
    output_file = "temp_directory_analysis.txt"
    with open(output_file, "w") as f:
        try:
            # Find reconnaissance tools in temporary directories
            result = subprocess.run(
                ["find", "/tmp", "/var/tmp", "-type", "f", "-name", "nmap", "-o", "-name", "netcat"],
                stdout=subprocess.PIPE,
                text=True
            )
            temp_files = result.stdout
            print("Reconnaissance tools found in temporary directories:")
            print(temp_files)
            f.write(temp_files)
        except Exception as e:
            print(f"Error searching temporary directories: {e}")
    print(f"Reconnaissance tools have been saved to '{output_file}'.")

def challenge2_step7_recently_modified_files():
    """Challenge 2, Step 9: Investigate recently modified files in /tmp and /var/tmp."""
    output_file = "recently_modified_files.txt"
    with open(output_file, "w") as f:
        try:
            # Find files modified in the last day
            result = subprocess.run(
                ["find", "/tmp", "/var/tmp", "-type", "f", "-mtime", "-1"],
                stdout=subprocess.PIPE,
                text=True
            )
            recent_files = result.stdout
            print("Recently modified files in /tmp and /var/tmp:")
            print(recent_files)
            f.write(recent_files)
        except Exception as e:
            print(f"Error listing recently modified files: {e}")
    print(f"Recently modified files have been saved to '{output_file}'.")

def challenge2_step8_ssh_logs():
    """Challenge 2, Step 10: Inspect SSH configuration and logs for unauthorized access."""
    try:
        # Get accepted and failed SSH login attempts
        result_accepted = subprocess.run(
            ["sudo", "grep", "Accepted", "/var/log/auth.log"],
            stdout=subprocess.PIPE,
            text=True
        )
        result_failed = subprocess.run(
            ["sudo", "grep", "Failed", "/var/log/auth.log"],
            stdout=subprocess.PIPE,
            text=True
        )
        with open("ssh_access.log", "w") as f:
            f.write(result_accepted.stdout)
        with open("ssh_failed.log", "w") as f:
            f.write(result_failed.stdout)
        print("SSH accepted login attempts:")
        print(result_accepted.stdout)
        print("SSH failed login attempts:")
        print(result_failed.stdout)
        print("SSH logs have been saved to 'ssh_access.log' and 'ssh_failed.log'.")
    except Exception as e:
        print(f"Error analyzing SSH logs: {e}")

def challenge2_step9_tunneling_processes():
    """Challenge 2, Step 11: Search for tunneling or port forwarding processes."""
    try:
        # List all running processes
        result = subprocess.run(
            ["ps", "aux"],
            stdout=subprocess.PIPE,
            text=True
        )
        processes = result.stdout
        tunneling_processes = []
        for line in processes.splitlines():
            if re.search(r'ssh.*\-(R|L|D)', line) or 'nc' in line or 'ncat' in line:
                tunneling_processes.append(line)
        with open("tunneling_processes.txt", "w") as f:
            f.write('\n'.join(tunneling_processes))
        print("Potential tunneling or port forwarding processes:")
        print('\n'.join(tunneling_processes))
        print("Tunneling processes have been saved to 'tunneling_processes.txt'.")
    except Exception as e:
        print(f"Error searching for tunneling processes: {e}")

def challenge2_step10_at_jobs():
    """Challenge 2, Step 12: Check for suspicious scheduled tasks in at jobs."""
    try:
        # List all scheduled at jobs
        result = subprocess.run(
            ["sudo", "atq"],
            stdout=subprocess.PIPE,
            text=True
        )
        at_jobs = result.stdout
        with open("at_jobs.txt", "w") as f:
            f.write(at_jobs)
        print("Scheduled at jobs:")
        print(at_jobs)
        print("At jobs have been saved to 'at_jobs.txt'.")
    except Exception as e:
        print(f"Error checking at jobs: {e}")

def challenge2_step11_hosts_file():
    """Challenge 2, Step 13: Examine /etc/hosts for unauthorized changes."""
    try:
        # Read the /etc/hosts file
        with open("/etc/hosts", "r") as f:
            hosts_content = f.read()
        with open("hosts_file.txt", "w") as f:
            f.write(hosts_content)
        print("Contents of '/etc/hosts':")
        print(hosts_content)
        print("Contents have been saved to 'hosts_file.txt'.")
    except Exception as e:
        print(f"Error accessing /etc/hosts: {e}")


# ---------------------------- Main Function ----------------------------

def main(challenge, step):
    if challenge == "1":
        if step == "2":
            challenge1_step2_new_users_groups()
        elif step == "3":
            challenge1_step3_sudoers_file()
        elif step == "4":
            challenge1_step4_setuid_setgid_files()
        elif step == "5":
            challenge1_step5_ssh_keys()
        elif step == "6":
            challenge1_step6_failed_logins()
        elif step == "7":
            challenge1_step7_system_logs()
        elif step == "8":
            challenge1_step8_hidden_files()
        elif step == "9":
            challenge1_step9_sensitive_file_access()
        elif step == "10":
            challenge1_step10_cron_jobs_services()
        else:
            print("Invalid step number for Challenge 1.")
    elif challenge == "2":
        if step == "1":
            challenge2_step1_network_commands()
        elif step == "2":
            challenge2_step2_active_connections()
        elif step == "4":
            challenge2_step4_arp_cache()
        elif step == "3":
            challenge2_step3_listening_services()
        elif step == "5":
            challenge2_step5_firewall_logs()
        elif step == "6":
            challenge2_step6_temp_directories()
        elif step == "7":
            challenge2_step7_recently_modified_files()
        elif step == "8":
            challenge2_step8_ssh_logs()
        elif step == "9":
            challenge2_step9_tunneling_processes()
        elif step == "10":
            challenge2_step10_at_jobs()
        elif step == "11":
            challenge2_step11_hosts_file()
        elif step == "12":
            challenge2_step12_environment_variables()
        else:
            print("Invalid step number for Challenge 2.")
    else:
        print("Invalid challenge number. Use '1' for Challenge 1 or '2' for Challenge 2.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <challenge_number> <step_number>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
