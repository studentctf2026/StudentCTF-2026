#!/usr/bin/python3
import socket
import threading
import time
import sys

KEY = "5Z507SIXfUZOkVLO"
FLAG = "7u38PKgtNjFWi+OKqp88igSzDzF/T5FaeOKOAQw1TrwQkie+wfOVF2R/OgmanobEZNP90aIYQA=="
HOST = '0.0.0.0'
PORT = 4444

def handle_client(client_socket, client_address):
    try:
        print(f"[+] Connection from {client_address}")
        client_socket.sendall((FLAG + '\n').encode('utf-8'))
        print(f"[+] Flag sent to {client_address}")
        time.sleep(0.5)

        client_socket.sendall((KEY + '\n').encode('utf-8'))
        print(f"[+] Key sent to {client_address}")
        
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        client_socket.close()
        print(f"[-] Disconnected {client_address}")

def start_server():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        
        print(f"[+] Server started on {HOST}:{PORT}")
        print(f"[+] Key: {KEY} (client ignores)")
        print(f"[+] Flag: {FLAG}")
        print("[+] Waiting for connections... (Ctrl+C to stop)\n")
        
        while True:
            client, address = server.accept()
            thread = threading.Thread(target=handle_client, args=(client, address))
            thread.daemon = True
            thread.start()
            
    except KeyboardInterrupt:
        print("\n[+] Server stopped")
    except Exception as e:
        print(f"[-] Server error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        FLAG = sys.argv[1]
        print(f"[*] Using flag: {FLAG}")
    
    if len(sys.argv) > 2:
        KEY = sys.argv[2]
        print(f"[*] Using key: {KEY}")
    
    start_server()