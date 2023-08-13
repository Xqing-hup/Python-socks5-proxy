from socket import socket, inet_aton, inet_ntoa, AF_INET, SOCK_STREAM
from struct import unpack, pack
from datetime import datetime
from threading import Thread
from json import loads

with open("config.json", "r") as server_config:
    server_config = loads(server_config.read())
    set_passwd = server_config["Passwd"]
    set_user = server_config["User"]
    set_ip = server_config["Server IP"]
    set_port = server_config["Server Port"]
    verify_code = server_config["Verify"]
client_verify_ok = []


def timelog():
    date = str(datetime.now()).split(".")[0]
    return date


def forwarding(client, server, server_addr, domain, port):
    try:
        while True:
            data = client.recv(4096)
            if not data:
                break
            server.sendall(data)
            print(f'[{timelog()}] Request: {server_addr[0]}:{server_addr[1]} <- {domain}:{port}')
    except ConnectionAbortedError:
        client.close()
        server.close()
    except OSError:
        client.close()
        server.close()
    finally:
        client.close()
        server.close()


def processing_data(server_new, server_addr):
    try:
        recvdata = server_new.recv(1024)
        port = unpack("!H", recvdata[-2:])[0]
        if recvdata[3] == 3:  # 域名模式
            domain = recvdata[5:5 + recvdata[4]].decode()
            remote_socket = socket(AF_INET, SOCK_STREAM)
            remote_socket.connect((domain, port))
            bind_address = remote_socket.getsockname()
            response = bytearray([0x05, 0x00, 0x00, 1])
            response += inet_aton(remote_socket.getsockname()[0]) + pack('!H', bind_address[1])
            server_new.sendall(response)
            Thread(target=forwarding, args=(server_new, remote_socket, server_addr, domain, port)).start()
            while True:
                data = remote_socket.recv(5120)
                if not data:
                    break
                server_new.sendall(data)
                print(f'[{timelog()}] Response: {domain}:{port} -> {server_addr[0]}:{server_addr[1]} Mode: Domain')
        elif recvdata[3] == 1:  # IP模式
            ip = inet_ntoa(recvdata[4:8])
            print("IP 模式")
            remote_socket = socket(AF_INET, SOCK_STREAM)
            remote_socket.connect((ip, port))
            bind_address = remote_socket.getsockname()
            response = bytearray([0x05, 0x00, 0x00, 1])
            response += inet_aton(remote_socket.getsockname()[0]) + pack('!H', bind_address[1])
            server_new.sendall(response)
            Thread(target=forwarding, args=(server_new, remote_socket, server_addr, ip, port)).start()
            while True:
                data = remote_socket.recv(5120)
                if not data:
                    break
                server_new.sendall(data)

            print(f'[{timelog()}] Response: {ip}:{port} -> {server_addr[0]}:{server_addr[1]} Mode: IPv4')
    except OSError:
        server_new.close()


def verify(server_new, server_addr):
    try:
        recvdata = server_new.recv(4)
        print(f"Client {server_addr[0]}:{server_addr[1]} listen, Data {recvdata}")
        if verify_code:
            if recvdata[2] == 2:  # 需要验证
                server_new.send(b"\x05\x02")
                recvdata = server_new.recv(254)
                client_user = recvdata[2:2 + recvdata[1]].decode()
                client_passwd = recvdata[recvdata[1] + 3:].decode()
                if client_passwd == set_passwd and client_user == set_user:
                    print(f"Verify {server_addr[0]}:{server_addr[1]} yes.")
                    if server_addr[0] in client_verify_ok:
                        pass
                    else:
                        client_verify_ok.append(server_addr[0])
                    server_new.send(b"\x01\x00")
                    processing_data(server_new, server_addr)
                else:  # 验证用户名密码失败
                    server_new.send(b"\x01\x01")
                    server_new.close()
            elif server_addr[0] in client_verify_ok and recvdata[2] == 0:
                print(f"Verify {server_addr[0]}:{server_addr[1]} yes.(Verified in history)")
                server_new.send(b"\x05\x00")
                processing_data(server_new, server_addr)
            elif recvdata[1] == 2:  # 客户端支持的验证方法数量
                server_new.send(b"\x05\x02")
                recvdata = server_new.recv(254)
                client_user = recvdata[2:2 + recvdata[1]].decode()
                client_passwd = recvdata[recvdata[1] + 3:].decode()
                if client_passwd == set_passwd and client_user == set_user:
                    print(f"Verify {server_addr[0]}:{server_addr[1]} yes.")
                    if server_addr[0] in client_verify_ok:
                        pass
                    else:
                        client_verify_ok.append(server_addr[0])
                    server_new.send(b"\x01\x00")
                    processing_data(server_new, server_addr)
                else:  # 验证用户名密码失败
                    server_new.send(b"\x01\x01")
                    server_new.close()
            elif recvdata[2] == 0:
                server_new.close()
        else:
            server_new.send(b"\x05\x00")
            processing_data(server_new, server_addr)
    except TimeoutError:
        print("超时")
        server_new.close()
    except ConnectionAbortedError:
        server_new.close()
    except ConnectionRefusedError:
        server_new.close()
    except IndexError:
        server_new.close()
    finally:
        server_new.close()


def main(host, port):
    server = socket(AF_INET, SOCK_STREAM)
    server.bind((host, port))
    server.listen(10)
    print(f"[*] Server startup {host}:{port}")
    print(f"[=] Verify {verify_code}")
    print("[=] Edition 0.2")

    try:
        while True:
            server_new, server_addr = server.accept()
            Thread(target=verify, args=(server_new, server_addr,)).start()

    except KeyboardInterrupt:
        print('[-] 服务器已停止运行')
        server.close()
        exit()


if __name__ == '__main__':
    main(host=set_ip, port=set_port)
