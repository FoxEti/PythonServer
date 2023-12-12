import socket
import ClientRequest
import InitDb
import threading

MAX_SIZE = 18000

def handle_client(client_conn):
    while True:
        data = bytearray()
        package = client_conn.recv(MAX_SIZE)
        if not package:
            break
        data.extend(package)
        answer = ClientRequest.def_request(data)
        if answer:
            client_conn.send(answer)

    client_conn.close()


def main():
    host = ''
    port = InitDb.read_port_from_file()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((host, port))
        InitDb.load_clients_db()
        server.listen()

        while True:
            print("Waiting for client to connect...")
            client_conn, addr = server.accept()
            print(f"Connection from {addr[0]}:{addr[1]}")

            # create a new thread to handle the client
            t = threading.Thread(target=handle_client, args=(client_conn,))
            t.start()

if __name__ == '__main__':
    main()
