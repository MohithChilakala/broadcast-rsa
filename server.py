import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class Server:
    def __init__(self, host, port):
        self.log_area = None
        self.window = None
        self.host = host
        self.port = port

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()

        self.clients = {}
        self.public_keys = {}

        # Generate server's key pair
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

        self.gui_init()

    def gui_init(self):
        self.window = tk.Tk()
        self.window.title("Server")

        self.log_area = scrolledtext.ScrolledText(
            self.window, wrap=tk.WORD, width=70, height=20
        )
        self.log_area.pack(padx=10, pady=10)

        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)

    def start(self):
        self.log_message("Server started. Waiting for connections...")
        accept_thread = threading.Thread(target=self.accept_connections)
        accept_thread.start()
        self.window.mainloop()

    def accept_connections(self):
        while True:
            client_socket, address = self.server_socket.accept()
            self.log_message(f"New connection from {address}")

            # Exchange public keys
            client_public_key = RSA.import_key(client_socket.recv(1024))
            client_socket.send(self.public_key.export_key())

            self.clients[address] = client_socket
            self.public_keys[address] = client_public_key

            client_thread = threading.Thread(
                target=self.handle_client, args=(client_socket, address)
            )
            client_thread.start()

    def handle_client(self, client_socket, address):
        while True:
            try:
                encrypted_message = client_socket.recv(1024)
                if not encrypted_message:
                    break

                print(encrypted_message)
                # Decrypt the message
                cipher = PKCS1_OAEP.new(self.private_key)
                decrypted_message = cipher.decrypt(encrypted_message)

                self.log_message(
                    f"Message from {address}: {decrypted_message.decode()}"
                )

                # Broadcast the message to all other clients
                self.broadcast(address, decrypted_message)
            except:
                break

        self.clients.pop(address)
        self.public_keys.pop(address)
        client_socket.close()
        self.log_message(f"Connection from {address} closed")

    def broadcast(self, sender_address, message):
        for address, client_socket in self.clients.items():
            if address != sender_address:
                # Encrypt the message with the recipient's public key
                cipher = PKCS1_OAEP.new(self.public_keys[address])
                encrypted_message = cipher.encrypt(message)
                client_socket.send(encrypted_message)

    def log_message(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)

    def on_closing(self):
        for client_socket in self.clients.values():
            client_socket.close()
        self.server_socket.close()
        self.window.destroy()


if __name__ == "__main__":
    server = Server("localhost", 5000)
    server.start()
