import socket
import threading
import re
import base64
import hashlib
import struct
import time

class WebSocketServer:
    def __init__(self, host, port):
        """Initialize the WebSocket server with host and port."""
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.extensions = []
        self.subprotocols = []

    def start(self):
        """Start the WebSocket server and listen for incoming connections."""
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print(f"WebSocket server started on {self.host}:{self.port}")

        while True:
            client, address = self.sock.accept()
            print(f"New connection from {address}")
            client_thread = threading.Thread(target=self.handle_client, args=(client,))
            client_thread.start()

    def handle_client(self, client_socket):
        """Handle a client connection."""
        try:
            self.handshake(client_socket)
            self.handle_websocket_frames(client_socket)
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def handshake(self, client_socket):
        """Perform the WebSocket handshake with the client."""
        data = client_socket.recv(1024).decode('utf-8')
        
        if "Upgrade: websocket" in data and "Connection: Upgrade" in data:
            key = re.search(r'Sec-WebSocket-Key: (.*)', data).group(1).strip()
            response_key = self.generate_accept_key(key)

            # Check for extensions and subprotocols
            extensions = re.search(r'Sec-WebSocket-Extensions: (.*)', data)
            subprotocols = re.search(r'Sec-WebSocket-Protocol: (.*)', data)

            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {response_key}\r\n"
            )

            if extensions:
                self.extensions = [ext.strip() for ext in extensions.group(1).split(',')]
                response += f"Sec-WebSocket-Extensions: {', '.join(self.extensions)}\r\n"

            if subprotocols:
                self.subprotocols = [proto.strip() for proto in subprotocols.group(1).split(',')]
                response += f"Sec-WebSocket-Protocol: {self.subprotocols[0]}\r\n"

            response += "\r\n"
            
            client_socket.send(response.encode('utf-8'))
            print("WebSocket handshake completed")
        else:
            raise Exception("Invalid WebSocket upgrade request")

    def generate_accept_key(self, key):
        """Generate the Sec-WebSocket-Accept key for the handshake."""
        GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        hash_key = key + GUID
        sha1 = hashlib.sha1(hash_key.encode()).digest()
        return base64.b64encode(sha1).decode()

    def handle_websocket_frames(self, client_socket):
        """Handle incoming WebSocket frames."""
        fragmented_message = bytearray()
        fragmented_opcode = None

        while True:
            try:
                frame = self.receive_frame(client_socket)

                if frame['opcode'] == 0x0:  # Continuation frame
                    self.handle_continuation_frame(client_socket, frame, fragmented_message, fragmented_opcode)
                    if frame['fin']:
                        fragmented_message = bytearray()
                        fragmented_opcode = None
                elif frame['opcode'] in (0x1, 0x2):  # Text or Binary frame
                    self.handle_data_frame(client_socket, frame, fragmented_message, fragmented_opcode)
                    if not frame['fin']:
                        fragmented_opcode = frame['opcode']
                        fragmented_message = bytearray(frame['payload'])
                elif frame['opcode'] == 0x8:  # Close frame
                    self.handle_close_frame(client_socket, frame)
                    break
                elif frame['opcode'] == 0x9:  # Ping frame
                    self.handle_ping_frame(client_socket, frame)
                elif frame['opcode'] == 0xA:  # Pong frame
                    self.handle_pong_frame(frame)
                else:
                    raise Exception(f"Unsupported opcode: {frame['opcode']}")

            except Exception as e:
                print(f"Error handling frame: {e}")
                self.send_close_frame(client_socket, 1002, "Protocol error")
                break

    def handle_continuation_frame(self, client_socket, frame, fragmented_message, fragmented_opcode):
        """Handle a continuation frame."""
        if fragmented_opcode is None:
            raise Exception("Received continuation frame without start frame")
        fragmented_message.extend(frame['payload'])
        if frame['fin']:
            self.handle_complete_message(client_socket, fragmented_opcode, fragmented_message)

    def handle_data_frame(self, client_socket, frame, fragmented_message, fragmented_opcode):
        """Handle a data frame (text or binary)."""
        if fragmented_opcode is not None:
            raise Exception("Received new data frame before completing fragmented message")
        if frame['fin']:
            self.handle_complete_message(client_socket, frame['opcode'], frame['payload'])

    def handle_complete_message(self, client_socket, opcode, payload):
        """Handle a complete message (fragmented or unfragmented)."""
        if opcode == 0x1:  # Text
            message = payload.decode('utf-8')
            print(f"Received text message: {message}")
            # Echo the message back to the client
            self.send_text_frame(client_socket, message)
        elif opcode == 0x2:  # Binary
            print(f"Received binary message of {len(payload)} bytes")
            # Echo the binary message back to the client
            self.send_binary_frame(client_socket, payload)

    def handle_close_frame(self, client_socket, frame):
        """Handle a close frame."""
        code = 1000
        reason = ""
        if len(frame['payload']) >= 2:
            code = struct.unpack('!H', frame['payload'][:2])[0]
            reason = frame['payload'][2:].decode('utf-8')
        print(f"Client requested to close the connection. Code: {code}, Reason: {reason}")
        self.send_close_frame(client_socket, code, reason)

    def handle_ping_frame(self, client_socket, frame):
        """Handle a ping frame."""
        print(f"Received Ping: {frame['payload']}")
        self.send_pong_frame(client_socket, frame['payload'])

    def handle_pong_frame(self, frame):
        """Handle a pong frame."""
        print(f"Received Pong: {frame['payload']}")

    def receive_frame(self, client_socket):
        """Receive and parse a WebSocket frame."""
        header = client_socket.recv(2)
        if not header:
            raise Exception("Client closed connection")

        fin = (header[0] & 0b10000000) != 0
        opcode = header[0] & 0b00001111
        mask = (header[1] & 0b10000000) != 0
        payload_length = header[1] & 0b01111111

        if payload_length == 126:
            payload_length = struct.unpack(">H", client_socket.recv(2))[0]
        elif payload_length == 127:
            payload_length = struct.unpack(">Q", client_socket.recv(8))[0]

        if mask:
            masking_key = client_socket.recv(4)
        else:
            masking_key = None

        payload = client_socket.recv(payload_length)

        if mask:
            payload = self.unmask_payload(payload, masking_key)

        return {
            'fin': fin,
            'opcode': opcode,
            'mask': mask,
            'payload_length': payload_length,
            'payload': payload
        }

    def unmask_payload(self, payload, masking_key):
        """Unmask the payload of a WebSocket frame."""
        return bytes(payload[i] ^ masking_key[i % 4] for i in range(len(payload)))

    def send_frame(self, client_socket, payload, opcode):
        """Send a WebSocket frame."""
        header = struct.pack('!B', 0b10000000 | opcode)
        length = len(payload)

        if length <= 125:
            header += struct.pack('!B', length)
        elif length <= 65535:
            header += struct.pack('!BH', 126, length)
        else:
            header += struct.pack('!BQ', 127, length)

        client_socket.send(header + payload)

    def send_text_frame(self, client_socket, message):
        """Send a text frame."""
        self.send_frame(client_socket, message.encode('utf-8'), 0x1)

    def send_binary_frame(self, client_socket, data):
        """Send a binary frame."""
        self.send_frame(client_socket, data, 0x2)

    def send_ping_frame(self, client_socket, data=b''):
        """Send a ping frame."""
        self.send_frame(client_socket, data, 0x9)

    def send_pong_frame(self, client_socket, data=b''):
        """Send a pong frame."""
        self.send_frame(client_socket, data, 0xA)

    def send_close_frame(self, client_socket, code=1000, reason=""):
        """Send a close frame."""
        payload = struct.pack('!H', code) + reason.encode('utf-8')
        self.send_frame(client_socket, payload, 0x8)

if __name__ == "__main__":
    server = WebSocketServer("localhost", 8765)
    server.start()