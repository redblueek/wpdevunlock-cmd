import socket
import struct

PHONE_IP = "127.0.0.1"
PHONE_PORT = 27077

def build_unlock_packet(auth_token: str, is_int: bool = False):
    token_bytes = auth_token.encode("ascii")
    token_len = len(token_bytes)

    # Payload:
    # 16 (version)
    # 3  (unlock command)
    # length (ushort)
    # 1 (tag: auth token)
    # token_len (ushort)
    # token_bytes
    # 2 (tag: environment)
    # 2 (ushort, length=2)
    # value (ushort) - 0 for internal, 1 for external
    value = 0 if is_int else 1

    # Calculate size field
    size = token_len + 3 + 2 + 3  # exact formula from UnlockCommand.cs

    packet = bytearray()
    packet.extend([16, 3])  # version + command
    packet.extend(struct.pack("<H", size))
    packet.append(1)
    packet.extend(struct.pack("<H", token_len))
    packet.extend(token_bytes)
    packet.append(2)
    packet.extend(struct.pack("<H", 2))
    packet.extend(struct.pack("<H", value))

    return bytes(packet)

def send_unlock(token):
    packet = build_unlock_packet(token)

    print("Sending packet:", packet.hex())

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    try:
        sock.connect((PHONE_IP, PHONE_PORT))
        sock.sendall(packet)
        response = sock.recv(1024)
        print("Response:", response.hex())
        return response
    except Exception as e:
        print("Socket error:", e)
        return None
    finally:
        sock.close()

if __name__ == "__main__":
    tok = input("Enter auth token: ")
    result = send_unlock(tok)
