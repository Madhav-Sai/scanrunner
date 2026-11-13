"""Independent SMB negotiation probes restricted to the owned Docker lab."""
import socket
import struct

ADDRESSES = {"172.29.77.10", "172.29.77.11", "172.29.77.12", "172.29.77.13"}


def receive_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise EOFError("Peer closed the negotiation connection")
        result.extend(chunk)
    return bytes(result)


def exchange(address, packet):
    if address not in ADDRESSES:
        raise ValueError("Probe address is outside the owned lab")
    with socket.create_connection((address, 445), timeout=5) as connection:
        connection.settimeout(5)
        connection.sendall(b"\x00" + len(packet).to_bytes(3, "big") + packet)
        header = receive_exact(connection, 4)
        length = int.from_bytes(header[1:], "big")
        if header[0] != 0 or not 32 <= length <= 65536:
            raise ValueError("Invalid SMB transport response")
        return receive_exact(connection, length)


def smb2_request():
    header = struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, bytes(16))
    body = struct.pack("<HHHHI16sQ", 36, 1, 1, 0, 0, bytes.fromhex("00112233445566778899aabbccddeeff"), 0)
    return header + body + struct.pack("<H", 0x0210)


def smb1_request():
    header = struct.pack("<4sBIBHH8sHHHHH", b"\xffSMB", 0x72, 0, 0x18, 0xC853, 0, bytes(8), 0, 0, 1234, 0, 1)
    dialect = b"\x02NT LM 0.12\x00"
    return header + b"\x00" + struct.pack("<H", len(dialect)) + dialect


def parse_smb2(response):
    if (len(response) < 128 or response[:4] != b"\xfeSMB" or struct.unpack_from("<H", response, 4)[0] != 64
            or struct.unpack_from("<H", response, 12)[0] != 0 or not struct.unpack_from("<I", response, 16)[0] & 1):
        raise ValueError("Unexpected SMB2 negotiation response")
    status = struct.unpack_from("<I", response, 8)[0]
    if status != 0 or struct.unpack_from("<H", response, 64)[0] != 65:
        raise ValueError(f"SMB2 negotiation failed with status {status:#x}")
    security_mode, dialect = struct.unpack_from("<HH", response, 66)
    if dialect != 0x0210 or security_mode & ~3:
        raise ValueError("Unexpected negotiated dialect or security mode")
    return {"dialect": "2.1", "security_mode": security_mode, "signing_required": bool(security_mode & 2)}


def parse_smb1(response):
    if len(response) >= 64 and response[:4] == b"\xfeSMB":
        return False
    if len(response) < 35 or response[:4] != b"\xffSMB" or response[4] != 0x72:
        raise ValueError("Unexpected SMB1 negotiation response")
    status = struct.unpack_from("<I", response, 5)[0]
    return status == 0 and response[32] >= 1 and struct.unpack_from("<H", response, 33)[0] == 0


def probe(address):
    packet2 = smb2_request()
    response2 = exchange(address, packet2)
    result = {"smb2_request_hex": packet2.hex(), "smb2_response_hex": response2.hex()}
    try:
        result["smb2"] = parse_smb2(response2)
    except ValueError as error:
        return {**result, "error": str(error)}
    packet1 = smb1_request()
    result["smb1_request_hex"] = packet1.hex()
    try:
        response1 = exchange(address, packet1)
        result.update(smbv1_accepted=parse_smb1(response1), smb1_response_hex=response1.hex())
    except (EOFError, ConnectionResetError) as error:
        result.update(smbv1_accepted=False, smb1_rejection=type(error).__name__)
    return result
