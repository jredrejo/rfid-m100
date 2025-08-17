from dataclasses import dataclass
from typing import Optional


@dataclass
class RequestPacket:
    """
    A packet object with attributes:
        head: Single byte header
        type: Single byte type
        command: Single byte command
        length: 16-bit unsigned int length
        payload: Bytes/bytearray of data
        checksum: Single byte checksum
        tail: Single byte trailer
    """

    head: bytes
    type: bytes
    command: bytes
    length: bytes
    payload: Optional[bytes]
    checksum: Optional[bytes]
    tail: bytes


def calculate_crc(packet: RequestPacket) -> bytes:
    """
    Calculate CRC for YRM100 protocol.
    Returns a single byte.
    """
    data = packet.type
    data += packet.command
    data += packet.length
    if packet.payload is not None:
        data += packet.payload
    crc = 0
    for byte in data:
        crc += byte
    return bytes([crc & 0xFF])


def extract_text_from_hex(hex_string: str) -> str:
    """
    Extract ASCII text from a hex string,
    starting 2 bytes after the response head 'bb0103' byte
    and excluding the last two bytes.

    Args:
        hex_string (str): like 'bb01030010004d31303020323664426d2056312e30927e'

    Returns:
        str: Decoded ASCII text
    """
    zero_pos = hex_string.find("bb0103")
    if zero_pos == -1:
        return ""
    hex_text = hex_string[zero_pos + 12 : -4]
    try:
        bytes_data = bytes.fromhex(hex_text)
        return bytes_data.decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return ""


def pack_frame(packet) -> bytes:
    """
    Pack a packet structure into a bytes buffer.
    Args:
        packet: A RequestPacket
    Returns:
        bytes: The packed frame
    """
    pbuf = packet.head
    pbuf += packet.type
    pbuf += packet.command
    pbuf += packet.length
    if packet.payload is not None:
        pbuf += packet.payload
    pbuf += packet.checksum if packet.checksum is not None else b"\x00"
    pbuf += packet.tail
    return pbuf


def parse_tag(data: str) -> dict[str, str]:
    raw_rssi = int(data[10:12], 16)
    rssi = -((-raw_rssi) & 0xFF)
    pc = data[12:16]
    epc = data[16:40]
    crc = data[40:44]
    return {"pc": pc, "epc": epc, "rssi": str(rssi), "crc": str(crc)}
