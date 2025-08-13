from dataclasses import dataclass
from typing import Optional
from .constants import Command, PacketType, MIN_RSSI


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


def verify_checksum(buffer: str) -> bool:
    checksum = int(buffer[-4:-2], 16)
    crc = 0
    for i in range(2, len(buffer) - 4, 2):
        crc += int(buffer[i : i + 2], 16)
    return (crc & 0xFF) == checksum


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
    end_pos = hex_string.find(Command.FRAME_TAIL.value.hex(), zero_pos) - 2
    if end_pos < 0:
        end_pos = -4
    hex_text = hex_string[zero_pos + 12 : end_pos]
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


def parse_tag(data: str) -> Optional[dict[str, str]]:
    raw_rssi = int(data[10:12], 16)
    rssi = -((-raw_rssi) & 0xFF)
    if rssi < MIN_RSSI:
        return None
    pc = data[12:16]
    epc = data[16:40]
    crc = data[40:44]
    return {"pc": pc, "epc": epc, "rssi": str(rssi), "crc": str(crc)}


def create_packet(command: Command, payload: Optional[bytes] = None) -> bytes:
    packet = RequestPacket(
        head=Command.FRAME_HEAD.value,
        type=PacketType.COMMAND.value,
        command=command.value,
        length=(
            b"\x00\x00"
            if payload is None
            else len(payload).to_bytes(2, byteorder="big")
        ),
        payload=None if payload is None else payload,
        checksum=None,
        tail=Command.FRAME_TAIL.value,
    )
    packet.checksum = calculate_crc(packet)
    frame = pack_frame(packet)

    return frame
