import pytest

from src.utils import (
    calculate_crc,
    extract_text_from_hex,
    pack_frame,
    parse_tag,
    RequestPacket,
)


class TestRequestPacket:
    """Test the RequestPacket dataclass"""

    def test_request_packet_creation(self):
        """Test creating a RequestPacket instance"""
        packet = RequestPacket(
            head=b"\xbb",
            type=b"\x01",
            command=b"\x03",
            length=b"\x00\x00",
            payload=None,
            checksum=b"\x04",
            tail=b"\x7e",
        )

        assert packet.head == b"\xbb"
        assert packet.type == b"\x01"
        assert packet.command == b"\x03"
        assert packet.length == b"\x00\x00"
        assert packet.payload is None
        assert packet.checksum == b"\x04"
        assert packet.tail == b"\x7e"

    def test_request_packet_with_payload(self):
        """Test RequestPacket with payload data"""
        payload = b"\x01\x02\x03"
        packet = RequestPacket(
            head=b"\xbb",
            type=b"\x01",
            command=b"\x03",
            length=b"\x00\x03",
            payload=payload,
            checksum=b"\x04",
            tail=b"\x7e",
        )

        assert packet.payload == payload
        assert len(packet.payload) == 3


def test_extract_text_from_hex_valid():
    hex_string = "bb01030010004d31303020323664426d2056312e30927e"
    result = extract_text_from_hex(hex_string)
    assert result == "M100 26dBm V1.0"


def test_extract_text_from_hex_no_zero():
    hex_string = "bb01030010"
    result = extract_text_from_hex(hex_string)
    assert result == ""


def test_extract_text_from_hex_invalid():
    hex_string = "bb01030010004z31303020323664426d2056312e30927e"
    result = extract_text_from_hex(hex_string)
    assert result == ""


def test_calculate_crc():
    packet = RequestPacket(
        head=b"\xbb",
        type=b"\x01",
        command=b"\x03",
        length=b"\x00\x01",
        payload=b"\x02",
        checksum=None,
        tail=b"\x7e",
    )
    crc = calculate_crc(packet)
    assert crc == b"\x07"


def test_calculate_crc_no_payload():
    packet = RequestPacket(
        head=b"\xbb",
        type=b"\x01",
        command=b"\x03",
        length=b"\x00\x00",
        payload=None,
        checksum=None,
        tail=b"\x7e",
    )
    crc = calculate_crc(packet)
    assert crc == b"\x04"


def test_calculate_crc_overflow():
    """Test CRC calculation with overflow"""
    packet = RequestPacket(
        head=b"\xbb",
        type=b"\xff",
        command=b"\xff",
        length=b"\xff\xff",
        payload=b"\xff",
        checksum=None,
        tail=b"\x7e",
    )

    crc = calculate_crc(packet)

    # Should handle overflow correctly (mask with 0xFF)
    expected = (0xFF + 0xFF + 0xFF + 0xFF + 0xFF) & 0xFF
    assert crc == bytes([expected])


def test_pack_frame_with_payload():
    packet = RequestPacket(
        head=b"\xbb",
        type=b"\x01",
        command=b"\x03",
        length=b"\x00\x01",
        payload=b"\x02",
        checksum=b"\x07",
        tail=b"\x7e",
    )
    frame = pack_frame(packet)
    expected = b"\xbb\x01\x03\x00\x01\x02\x07\x7e"
    assert frame == expected


def test_pack_frame_no_payload():
    packet = RequestPacket(
        head=b"\xbb",
        type=b"\x01",
        command=b"\x03",
        length=b"\x00\x00",
        payload=None,
        checksum=b"\x04",
        tail=b"\x7e",
    )
    frame = pack_frame(packet)
    expected = b"\xbb\x01\x03\x00\x00\x04\x7e"
    assert frame == expected


def test_pack_frame_no_checksum():
    packet = RequestPacket(
        head=b"\xbb",
        type=b"\x01",
        command=b"\x03",
        length=b"\x00\x00",
        payload=None,
        checksum=None,
        tail=b"\x7e",
    )
    frame = pack_frame(packet)
    expected = b"\xbb\x01\x03\x00\x00\x00\x7e"
    assert frame == expected


def test_parse_tag():
    data = "bb000c00ff3000123456789ABCDEF0123456781234"
    result = parse_tag(data)
    assert result["pc"] == "0012"
    assert result["epc"] == "3456789ABCDEF01234567812"
    assert result["crc"] == "34"
    assert result["rssi"] == "-208"


def test_parse_tag_negative_rssi():
    data = "bb000c0080300012345678"
    result = parse_tag(data)
    assert result["rssi"] == "-208"
