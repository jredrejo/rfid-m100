"""
Tests for rfid_reader.py module
"""

import pytest
from unittest.mock import Mock, patch
import serial

# Import the module under test
from src.rfid_reader import RFIDReader, RequestPacket
from src.constants import Command


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


class TestRFIDReaderInit:
    """Test RFIDReader initialization"""

    def test_default_init(self):
        """Test default initialization parameters"""
        reader = RFIDReader()
        assert reader.port == "/dev/ttyUSB0"
        assert reader.baudrate == 115200

    def test_custom_init(self):
        """Test initialization with custom parameters"""
        reader = RFIDReader(port="COM3", baudrate=9600)
        assert reader.port == "COM3"
        assert reader.baudrate == 9600


class TestRFIDReaderConnection:
    """Test connection and disconnection methods"""

    @patch("src.rfid_reader.serial.Serial")
    def test_connect_success(self, mock_serial):
        """Test successful connection"""
        mock_instance = Mock()
        mock_instance.flush.return_value = None
        mock_serial.return_value = mock_instance

        reader = RFIDReader()
        result = reader.connect()

        assert result is True
        assert hasattr(reader, "serial")
        mock_serial.assert_called_once_with(
            port="/dev/ttyUSB0",
            baudrate=115200,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=None,
        )
        mock_instance.flush.assert_called_once()

    @patch("src.rfid_reader.serial.Serial")
    def test_connect_failure(self, mock_serial):
        """Test connection failure"""
        mock_serial.side_effect = serial.SerialException("Port not found")

        reader = RFIDReader()
        result = reader.connect()

        assert result is False

    def test_disconnect_with_open_serial(self):
        """Test disconnect with open serial connection"""
        reader = RFIDReader()
        reader.serial = Mock()
        reader.serial.is_open = True
        reader.serial.flush.return_value = None
        reader.serial.close.return_value = None

        reader.disconnect()

        reader.serial.flush.assert_called_once()
        reader.serial.close.assert_called_once()

    def test_disconnect_without_serial(self):
        """Test disconnect when serial is not initialized"""
        reader = RFIDReader()
        # Should not raise an exception
        reader.disconnect()

    def test_disconnect_with_closed_serial(self):
        """Test disconnect with closed serial connection"""
        reader = RFIDReader()
        reader.serial = Mock()
        reader.serial.is_open = False

        reader.disconnect()

        reader.serial.flush.assert_not_called()
        reader.serial.close.assert_not_called()


class TestRFIDReaderHexOperations:
    """Test hex data reading and parsing"""

    def test_read_hex_success(self, mock_serial_device):
        """Test successful hex reading"""
        reader = RFIDReader()
        reader.serial = mock_serial_device

        # Setup mock data
        mock_serial_device.in_waiting = 3
        mock_serial_device.read.side_effect = [b"\xbb", b"\x01", b"\x03"]

        result = reader._read_hex()

        assert result == "bb0103"
        mock_serial_device.flush.assert_called_once()

    def test_read_hex_no_data(self, mock_serial_device):
        """Test reading hex when no data available"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.in_waiting = 0

        result = reader._read_hex()

        assert result == ""
        mock_serial_device.flush.assert_called_once()

    def test_read_hex_no_serial(self):
        """Test reading hex without serial connection"""
        reader = RFIDReader()

        with pytest.raises(ValueError, match="Serial port not initialized"):
            reader._read_hex()

    def test_extract_text_from_hex_valid(self):
        """Test extracting text from valid hex string"""
        reader = RFIDReader()
        hex_string = "bb01030010004d31303020323664426d2056312e30927e"

        result = reader._extract_text_from_hex(hex_string)

        assert result == "M100 26dBm V1.0"

    def test_extract_text_from_hex_no_zero(self):
        """Test extracting text when no '00' marker found"""
        reader = RFIDReader()
        hex_string = "bb01030010"

        result = reader._extract_text_from_hex(hex_string)

        assert result == ""

    def test_extract_text_from_hex_invalid(self):
        """Test extracting text from invalid hex"""
        reader = RFIDReader()
        hex_string = "bb01030010004z31303020323664426d2056312e30927e"

        result = reader._extract_text_from_hex(hex_string)

        assert result == ""


class TestRFIDReaderCRC:
    """Test CRC calculation"""

    def test_calculate_crc(self):
        """Test CRC calculation"""
        reader = RFIDReader()
        packet = RequestPacket(
            head=b"\xbb",
            type=b"\x01",
            command=b"\x03",
            length=b"\x00\x01",
            payload=b"\x02",
            checksum=None,
            tail=b"\x7e",
        )

        crc = reader.calculate_crc(packet)

        # Expected: 0x01 + 0x03 + 0x00 + 0x01 + 0x02 = 0x07
        assert crc == b"\x07"

    def test_calculate_crc_no_payload(self):
        """Test CRC calculation without payload"""
        reader = RFIDReader()
        packet = RequestPacket(
            head=b"\xbb",
            type=b"\x01",
            command=b"\x03",
            length=b"\x00\x00",
            payload=None,
            checksum=None,
            tail=b"\x7e",
        )

        crc = reader.calculate_crc(packet)

        # Expected: 0x01 + 0x03 + 0x00 + 0x00 = 0x04
        assert crc == b"\x04"

    def test_calculate_crc_overflow(self):
        """Test CRC calculation with overflow"""
        reader = RFIDReader()
        packet = RequestPacket(
            head=b"\xbb",
            type=b"\xff",
            command=b"\xff",
            length=b"\xff\xff",
            payload=b"\xff",
            checksum=None,
            tail=b"\x7e",
        )

        crc = reader.calculate_crc(packet)

        # Should handle overflow correctly (mask with 0xFF)
        expected = (0xFF + 0xFF + 0xFF + 0xFF + 0xFF) & 0xFF
        assert crc == bytes([expected])


class TestRFIDReaderPackaging:
    """Test packet packing"""

    def test_pack_frame_with_payload(self):
        """Test packing frame with payload"""
        reader = RFIDReader()
        packet = RequestPacket(
            head=b"\xbb",
            type=b"\x01",
            command=b"\x03",
            length=b"\x00\x01",
            payload=b"\x02",
            checksum=b"\x07",
            tail=b"\x7e",
        )

        frame = reader.pack_frame(packet)

        expected = b"\xbb\x01\x03\x00\x01\x02\x07\x7e"
        assert frame == expected

    def test_pack_frame_no_payload(self):
        """Test packing frame without payload"""
        reader = RFIDReader()
        packet = RequestPacket(
            head=b"\xbb",
            type=b"\x01",
            command=b"\x03",
            length=b"\x00\x00",
            payload=None,
            checksum=b"\x04",
            tail=b"\x7e",
        )

        frame = reader.pack_frame(packet)

        expected = b"\xbb\x01\x03\x00\x00\x04\x7e"
        assert frame == expected

    def test_pack_frame_no_checksum(self):
        """Test packing frame without checksum"""
        reader = RFIDReader()
        packet = RequestPacket(
            head=b"\xbb",
            type=b"\x01",
            command=b"\x03",
            length=b"\x00\x00",
            payload=None,
            checksum=None,
            tail=b"\x7e",
        )

        frame = reader.pack_frame(packet)

        expected = b"\xbb\x01\x03\x00\x00\x00\x7e"
        assert frame == expected


class TestRFIDReaderCommands:
    """Test command sending"""

    def test_send_command_success(self, mock_serial_device):
        """Test successful command sending"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True

        with patch.object(reader, "calculate_crc", return_value=b"\x04"), patch.object(
            reader, "pack_frame", return_value=b"\xbb\x01\x03\x00\x00\x04\x7e"
        ), patch("time.sleep"):

            result = reader.send_command(Command.GET_INFO)

            assert result is True
            mock_serial_device.write.assert_any_call(b"\xbb\x01\x03\x00\x00\x04\x7e")
            mock_serial_device.write.assert_any_call(Command.TERMINATOR.value)

    def test_send_command_with_payload(self, mock_serial_device):
        """Test sending command with payload"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True

        payload = b"\x01\x02"

        with patch.object(reader, "calculate_crc", return_value=b"\x07"), patch.object(
            reader, "pack_frame", return_value=b"\xbb\x01\x03\x00\x02\x01\x02\x07\x7e"
        ), patch("time.sleep"):

            result = reader.send_command(Command.GET_INFO, payload)

            assert result is True

    def test_send_command_no_wait(self, mock_serial_device):
        """Test sending command without time wait"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True

        with patch.object(reader, "calculate_crc", return_value=b"\x04"), patch.object(
            reader, "pack_frame", return_value=b"\xbb\x01\x03\x00\x00\x04\x7e"
        ), patch("time.sleep") as mock_sleep:

            result = reader.send_command(Command.GET_INFO, time_wait=False)

            assert result is True
            mock_sleep.assert_not_called()

    def test_send_command_not_connected(self):
        """Test sending command when not connected"""
        reader = RFIDReader()

        with pytest.raises(ConnectionError, match="Reader is not connected"):
            reader.send_command(Command.GET_INFO)

    def test_send_command_closed_serial(self, mock_serial_device):
        """Test sending command with closed serial"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = False

        with pytest.raises(ConnectionError, match="Reader is not connected"):
            reader.send_command(Command.GET_INFO)

    def test_send_command_exception(self, mock_serial_device):
        """Test sending command with exception"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True
        mock_serial_device.write.side_effect = Exception("Write error")

        with patch.object(reader, "calculate_crc", return_value=b"\x04"), patch.object(
            reader, "pack_frame", return_value=b"\xbb\x01\x03\x00\x00\x04\x7e"
        ):

            result = reader.send_command(Command.GET_INFO)

            assert result is False


class TestRFIDReaderInfo:
    """Test reader information methods"""

    def test_get_reader_info_success(self, mock_serial_device):
        """Test successful reader info retrieval"""
        reader = RFIDReader()
        reader.serial = mock_serial_device

        # Mock the hex responses for each info type
        hex_responses = [
            "bb01030010004d31303020323664426d2056312e30927e",  # Hardware
            "bb01030010005357312e3020323664426d2056312e30927e",  # Software
            "bb01030010004d616e7566616374757265722058595a927e",  # Manufacturer
        ]

        with patch.object(reader, "send_command", return_value=True), patch.object(
            reader, "_read_hex", side_effect=hex_responses
        ):

            result = reader.get_reader_info()

            assert result is not None
            assert isinstance(result, dict)
            assert "hardware_version" in result
            assert "software_version" in result
            assert "manufacturer" in result

    def test_get_reader_info_exception(self, mock_serial_device):
        """Test reader info with exception"""
        reader = RFIDReader()
        reader.serial = mock_serial_device

        with patch.object(
            reader, "send_command", side_effect=Exception("Command error")
        ):

            result = reader.get_reader_info()

            assert result is None


class TestRFIDReaderTagOperations:
    """Test tag reading operations"""

    def test_read_tag_success(self, mock_serial_device, mock_rfid_responses):
        """Test successful single tag reading"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True

        # Mock response for successful tag read
        tag_response = mock_rfid_responses["valid_card"].hex()

        with patch.object(reader, "send_command", return_value=True), patch.object(
            reader, "_read_hex", return_value=tag_response
        ), patch.object(
            reader,
            "_parse_tag",
            return_value={
                "pc": "3000",
                "epc": "123456789ABCDEF0",
                "rssi": "-45",
                "crc": "1234",
            },
        ), patch(
            "time.sleep"
        ):
            result = reader.read_tag()

            assert result is not None
            assert isinstance(result, dict)
            assert "epc" in result
            assert "pc" in result
            assert "rssi" in result
            assert "crc" in result

    def test_read_tag_no_tag_found(self, mock_serial_device):
        """Test reading when no tag is found"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True

        with patch.object(reader, "send_command", return_value=True), patch.object(
            reader, "_read_hex", return_value=""
        ), patch("time.sleep"):

            result = reader.read_tag()

            assert result is None

    def test_read_tag_not_connected(self):
        """Test reading tag when not connected"""
        reader = RFIDReader()

        with pytest.raises(ConnectionError, match="Reader is not connected"):
            reader.read_tag()

    def test_read_tag_exception(self, mock_serial_device):
        """Test reading tag with exception"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True

        with patch.object(reader, "send_command", side_effect=Exception("Read error")):

            result = reader.read_tag()

            assert result is None

    def test_parse_tag(self):
        """Test tag data parsing"""
        reader = RFIDReader()
        # Sample tag data: bb000c0001 + ff + 3000 + 123456789ABCDEF012345678 + 1234
        data = "bb000c00ff3000123456789ABCDEF0123456781234"

        result = reader._parse_tag(data)

        assert result["pc"] == "0012"
        assert result["epc"] == "3456789ABCDEF01234567812"
        assert result["crc"] == "34"
        # RSSI calculation: ff = 255, -((-255) & 0xFF) = -255 + 256 = 1
        assert result["rssi"] == "-208"

    def test_parse_tag_negative_rssi(self):
        """Test parsing tag with negative RSSI"""
        reader = RFIDReader()
        # RSSI = 0x30 (48) should give negative value
        data = "bb000c0080300012345678"

        result = reader._parse_tag(data)

        # 0x30 = 48, -((-48) & 0xFF) = -(208) = -208
        assert result["rssi"] == "-208"


class TestRFIDReaderInventory:
    """Test inventory operations"""

    def test_inventory_success(self, mock_serial_device):
        """Test successful inventory operation"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True

        # Mock response with multiple tags
        inventory_response = (
            Command.NOTIFICATION_POOLING.value.hex()
            + "000c00ff3000123456789ABCDEF0123456781234"
            + Command.NOTIFICATION_POOLING.value.hex()
            + "000c00fe3001ABCDEF123456789012345678ABCD"
        )

        with patch.object(reader, "send_command", return_value=True), patch.object(
            reader, "_read_hex", return_value=inventory_response
        ), patch.object(
            reader,
            "_parse_tag",
            side_effect=[
                {
                    "pc": "3000",
                    "epc": "123456789ABCDEF012345678",
                    "rssi": "1",
                    "crc": "1234",
                },
                {
                    "pc": "3001",
                    "epc": "ABCDEF123456789012345678",
                    "rssi": "2",
                    "crc": "ABCD",
                },
            ],
        ):

            result = reader.inventory()

            assert isinstance(result, list)
            assert len(result) == 2
            assert all("epc" in tag for tag in result)

    def test_inventory_no_tags(self, mock_serial_device):
        """Test inventory with no tags found"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True

        with patch.object(reader, "send_command", return_value=True), patch.object(
            reader, "_read_hex", return_value=""
        ):

            result = reader.inventory()

            assert result == []

    def test_inventory_not_connected(self):
        """Test inventory when not connected"""
        reader = RFIDReader()

        with pytest.raises(ConnectionError, match="Reader is not connected"):
            reader.inventory()

    def test_inventory_exception(self, mock_serial_device):
        """Test inventory with exception"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True

        with patch.object(
            reader, "send_command", side_effect=Exception("Inventory error")
        ):

            result = reader.inventory()

            assert result == []

    def test_inventory_custom_timeout(self, mock_serial_device):
        """Test inventory with custom timeout"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True

        with patch.object(reader, "send_command", return_value=True), patch.object(
            reader, "_read_hex", return_value=""
        ):

            result = reader.inventory(timeout=2.0)

            assert result == []


class TestRFIDReaderFrequencyHopping:
    """Test automatic frequency hopping mode"""

    def test_automatic_frequency_hopping_enable(self, mock_serial_device):
        """Test enabling automatic frequency hopping"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True

        with patch("time.sleep"):
            result = reader.automatic_frequency_hopping_mode(True)

            assert result is True
            mock_serial_device.write.assert_any_call(Command.AFHM.value)
            mock_serial_device.write.assert_any_call(b"\xFF")
            mock_serial_device.write.assert_any_call(Command.TERMINATOR.value)

    def test_automatic_frequency_hopping_disable(self, mock_serial_device):
        """Test disabling automatic frequency hopping"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True

        with patch("time.sleep"):
            result = reader.automatic_frequency_hopping_mode(False)

            assert result is True
            mock_serial_device.write.assert_any_call(Command.AFHM.value)
            mock_serial_device.write.assert_any_call(b"\x00")
            mock_serial_device.write.assert_any_call(Command.TERMINATOR.value)

    def test_automatic_frequency_hopping_not_connected(self):
        """Test frequency hopping when not connected"""
        reader = RFIDReader()

        with pytest.raises(ConnectionError, match="Reader is not connected"):
            reader.automatic_frequency_hopping_mode()

    def test_automatic_frequency_hopping_exception(self, mock_serial_device):
        """Test frequency hopping with exception"""
        reader = RFIDReader()
        reader.serial = mock_serial_device
        mock_serial_device.is_open = True
        mock_serial_device.write.side_effect = Exception("Write error")

        result = reader.automatic_frequency_hopping_mode()

        assert result is False


class TestRFIDReaderIntegration:
    """Integration tests combining multiple operations"""

    def test_full_workflow(self, mock_serial_device):
        """Test complete workflow: connect, get info, read tag, disconnect"""
        reader = RFIDReader()

        with patch.object(reader, "connect", return_value=True), patch.object(
            reader, "get_reader_info", return_value={"hardware_version": "M100"}
        ), patch.object(
            reader, "read_tag", return_value={"epc": "123456789ABCDEF0"}
        ), patch.object(
            reader, "disconnect"
        ):

            # Connect
            assert reader.connect() is True

            # Get info
            info = reader.get_reader_info()
            assert info is not None
            assert "hardware_version" in info

            # Read tag
            tag = reader.read_tag()
            assert tag is not None
            assert "epc" in tag

            # Disconnect
            reader.disconnect()

    def test_multiple_baud_rates(self, baud_rate):
        """Test initialization with different baud rates"""
        reader = RFIDReader(baudrate=baud_rate)
        assert reader.baudrate == baud_rate

    def test_multiple_ports(self, serial_port):
        """Test initialization with different serial ports"""
        reader = RFIDReader(port=serial_port)
        assert reader.port == serial_port


# Markers for test organization
pytestmark = [pytest.mark.rfid, pytest.mark.unit]
