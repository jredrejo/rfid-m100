import time
from dataclasses import dataclass

import serial
from constants import Command
from constants import InfoVersion
from constants import PacketType


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
    payload: bytes
    checksum: bytes
    tail: bytes


class RFIDReader:
    """
    RFID Reader class for ISO18000-6C / EPC C1 GEN2 protocol
    """

    def __init__(self, port="/dev/ttyUSB0", baudrate=115200):
        self.port = port
        self.baudrate = baudrate
        self.serial = None

    def connect(self):
        try:
            self.serial = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=None,
            )
            self.serial.flush()
            return True
        except serial.SerialException as e:
            print(f"Error connecting to RFID reader: {e}")
            return False

    def disconnect(self):
        if self.serial and self.serial.is_open:
            self.serial.flush()
            self.serial.close()

    def _read_hex(self):
        """Read hex data from serial port"""
        buffer = []
        while self.serial.in_waiting > 0:
            read_byte = self.serial.read().hex()
            buffer.append(read_byte)

        self.serial.flush()
        return "".join(buffer)

    def calculate_crc(self, packet: RequestPacket):
        """Calculate CRC for YRM100 protocol.
        Returns a single byte."""
        data = packet.type
        data += packet.command
        data += packet.length
        if packet.payload is not None:
            data += packet.payload
        crc = 0
        for byte in data:
            crc += byte
        return bytes([crc & 0xFF])

    def _extract_text_from_hex(self, hex_string):
        """
        Extract ASCII text from a hex string,
        starting after the first '00' byte
        and excluding the last two bytes.

        Args:
            hex_string (str):
            like 'bb01030010004d31303020323664426d2056312e30927e'

        Returns:
            str: Decoded ASCII text
        """
        # Find the position of '00' in the hex string
        zero_pos = hex_string.find("00")
        if zero_pos == -1:
            return ""

        # Get the relevant portion (after '00', excluding last 2 bytes)
        hex_text = hex_string[zero_pos + 2 : -4]  # noqa: E203

        # Convert hex string to bytes and then to ASCII
        try:
            bytes_data = bytes.fromhex(hex_text)
            return bytes_data.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            return ""

    def pack_frame(self, packet: RequestPacket):
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
        pbuf += packet.checksum
        pbuf += packet.tail

        return pbuf

    def send_command(self, command, payload=None, time_wait=True):
        if not self.serial or not self.serial.is_open:
            raise ConnectionError("Reader is not connected")

        try:
            packet = RequestPacket(
                head=Command.FRAME_HEAD.value,
                type=PacketType.COMMAND.value,
                command=command.value,
                length=(
                    b"\x00\x00"
                    if payload is None
                    else len(payload.value).to_bytes(2, byteorder="big")
                ),
                payload=None if payload is None else payload.value,
                checksum=None,
                tail=Command.FRAME_TAIL.value,
            )
            packet.checksum = self.calculate_crc(packet)
            frame = self.pack_frame(packet)
            self.serial.write(frame)
            self.serial.write(Command.TERMINATOR.value)
            if time_wait:
                # Give time for the reader to collect data
                time.sleep(0.1)
            return True
        except Exception as e:
            print(f"Error sending command: {e}")
            return False

    def get_reader_info(self):
        """Get reader information"""
        try:
            self.send_command(Command.GET_INFO, InfoVersion.HARDWARE)
            hw_version = self._read_hex()
            hw_version_text = self._extract_text_from_hex(hw_version)

            self.send_command(Command.GET_INFO, InfoVersion.SOFTWARE)
            sw_version = self._read_hex()
            sw_version_text = self._extract_text_from_hex(sw_version)

            self.send_command(Command.GET_INFO, InfoVersion.MANUFACTURERS)
            manufacturer = self._read_hex()
            manufacturer_text = self._extract_text_from_hex(manufacturer)

            return {
                "hardware_version": hw_version_text,
                "software_version": sw_version_text,
                "manufacturer": manufacturer_text,
            }

        except Exception as e:
            print(f"Error getting reader info: {e}")
            return None

    def read_tag(self):
        """
        Read a single RFID tag
        Returns a dictionary with tag data if successful, None otherwise
        """
        if not self.serial or not self.serial.is_open:
            raise ConnectionError("Reader is not connected")

        try:
            self.send_command(Command.GET_SINGLE_POOLING)
            time.sleep(0.4)

            buffer = self._read_hex()

            # verify output is valid - card found
            if buffer.startswith(Command.NOTIFICATION_POOLING.value.hex()):
                rssi = int(buffer[10:12], 16)
                rssi = -((-rssi) & 0xFF)

                pc = buffer[12:16]
                epc = buffer[16:40]
                crc = buffer[40:44]

                return {"pc": pc, "epc": epc, "rssi": rssi, "crc": crc}

            return None

        except Exception as e:
            print(f"Error reading tag: {e}")
            return None

    def inventory(self, timeout=1.0):
        pass

    def automatic_frequency_hopping_mode(self, mode=True):
        pass
