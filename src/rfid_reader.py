import time
from dataclasses import dataclass
from typing import Optional

import serial

from .constants import Command
from .constants import InfoVersion
from .constants import PacketType


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


class RFIDReader:
    """
    RFID Reader class for ISO18000-6C / EPC C1 GEN2 protocol
    """

    def __init__(self, port: str = "/dev/ttyUSB0", baudrate: int = 115200):
        self.port = port
        self.baudrate = baudrate

    def connect(self) -> bool:
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
        if hasattr(self, "serial") and self.serial.is_open:
            self.serial.flush()
            self.serial.close()

    def _read_hex(self) -> str:
        """Read hex data from serial port"""
        if not hasattr(self, "serial"):
            raise ValueError("Serial port not initialized")
        buffer = []
        while self.serial.in_waiting > 0:
            read_byte = self.serial.read().hex()
            buffer.append(read_byte)

        self.serial.flush()
        return "".join(buffer)

    def calculate_crc(self, packet: RequestPacket) -> bytes:
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

    def _extract_text_from_hex(self, hex_string: str) -> str:
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
        hex_text = hex_string[zero_pos + 2 : -4]

        # Convert hex string to bytes and then to ASCII
        try:
            bytes_data = bytes.fromhex(hex_text)
            return bytes_data.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            return ""

    def pack_frame(self, packet: RequestPacket) -> bytes:
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

    def send_command(
        self, command: Command, payload: Optional[bytes] = None, time_wait: bool = True
    ) -> bool:
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
                    else len(payload).to_bytes(2, byteorder="big")
                ),
                payload=None if payload is None else payload,
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

    def get_reader_info(self) -> Optional[dict[str, str]]:
        """Get reader information"""
        try:
            self.send_command(Command.GET_INFO, InfoVersion.HARDWARE.value)
            hw_version = self._read_hex()
            hw_version_text = self._extract_text_from_hex(hw_version)

            self.send_command(Command.GET_INFO, InfoVersion.SOFTWARE.value)
            sw_version = self._read_hex()
            sw_version_text = self._extract_text_from_hex(sw_version)

            self.send_command(Command.GET_INFO, InfoVersion.MANUFACTURERS.value)
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

    def read_tag(self) -> Optional[dict[str, str]]:
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
                raw_rssi = int(buffer[10:12], 16)
                rssi = -((-raw_rssi) & 0xFF)

                pc = buffer[12:16]
                epc = buffer[16:40]
                crc = buffer[40:44]

                return {"pc": pc, "epc": epc, "rssi": str(rssi), "crc": str(crc)}

            return None

        except Exception as e:
            print(f"Error reading tag: {e}")
            return None

    def inventory(self, timeout: float = 1.0) -> list[dict[str, str]]:
        """
        Perform an ISO18000-6C inventory command to read multiple tags at once
        Args:
            timeout: How long to wait for response in seconds
        Returns:
            List of dictionaries containing tag data
        """
        if not self.serial or not self.serial.is_open:
            raise ConnectionError("Reader is not connected")

        try:
            tags = []

            # Send inventory command
            self.send_command(Command.GET_INVENTORY, b"\x22\x27\x10")

            # Read response
            buffer = self._read_hex()

            # Parse multiple tag response
            if buffer.startswith(Command.NOTIFICATION_POOLING.value.hex()):
                print("Debug - Prefix matched successfully")
                # Get number of tags from response
                num_tags = int(buffer[8:10], 16)
                print(f"Debug - Number of tags found: {num_tags}")

                # Parse each tag
                pos = 10  # Start position after tag count
                for i in range(num_tags):
                    # Minimum length for one tag data is 34 bytes
                    if len(buffer) < pos + 34:
                        print(
                            f"Debug - Buffer too short at tag {i}. Length: {len(buffer)}, Position: {pos}"  # noqa: E501
                        )
                        break

                    rssi = int(buffer[pos : pos + 2], 16)
                    rssi = -((-rssi) & 0xFF)
                    pos += 2

                    pc = buffer[pos : pos + 4]
                    pos += 4

                    epc = buffer[pos : pos + 24]
                    pos += 24

                    crc = buffer[pos : pos + 4]
                    pos += 4

                    tag_data = {
                        "pc": pc,
                        "epc": epc,
                        "rssi": str(rssi),
                        "crc": str(crc),
                    }
                    print(f"Debug - Tag {i} data: {tag_data}")
                    tags.append(tag_data)
            else:
                print("Debug - Prefix match failed")

            return tags

        except Exception as e:
            print(f"Error during inventory: {e}")
            return []

    def automatic_frequency_hopping_mode(self, mode: bool = True) -> bool:
        if not self.serial or not self.serial.is_open:
            raise ConnectionError("Reader is not connected")

        try:
            self.serial.write(Command.AFHM.value)
            # xFF\xAD\x7E
            if mode:
                self.serial.write(b"\xFF")
            else:
                self.serial.write(b"\x00")

            self.serial.write(Command.TERMINATOR.value)
            time.sleep(0.1)
            return True
        except Exception as e:
            print(f"Error setting automatic frequency hopping mode: {e}")
            return False
