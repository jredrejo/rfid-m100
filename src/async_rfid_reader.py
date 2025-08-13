import asyncio
from asyncio.streams import StreamWriter
import logging
import re
import serial
import serial_asyncio
from typing import cast
from typing import Optional
from .constants import Command, InfoVersion
from .rfid_reader import RFIDReader
from .utils import (
    create_packet,
    extract_text_from_hex,
    parse_tag,
    verify_checksum,
)


logger = logging.getLogger(__name__)


class AsyncRFIDReader(RFIDReader):
    """Async RFID Reader"""

    async def async_connect(self) -> bool:
        self.reader: asyncio.streams.StreamReader
        self.writer: asyncio.streams.StreamWriter
        try:
            self.reader, self.writer = await serial_asyncio.open_serial_connection(
                url=self.port,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
            )

            self.transport = cast(serial_asyncio.SerialTransport, self.writer.transport)
            await self.clear_buffers()

            return True
        except serial.SerialException as e:
            logger.exception(f"Error connecting to RFID reader: {e}")
            return False
        except Exception as e:
            logger.exception(f"Unexpected error connecting to RFID reader: {e}")
            return False

    async def clear_buffers(self):
        if self.transport.serial:
            if self.is_port_open():
                await self.writer.drain()
            self.transport.serial.reset_input_buffer()
            self.transport.serial.reset_output_buffer()

    async def async_disconnect(self):
        if self.is_port_open():
            # ensure pending writes are flushed before closing
            await self.clear_buffers()
            self.writer.close()
            await self.writer.wait_closed()

    def is_port_open(self) -> bool:
        if not hasattr(self, "writer"):
            return False
        ser = getattr(self.transport, "serial", None)
        return bool(ser and ser.is_open)

    async def async_send_command(
        self, command: Command, payload: Optional[bytes] = None, time_wait: float = 0.1
    ) -> bool:
        if not self.is_port_open():
            logger.exception("Reader is not connected")
            raise ConnectionError("Reader is not connected")

        try:
            await self.clear_buffers()
            frame = create_packet(command, payload)

            self.writer.write(frame)
            self.writer.write(Command.TERMINATOR.value)
            await self.writer.drain()  # <-- important: let the loop flush the buffer

            if time_wait is not None:
                # Give time for the reader to collect data
                await asyncio.sleep(time_wait)
            return True
        except Exception as e:
            logger.exception(f"Error sending command: {e}")
            return False

    async def async_read_hex(self) -> str:
        """Read hex data from serial port asynchronously"""
        if not hasattr(self, "reader") or not hasattr(self, "writer"):
            raise ValueError("Serial streams not initialized")

        # using inWaiting with async does not have sense, we must read all data
        # Considering this rfid device will never sent more than 64K of data
        try:
            buffer = await asyncio.wait_for(self.reader.read(65536), timeout=0.1)
        except asyncio.TimeoutError:
            buffer = b""

        return buffer.hex()

    async def async_get_reader_info(self) -> Optional[dict[str, str]]:
        """Get reader information"""
        try:
            await self.async_send_command(Command.GET_INFO, InfoVersion.HARDWARE.value)
            hw_version = await self.async_read_hex()
            hw_version_text = extract_text_from_hex(hw_version)
            await self.async_send_command(Command.GET_INFO, InfoVersion.SOFTWARE.value)
            sw_version = await self.async_read_hex()
            sw_version_text = extract_text_from_hex(sw_version)

            await self.async_send_command(
                Command.GET_INFO, InfoVersion.MANUFACTURERS.value
            )
            manufacturer = await self.async_read_hex()
            manufacturer_text = extract_text_from_hex(manufacturer)

            return {
                "hardware_version": hw_version_text,
                "software_version": sw_version_text,
                "manufacturer": manufacturer_text,
            }

        except Exception as e:
            logger.exception(f"Error getting reader info: {e}")
            return None

    async def async_read_tag(self) -> Optional[dict[str, str]]:
        """Read a tag asynchronously"""
        try:
            await self.async_send_command(Command.GET_SINGLE_POOLING, time_wait=0.4)
            buffer = await self.async_read_hex()
            # verify output is valid - card found
            if buffer.startswith(
                Command.NOTIFICATION_POOLING.value.hex()
            ) and verify_checksum(buffer):
                return parse_tag(buffer)
            else:
                return None
        except Exception as e:
            logger.exception(f"Error reading tag: {e}")
            return None

    async def async_inventory(self) -> list[dict[str, str]]:
        """Perform an ISO18000-6C inventory command to read multiple tags at once"""
        try:
            tags: dict[str, dict[str, str]] = {}
            # Send inventory command
            # 2710: up to 10000 tags
            await self.async_send_command(Command.GET_INVENTORY, b"\x22\x27\x10")
            buffer = await self.async_read_hex()
            # Parse multiple tag response
            if buffer.startswith(Command.NOTIFICATION_POOLING.value.hex()):
                logger.debug("Prefix matched successfully")
                # Get number of tags from response
                positions = [
                    m.start()
                    for m in re.finditer(
                        re.escape(Command.NOTIFICATION_POOLING.value.hex()), buffer
                    )
                ]
                boundaries = list(zip(positions, positions[1:] + [len(buffer)]))
                # Parse each tag
                for i in range(0, len(positions)):
                    start, end = boundaries[i]
                    # Minimum length for one tag data is 44 bytes
                    if (end - start) < 44:
                        logger.error(
                            f"Buffer too short at tag {i}. Length: {len(buffer)}, Position: {start}"
                        )  # noqa: E501
                        break

                    tag_data = parse_tag(buffer[start:end])
                    if tag_data is None:
                        continue
                    epc = tag_data["epc"]
                    if epc not in tags:
                        tags[epc] = tag_data
                        logger.info(f"Tag data: {tag_data}")

                logger.info(f"Number of tags found: {len(tags)}")
            else:
                logger.debug("Prefix match failed")
            return list(tags.values())

        except Exception as e:
            logger.exception(f"Error during inventory: {e}")
            return []

    async def async_get_power(self) -> Optional[float]:
        """Get reader power"""
        """ Returns a float with the dBm value """

        try:
            await self.async_send_command(Command.GET_POWER)
            buffer = await self.async_read_hex()
            if buffer.startswith(
                Command.GENERAL_NOTIFICATION_HEADER.value.hex()
            ) and verify_checksum(buffer):
                power = int(buffer[10:14], 16)
                return power / 100
            else:
                return None
        except Exception as e:
            logger.exception(f"Error getting power: {e}")
            return None
