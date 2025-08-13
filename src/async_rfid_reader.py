import asyncio
from asyncio.streams import StreamWriter
import logging
import serial
import serial_asyncio
from typing import cast
from typing import Optional
from .constants import Command, PacketType, InfoVersion
from .rfid_reader import RFIDReader, RequestPacket


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

            transport = cast(serial_asyncio.SerialTransport, self.writer.transport)
            if transport.serial:
                transport.serial.reset_input_buffer()
                transport.serial.reset_output_buffer()

            return True
        except serial.SerialException as e:
            logger.exception(f"Error connecting to RFID reader: {e}")
            return False
        except Exception as e:
            logger.exception(f"Unexpected error connecting to RFID reader: {e}")
            return False


    async def async_disconnect(self):
        if self.is_port_open():
            # ensure pending writes are flushed before closing
            await self.writer.drain()
            self.writer.close()
            await self.writer.wait_closed()

    def is_port_open(self) -> bool:
        if not hasattr(self, "writer"):
            return False
        transport = cast(serial_asyncio.SerialTransport, self.writer.transport)
        ser = getattr(transport, "serial", None)
        return bool(ser and ser.is_open)

    async def async_send_command(
        self, command: Command, payload: Optional[bytes] = None, time_wait: bool = True
    ) -> bool:
        if not self.is_port_open():
            logger.exception("Reader is not connected")
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

            self.writer.write(frame)
            self.writer.write(Command.TERMINATOR.value)
            await self.writer.drain()          # <-- important: let the loop flush the buffer

            if time_wait:
                # Give time for the reader to collect data
                await asyncio.sleep(0.1)
            return True
        except Exception as e:
            logger.exception(f"Error sending command: {e}")
            return False

    async def async_read_hex(self) -> str:
        """Read hex data from serial port asynchronously"""
        if not self.is_port_open():
            raise ValueError("Serial port not initialized")

        buffer = []
        transport = cast(serial_asyncio.SerialTransport, self.writer.transport)

        # Get the number of bytes available to read
        if transport.serial:
            to_read = transport.serial.in_waiting

            for _ in range(to_read):
                try:
                    # Read exactly 1 byte with timeout
                    data = await asyncio.wait_for(self.reader.read(1), timeout=0.1)
                    if not data:
                        break
                    buffer.append(data.hex())
                except asyncio.TimeoutError:
                    break

            transport.serial.flush()

        return "".join(buffer)

    async def async_get_reader_info(self) -> Optional[dict[str, str]]:
        """Get reader information"""
        try:
            await self.async_send_command(Command.GET_INFO, InfoVersion.HARDWARE.value)
            hw_version = await self.async_read_hex()
            hw_version_text = self._extract_text_from_hex(hw_version)

            await self.async_send_command(Command.GET_INFO, InfoVersion.SOFTWARE.value)
            sw_version = await self.async_read_hex()
            sw_version_text = self._extract_text_from_hex(sw_version)

            await self.async_send_command(Command.GET_INFO, InfoVersion.MANUFACTURERS.value)
            manufacturer = await self.async_read_hex()
            manufacturer_text = self._extract_text_from_hex(manufacturer)

            return {
                "hardware_version": hw_version_text,
                "software_version": sw_version_text,
                "manufacturer": manufacturer_text,
            }

        except Exception as e:
            logger.exception(f"Error getting reader info: {e}")
            return None
