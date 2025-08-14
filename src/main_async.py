#!/usr/bin/env python3
import asyncio
import logging
import sys


from .async_rfid_reader import AsyncRFIDReader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


async def single_tag_mode(reader: AsyncRFIDReader):
    pass


async def inventory_mode(reader: AsyncRFIDReader):
    pass


def print_tag(tag: dict[str, str]):
    """Helper function to print tag information"""
    print(f"PC: {tag['pc']}")
    print(f"EPC: {tag['epc']}")
    print(f"RSSI: {tag['rssi']} dBm")
    print(f"CRC: {tag['crc']}")


def print_menu():
    """Print the operation mode menu"""
    print("\nRFID Reader Modes:")
    print("1. Single Tag Reading")
    print("2. Inventory Mode (Multiple Tags)")
    print("3. Switch Mode")
    print("q. Quit")
    return input("Select mode (1, 2, 3, or q): ")


async def main():
    # Initialize the RFID reader
    reader = AsyncRFIDReader(port="/dev/ttyUSB0")

    try:
        # Connect to the reader
        if not await reader.async_connect():
            print("Failed to connect to RFID reader")
            sys.exit(1)

        print("Successfully connected to RFID reader")
        print("\nReader Information:")
        reader_info = await reader.async_get_reader_info()
        if reader_info:
            print(f"Hardware Version: {reader_info['hardware_version']}")
            print(f"Software Version: {reader_info['software_version']}")
            print(f"Manufacturer: {reader_info['manufacturer']}")

        # Main program loop
        while True:
            choice = print_menu()

            if choice == "1":
                await single_tag_mode(reader)
            elif choice == "2":
                await inventory_mode(reader)
            elif choice == "3":
                continue  # Just show menu again
            elif choice.lower() == "q":
                break
            else:
                print("\nInvalid choice. Please try again.")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        reader.disconnect()
        print("\nRFID reader disconnected")


if __name__ == "__main__":
    asyncio.run(main())
