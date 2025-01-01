#!/usr/bin/env python3
import sys
import time

from rfid_reader import RFIDReader


def print_tag(tag):
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


def single_tag_mode(reader):
    """Run single tag reading mode"""
    print("\nSingle Tag Reading Mode")
    print("Press Ctrl+C to return to menu")
    try:
        while True:
            tag = reader.read_tag()
            if tag:
                print("\nTag detected!")
                print_tag(tag)
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nReturning to menu...")


def inventory_mode(reader):
    """Run inventory mode"""
    print("\nInventory Mode (Multiple Tags)")
    print("Press Ctrl+C to return to menu")
    try:
        while True:
            print("\nPerforming ISO18000-6C inventory...")
            tags = reader.inventory()

            if tags:
                print(f"\nFound {len(tags)} tags in this inventory round:")
                for i, tag in enumerate(tags, 1):
                    print(f"\nTag {i}:")
                    print_tag(tag)
            else:
                print("No tags found")

            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nReturning to menu...")


def main():
    # Initialize the RFID reader
    reader = RFIDReader(port="/dev/ttyUSB0")

    try:
        # Connect to the reader
        if not reader.connect():
            print("Failed to connect to RFID reader")
            sys.exit(1)

        print("Successfully connected to RFID reader")
        print("\nReader Information:")
        reader_info = reader.get_reader_info()
        if reader_info:
            print(f"Hardware Version: {reader_info['hardware_version']}")
            print(f"Software Version: {reader_info['software_version']}")
            print(f"Manufacturer: {reader_info['manufacturer']}")

        # Main program loop
        while True:
            choice = print_menu()

            if choice == "1":
                single_tag_mode(reader)
            elif choice == "2":
                inventory_mode(reader)
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
    main()
