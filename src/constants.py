from enum import Enum


class Command(Enum):
    FRAME_HEAD = b"\xBB"
    FRAME_TAIL = b"\x7E"
    TERMINATOR = b"\x0A\x0D"
    NOTIFICATION_POOLING = b"\xBB\x02\x22\x00\x11"
    GET_INVENTORY = b"\x27"
    GET_SINGLE_POOLING = b"\x22"
    GET_INFO = b"\x03"


class MemoryBank(Enum):
    RFU = b"\x00"
    EPC = b"\x01"
    TID = b"\x02"
    USER = b"\x03"
    MAX = b"\x04"


class InfoVersion(Enum):
    HARDWARE = b"\x00"
    SOFTWARE = b"\x01"
    MANUFACTURERS = b"\x02"


class PacketType(Enum):
    COMMAND = b"\x00"
    RESPONSE = b"\x01"
    NOTICE = b"\x02"


class Mixer(Enum):
    GAIN_0DB = b"\x00"
    GAIN_3DB = b"\x01"
    GAIN_6DB = b"\x02"
    GAIN_9DB = b"\x03"
    GAIN_12DB = b"\x04"
    GAIN_15DB = b"\x05"
    GAIN_16DB = b"\x06"
    GAIN_MAX = b"\x07"


class IF_Gain(Enum):
    GAIN_12DB = b"\x00"
    GAIN_18DB = b"\x01"
    GAIN_21DB = b"\x02"
    GAIN_24B = b"\x03"
    GAIN_27DB = b"\x04"
    GAIN_30DB = b"\x05"
    GAIN_36DB = b"\x06"
    GAIN_40DB = b"\x07"
    GAIN_MAX = b"\x08"


class Region(Enum):
    CHINA_900 = b"\x01"  # freq = 920.125 ~ 924.875MHz (China 900MHz)  Step:0.25MHz  # noqa: E501
    AMERICA = (
        b"\x02"  # freq = 902.250 ~ 927.750MHz (US)            Step:0.5MHz  # noqa: E501
    )
    EUROPE = (
        b"\x03"  # freq = 865.100 ~ 867.900MHz (Europe)        Step:0.2MHz  # noqa: E501
    )
    CHINA_800 = b"\x04"  # freq = 840.125 ~ 844.875MHz (China 800MHz)  Step:0.25MHz  # noqa: E501
    RESERVED1 = b"\x05"
    KOREA = (
        b"\x06"  # freq = 917.100 ~ 923.300MHz (Korea)         Step:0.2MHz  # noqa: E501
    )
    MAX = b"\x07"
