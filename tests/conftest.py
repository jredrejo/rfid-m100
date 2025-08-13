"""
pytest configuration and shared fixtures for my_package tests.
"""

import os
import sys
from unittest.mock import Mock, MagicMock
import queue
import pytest

# Add src to Python path for imports during testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# ============================================================================
# Serial/RFID-specific fixtures
# ============================================================================

@pytest.fixture
def mock_serial_port():
    """Mock serial port for testing RFID reader without hardware."""
    mock_port = Mock()
    mock_port.is_open = True
    mock_port.in_waiting = 0
    mock_port.timeout = 1.0
    mock_port.baudrate = 9600
    mock_port.port = "/dev/ttyUSB0"

    # Mock common serial methods
    mock_port.open.return_value = None
    mock_port.close.return_value = None
    mock_port.reset_input_buffer.return_value = None
    mock_port.reset_output_buffer.return_value = None
    mock_port.read.return_value = b""
    mock_port.readline.return_value = b""
    mock_port.write.return_value = 10  # bytes written
    mock_port.flush.return_value = None

    return mock_port


@pytest.fixture
def mock_rfid_responses():
    """Sample RFID card responses for testing."""
    return {
        "valid_card": b"\xBB\x02\x22\x00\x11\x02\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\xDA\x03",
        "invalid_card": b"\x02\x45\x52\x52\x4F\x52\x03",
        "no_card": b"",
        "partial_read": b"\x02\x31\x32\x33",
        "multiple_cards": [
            b"\xBB\x02\x22\x00\x11\x02\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x03",
            b"\xBB\x02\x22\x00\x11\x02\x41\x42\x43\x44\x45\x46\x37\x38\x39\x31\x32\x33\x34\x35\x03",
        ],
        "malformed": b"\x02\x31\x32\x33\x34\xFF\xFF\x03",  # corrupted data
    }


class MockSerialDevice:
    """Mock serial device that simulates RFID reader behavior."""

    def __init__(self):
        self.is_open = False
        self.port = None
        self.baudrate = 9600
        self.timeout = 1.0
        self.in_waiting = 0
        self._response_queue = queue.Queue()

        # Mocks so tests can use .side_effect / .assert_*
        self.read = MagicMock(side_effect=self._read_impl)
        self.readline = MagicMock(side_effect=self._read_impl)
        self.write = MagicMock(side_effect=lambda data: len(data))
        self.flush = MagicMock()
        self.reset_input_buffer = MagicMock(side_effect=self._drain_queue)
        self.reset_output_buffer = MagicMock()

    def _read_impl(self, size=1):
        try:
            return self._response_queue.get_nowait()
        except queue.Empty:
            return b""

    def _drain_queue(self):
        while True:
            try:
                self._response_queue.get_nowait()
            except queue.Empty:
                break

    def set_response(self, response):
        self._response_queue.put(response)

    def set_responses(self, responses):
        for r in responses:
            self._response_queue.put(r)

    def open(self):
        self.is_open = True

    def close(self):
        self.is_open = False


@pytest.fixture
def mock_serial_device():
    return MockSerialDevice()


# ============================================================================
# Parametrized fixtures for testing with different inputs
# ============================================================================


@pytest.fixture(params=["9600", "19200", "38400", "115200"])
def baud_rate(request):
    """Parametrized fixture for testing with different baud rates."""
    return int(request.param)


@pytest.fixture(params=["/dev/ttyUSB0", "/dev/ttyUSB1", "COM3", "COM4"])
def serial_port(request):
    """Parametrized fixture for testing with different serial ports."""
    return request.param


@pytest.fixture(params=[0.1, 0.5, 1.0, 2.0])
def timeout_values(request):
    """Parametrized fixture for testing with different timeout values."""
    return request.param


@pytest.fixture(params=[1, 10, 100])
def batch_size(request):
    """Parametrized fixture for testing with different batch sizes."""
    return request.param


# ============================================================================
# Configuration fixtures
# ============================================================================


@pytest.fixture
def test_config():
    """Test configuration dictionary."""
    return {
        "serial_port": "/dev/ttyUSB0",
        "baud_rate": 9600,
        "timeout": 1.0,
        "read_timeout": 0.5,
        "max_retries": 3,
        "debug": True,
        "card_format": "hex",
        "min_card_length": 8,
        "max_card_length": 16,
    }


# ============================================================================
# Pytest configuration hooks
# ============================================================================


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "unit: marks tests as unit tests")
    config.addinivalue_line(
        "markers", "hardware: marks tests that require actual hardware"
    )
    config.addinivalue_line(
        "markers", "serial: marks tests that use serial communication"
    )
    config.addinivalue_line(
        "markers", "rfid: marks tests specific to RFID functionality"
    )
