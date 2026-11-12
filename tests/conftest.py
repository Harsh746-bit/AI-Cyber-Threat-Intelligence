import os
import pytest

TEST_SENSOR_KEY = "sentrix-test-isolated-sensor-key-32chars!"

# Set isolated test sensor key for the test process
os.environ["SENTRIX_SENSOR_API_KEY"] = TEST_SENSOR_KEY


@pytest.fixture(autouse=True)
def ensure_test_sensor_key(monkeypatch):
    """Ensure the test sensor key is present in environment for each test."""
    monkeypatch.setenv("SENTRIX_SENSOR_API_KEY", TEST_SENSOR_KEY)
