"""Pytest configuration and shared fixtures."""

import pytest
from bedrock.config import CoreConfig


@pytest.fixture
def config():
    """Provide a default CoreConfig for tests."""
    return CoreConfig(environment="test", debug=True)