"""
Bedrock Python SDK — Official client library for Bedrock Core.

Any licensed developer uses this SDK to connect to a Bedrock Core instance
and build identity-first, encrypted applications.

Usage:
    from bedrock_sdk import BedrockClient

    client = BedrockClient(
        base_url="https://bedrock.example.com",
        license_key="BR-DEV-xxxx-xxxx",
    )

    # Register a node
    node = client.nodes.register(name="my-service", node_type="application")

    # Create a data silo
    silo = client.silos.create(
        name="patient-records",
        display_name="Patient Records",
        categories=["medical", "phi"],
    )

    # Encrypt a field
    ciphertext = client.encryption.encrypt(
        plaintext="SSN-123-45-6789",
        silo=silo.silo_id,
        record_id="patient-001",
        scope="ssn",
        operation="store",
    )

    # Request consent
    consent = client.consent.request(
        requester_id=node.node_id,
        target_id="patient-001",
        silo_id=silo.silo_id,
        purpose="treatment",
        scope=["ssn", "diagnosis"],
    )
"""

from bedrock_sdk.client import BedrockClient
from bedrock_sdk.exceptions import (
    BedrockError,
    AuthenticationError,
    LicenseError,
    NotFoundError,
    ValidationError,
    QuotaExceededError,
    MeshError,
)

__version__ = "1.0.0"
__all__ = [
    "BedrockClient",
    "BedrockError",
    "AuthenticationError",
    "LicenseError",
    "NotFoundError",
    "ValidationError",
    "QuotaExceededError",
    "MeshError",
]