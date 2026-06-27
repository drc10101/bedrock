"""Bedrock SDK exception hierarchy."""


class BedrockError(Exception):
    """Base exception for all Bedrock SDK errors."""

    def __init__(self, message: str, status_code: int | None = None, detail: dict | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.detail = detail or {}


class AuthenticationError(BedrockError):
    """Invalid or missing authentication credentials."""
    pass


class LicenseError(BedrockError):
    """License validation failed, expired, or quota exceeded."""
    pass


class NotFoundError(BedrockError):
    """Requested resource not found."""
    pass


class ValidationError(BedrockError):
    """Request validation failed."""
    pass


class QuotaExceededError(BedrockError):
    """License quota exceeded (nodes, certificates, etc.)."""
    pass


class MeshError(BedrockError):
    """Self-Healing Mesh operation failed."""
    pass