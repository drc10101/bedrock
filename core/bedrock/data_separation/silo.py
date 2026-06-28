"""
Silo architecture — cryptographically isolated data partitions.

Data is partitioned into silos by category. A breach of one silo reveals
only that category of data, never the full picture.

Each silo has:
- Its own HKDF-derived encryption key (via KeyManager)
- Its own anonymous ID space (records in different silos link via opaque IDs)
- Its own access controls (ConsentGate gates cross-silo access)
- Categories for fine-grained compartmentalization within the silo

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class Silo:
    """A cryptographically isolated data partition.

    Each silo has its own encryption key (derived via HKDF from the master key),
    its own anonymous ID space, and its own access controls.

    Examples:
    - Healthcare: PII silo, Medical silo, Auth silo
    - Banking: Identity silo, Transaction silo, Auth silo
    - Defense: Identity silo, Intelligence silo, Auth silo
    """

    name: str  # e.g., "medical", "identity", "transaction"
    display_name: str  # e.g., "Medical Records", "Personal Information"
    hkdf_info: str  # e.g., "bedrock:silo:medical:v1"
    encrypted: bool = True  # All silos encrypted by default
    categories: list[str] = field(default_factory=list)  # Data categories in this silo
    description: str = ""
    key_version: int = 1  # Current key version for this silo
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def derive_key_info(self) -> str:
        """Return the HKDF info string for this silo's key derivation."""
        return self.hkdf_info

    def has_category(self, category: str) -> bool:
        """Check if this silo contains a given data category."""
        return category in self.categories


class SiloManager:
    """Manages the lifecycle of data silos.

    Silos are the fundamental isolation unit in Bedrock. Each silo:
    - Gets its own HKDF-derived encryption key
    - Has its own anonymous ID namespace
    - Requires explicit consent for cross-silo data access
    - Is audited on every access

    The SiloManager provides CRUD for silos and enforces that every
    piece of data belongs to exactly one silo.
    """

    def __init__(self):
        self._silos: dict[str, Silo] = {}

    def create_silo(
        self,
        name: str,
        display_name: str,
        categories: list[str] | None = None,
        description: str = "",
        encrypted: bool = True,
        hkdf_info: str | None = None,
    ) -> Silo:
        """Create a new data silo.

        Args:
            name: Unique silo identifier (lowercase, no spaces)
            display_name: Human-readable name
            categories: Data categories within this silo
            description: What this silo stores
            encrypted: Whether data in this silo is encrypted (default True)
            hkdf_info: Custom HKDF info string (default: bedrock:silo:{name}:v1)

        Returns:
            The created Silo

        Raises:
            ValueError: If a silo with this name already exists
        """
        if name in self._silos:
            raise ValueError(f"Silo '{name}' already exists")

        info = hkdf_info or f"bedrock:silo:{name}:v1"
        silo = Silo(
            name=name,
            display_name=display_name,
            hkdf_info=info,
            encrypted=encrypted,
            categories=categories or [],
            description=description,
        )
        self._silos[name] = silo
        return silo

    def get_silo(self, name: str) -> Silo | None:
        """Get a silo by name. Returns None if not found."""
        return self._silos.get(name)

    def list_silos(self) -> list[Silo]:
        """List all silos."""
        return list(self._silos.values())

    def update_silo(
        self,
        name: str,
        display_name: str | None = None,
        categories: list[str] | None = None,
        description: str | None = None,
    ) -> Silo:
        """Update a silo's metadata.

        Args:
            name: Silo to update
            display_name: New display name (or None to keep)
            categories: New categories list (replaces entirely)
            description: New description (or None to keep)

        Returns:
            Updated Silo

        Raises:
            KeyError: If silo doesn't exist
        """
        silo = self._silos.get(name)
        if silo is None:
            raise KeyError(f"Silo '{name}' not found")

        if display_name is not None:
            silo.display_name = display_name
        if categories is not None:
            silo.categories = categories
        if description is not None:
            silo.description = description

        return silo

    def delete_silo(self, name: str) -> None:
        """Delete a silo. Use with extreme caution — data becomes inaccessible.

        In production, deletion should be gated by audit chain approval.
        This is a hard delete; soft-delete patterns belong in the SDK layer.

        Raises:
            KeyError: If silo doesn't exist
        """
        if name not in self._silos:
            raise KeyError(f"Silo '{name}' not found")
        del self._silos[name]

    def silo_exists(self, name: str) -> bool:
        """Check if a silo exists."""
        return name in self._silos

    def get_silos_for_category(self, category: str) -> list[Silo]:
        """Find all silos that contain a given data category."""
        return [s for s in self._silos.values() if s.has_category(category)]
