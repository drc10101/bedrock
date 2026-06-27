"""
Silo architecture — cryptographically isolated data partitions.

Data is partitioned into silos by category. A breach of one silo reveals
only that category of data, never the full picture.
"""

from dataclasses import dataclass, field
from typing import List, Optional


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
    name: str                    # e.g., "medical", "identity", "transaction"
    display_name: str            # e.g., "Medical Records", "Personal Information"
    hkdf_info: str               # e.g., "bedrock:silo:medical:v1"
    encrypted: bool = True       # All silos encrypted by default
    categories: List[str] = field(default_factory=list)  # Data categories in this silo
    description: str = ""

    def derive_key_info(self) -> str:
        """Return the HKDF info string for this silo's key derivation."""
        return self.hkdf_info