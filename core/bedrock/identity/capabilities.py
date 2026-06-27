"""
Capability scoping for nodes.

Defines what data categories a node can request, process, or store.
Capability scope is embedded in the node's certificate and enforced
by the Encryption Engine (AAD), Access Control, and Self-Healing Mesh.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class DataCategory(Enum):
    """Data categories that can be scoped to a node.

    Each vertical template defines its own categories. These are the base set.
    """
    IDENTITY = "identity"       # PII: names, DOB, SSN, address
    MEDICAL = "medical"         # Health records, conditions, medications
    TRANSACTION = "transaction" # Financial transactions
    PORTFOLIO = "portfolio"     # Investment positions, strategies
    INTELLIGENCE = "intelligence"  # Classified/sensitive intel
    AUTH = "auth"                # Credentials, sessions, MFA
    AUDIT = "audit"            # Audit chain entries


@dataclass
class CapabilityScope:
    """The set of data categories a node is authorized to access.

    Enforced at multiple layers:
    - Certificate: embedded in X.509 extensions
    - AAD: included in encryption context (mismatch = decrypt failure)
    - Access Control: RBAC checks against scope
    - Mesh: rerouting respects scope boundaries
    """
    node_id: str
    categories: List[DataCategory] = field(default_factory=list)
    operations: List[str] = field(default_factory=lambda: ["read"])  # read, write, consent

    def can_access(self, category: DataCategory) -> bool:
        """Check if this scope includes the given data category."""
        return category in self.categories

    def can_write(self, category: DataCategory) -> bool:
        """Check if this scope includes write access to the given category."""
        return category in self.categories and "write" in self.operations