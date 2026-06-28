"""
Bedrock Data Separation Layer.

Silo-based compartmentalization, anonymous ID generation,
cross-silo identity mapping, and consent-gated data access.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

from bedrock.data_separation.anonymous_id import AnonymousID, IDMappingTable
from bedrock.data_separation.consent import ConsentEvent, ConsentGate, ConsentStatus
from bedrock.data_separation.silo import Silo, SiloManager

__all__ = [
    "Silo",
    "SiloManager",
    "AnonymousID",
    "IDMappingTable",
    "ConsentGate",
    "ConsentEvent",
    "ConsentStatus",
]
