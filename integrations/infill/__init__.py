"""
InFill Integration — Re-implementation on Bedrock Core.

This module provides the bridge between InFill's domain concepts
(Patients, Intake, E2EE, PIR, ePRR) and Bedrock's core modules
(Identity, Encryption, Data Separation, Consent, Audit, Transport).

InFill is the first vertical application built on Bedrock.
It uses the Healthcare Template for HIPAA compliance and maps
InFill-specific concepts to Bedrock's general-purpose architecture.

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

from infill.adapter import InFillAdapter

__all__ = ["InFillAdapter"]