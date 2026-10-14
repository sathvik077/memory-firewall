"""Version constants.

``DETECTOR_VERSION`` is persisted on every risk finding so that a finding can always be traced to
the exact rule set that produced it. Bump it whenever a rule is added, removed or retuned.
"""

from __future__ import annotations

__all__ = ["DETECTOR_VERSION", "POLICY_REVISION", "SCHEMA_VERSION", "__version__"]

__version__ = "0.1.0"
SCHEMA_VERSION = "2026-10-14.1"
DETECTOR_VERSION = "mf-detector/1.0.0"
POLICY_REVISION = "mf-policy/1.0.0"
