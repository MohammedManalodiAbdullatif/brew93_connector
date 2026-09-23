# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Post-model-sync patch: (re)create the external-ID mapping fields.

Idempotent — safe on every migrate, including existing installs.
"""

from brew93_connector.setup.custom_fields import create_external_id_fields


def execute():
    create_external_id_fields()
