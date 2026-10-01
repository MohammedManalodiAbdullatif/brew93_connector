# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
import frappe
from brew93_connector.setup.custom_fields import create_external_id_fields
from brew93_connector.setup.integration_user import ensure_integration_identity


def after_install():
    """Run automatically when brew93_connector is installed on a site.
    
    Provisions all custom fields and sets up the Brew93 Integration role,
    permissions, and system identity automatically.
    """
    create_external_id_fields()
    ensure_integration_identity()


def after_migrate():
    """Keep custom fields and integration role permissions in sync across bench updates."""
    create_external_id_fields()
    ensure_integration_identity()
