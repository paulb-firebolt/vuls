"""Database models for the Vuls Web application"""

from .base import Base
from .user import User
from .host import Host
from .scan import Scan
from .vulnerability import Vulnerability
from .scheduled_task import ScheduledTask, TaskRun
from .lynis_scan import LynisScan
from .lynis_control import LynisControl
from .lynis_finding import LynisFinding
from .oval_schema import (
    OVALSchemaDefinition, OVALSchemaTest, OVALSchemaObject,
    OVALSchemaState, OVALSchemaCriteria, OVALSchemaReference,
    OVALSchemaTestState, OVALSchemaVariable, OVALSchemaVariableValue
)
from .debian_oval_schema import (
    DebianOVALSchemaDefinition, DebianOVALSchemaTest, DebianOVALSchemaObject,
    DebianOVALSchemaState, DebianOVALSchemaCriteria, DebianOVALSchemaReference,
    DebianOVALSchemaTestState, DebianOVALSchemaVariable, DebianOVALSchemaVariableValue
)
from .nvd_cve_cache import NVDCVECache

__all__ = [
    "Base",
    "User",
    "Host",
    "Scan",
    "Vulnerability",
    "ScheduledTask",
    "TaskRun",
    "LynisScan",
    "LynisControl",
    "LynisFinding",
    # Ubuntu OVAL Schema
    "OVALSchemaDefinition",
    "OVALSchemaTest",
    "OVALSchemaObject",
    "OVALSchemaState",
    "OVALSchemaCriteria",
    "OVALSchemaReference",
    "OVALSchemaTestState",
    "OVALSchemaVariable",
    "OVALSchemaVariableValue",
    # Debian OVAL Schema
    "DebianOVALSchemaDefinition",
    "DebianOVALSchemaTest",
    "DebianOVALSchemaObject",
    "DebianOVALSchemaState",
    "DebianOVALSchemaCriteria",
    "DebianOVALSchemaReference",
    "DebianOVALSchemaTestState",
    "DebianOVALSchemaVariable",
    "DebianOVALSchemaVariableValue",
    # NVD CVE Cache
    "NVDCVECache"
]
