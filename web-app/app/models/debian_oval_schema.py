"""
Debian OVAL Schema Models
Schema-based models for Debian OVAL data with variable resolution support.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .base import Base


class DebianOVALSchemaDefinition(Base):
    """OVAL definition with schema-based structure for Debian."""
    __tablename__ = 'debian_oval_schema_definitions'

    id = Column(Integer, primary_key=True)
    definition_id = Column(String(255), nullable=False, index=True)
    release_version = Column(String(50), nullable=False, index=True)
    title = Column(Text)
    description = Column(Text)
    severity = Column(String(50))
    family = Column(String(100))
    class_type = Column(String(50))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    criteria = relationship("DebianOVALSchemaCriteria", back_populates="definition", cascade="all, delete-orphan")
    references = relationship("DebianOVALSchemaReference", back_populates="definition", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<DebianOVALSchemaDefinition(id={self.id}, definition_id='{self.definition_id}', release='{self.release_version}')>"


class DebianOVALSchemaTest(Base):
    """OVAL test with schema-based structure for Debian."""
    __tablename__ = 'debian_oval_schema_tests'

    id = Column(Integer, primary_key=True)
    test_id = Column(String(255), nullable=False, unique=True, index=True)
    test_type = Column(String(100), nullable=False)
    check_existence = Column(String(50))
    check_operation = Column(String(50))
    comment = Column(Text)
    object_ref = Column(String(255), index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    test_states = relationship("DebianOVALSchemaTestState", back_populates="test", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<DebianOVALSchemaTest(id={self.id}, test_id='{self.test_id}', type='{self.test_type}')>"


class DebianOVALSchemaObject(Base):
    """OVAL object with schema-based structure and variable resolution for Debian."""
    __tablename__ = 'debian_oval_schema_objects'

    id = Column(Integer, primary_key=True)
    object_id = Column(String(255), nullable=False, unique=True, index=True)
    object_type = Column(String(100), nullable=False)
    package_name = Column(String(255), index=True)  # Resolved from variables
    architecture = Column(String(50))
    variable_ref = Column(String(255), index=True)  # Reference to variable
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<DebianOVALSchemaObject(id={self.id}, object_id='{self.object_id}', package='{self.package_name}')>"


class DebianOVALSchemaState(Base):
    """OVAL state with schema-based structure for Debian."""
    __tablename__ = 'debian_oval_schema_states'

    id = Column(Integer, primary_key=True)
    state_id = Column(String(255), nullable=False, unique=True, index=True)
    state_type = Column(String(100), nullable=False)
    package_name = Column(String(255))
    evr_operation = Column(String(50))  # equals, less than, greater than, etc.
    evr_value = Column(String(255))     # Version constraint
    arch_operation = Column(String(50))
    arch_value = Column(String(100))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    test_states = relationship("DebianOVALSchemaTestState", back_populates="state", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<DebianOVALSchemaState(id={self.id}, state_id='{self.state_id}', evr='{self.evr_operation} {self.evr_value}')>"


class DebianOVALSchemaCriteria(Base):
    """OVAL criteria with schema-based structure for Debian."""
    __tablename__ = 'debian_oval_schema_criteria'

    id = Column(Integer, primary_key=True)
    definition_id = Column(Integer, ForeignKey('debian_oval_schema_definitions.id'), nullable=False, index=True)
    parent_id = Column(Integer, ForeignKey('debian_oval_schema_criteria.id'), index=True)
    operator = Column(String(20), nullable=False)  # AND, OR, LEAF, EXTEND
    test_ref = Column(String(255), index=True)     # For criterion elements
    extend_definition_ref = Column(String(255))    # For extend_definition elements
    comment = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    definition = relationship("DebianOVALSchemaDefinition", back_populates="criteria")
    parent = relationship("DebianOVALSchemaCriteria", remote_side=[id])
    children = relationship("DebianOVALSchemaCriteria", back_populates="parent")

    def __repr__(self):
        return f"<DebianOVALSchemaCriteria(id={self.id}, operator='{self.operator}', test_ref='{self.test_ref}')>"


class DebianOVALSchemaReference(Base):
    """OVAL reference with schema-based structure for Debian."""
    __tablename__ = 'debian_oval_schema_references'

    id = Column(Integer, primary_key=True)
    definition_id = Column(Integer, ForeignKey('debian_oval_schema_definitions.id'), nullable=False, index=True)
    source = Column(String(100))
    ref_id = Column(String(255), nullable=False, index=True)  # CVE-XXXX-XXXX, DSA-XXXX, etc.
    ref_url = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    definition = relationship("DebianOVALSchemaDefinition", back_populates="references")

    def __repr__(self):
        return f"<DebianOVALSchemaReference(id={self.id}, ref_id='{self.ref_id}', source='{self.source}')>"


class DebianOVALSchemaTestState(Base):
    """OVAL test-state relationship with schema-based structure for Debian."""
    __tablename__ = 'debian_oval_schema_test_states'

    id = Column(Integer, primary_key=True)
    test_id = Column(Integer, ForeignKey('debian_oval_schema_tests.id'), nullable=False, index=True)
    state_id = Column(Integer, ForeignKey('debian_oval_schema_states.id'), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    test = relationship("DebianOVALSchemaTest", back_populates="test_states")
    state = relationship("DebianOVALSchemaState", back_populates="test_states")

    def __repr__(self):
        return f"<DebianOVALSchemaTestState(test_id={self.test_id}, state_id={self.state_id})>"


class DebianOVALSchemaVariable(Base):
    """OVAL variable with schema-based structure for Debian."""
    __tablename__ = 'debian_oval_schema_variables'

    id = Column(Integer, primary_key=True)
    variable_id = Column(String(255), nullable=False, unique=True, index=True)
    variable_type = Column(String(100), nullable=False)  # constant_variable, etc.
    datatype = Column(String(50))  # string, int, boolean, etc.
    comment = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    values = relationship("DebianOVALSchemaVariableValue", back_populates="variable", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<DebianOVALSchemaVariable(id={self.id}, variable_id='{self.variable_id}', type='{self.variable_type}')>"


class DebianOVALSchemaVariableValue(Base):
    """OVAL variable value with schema-based structure for Debian."""
    __tablename__ = 'debian_oval_schema_variable_values'

    id = Column(Integer, primary_key=True)
    variable_id = Column(Integer, ForeignKey('debian_oval_schema_variables.id'), nullable=False, index=True)
    value = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    variable = relationship("DebianOVALSchemaVariable", back_populates="values")

    def __repr__(self):
        return f"<DebianOVALSchemaVariableValue(id={self.id}, value='{self.value}')>"
