"""
SQLAlchemy models for schema-based OVAL data storage.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .base import Base


class OVALSchemaDefinition(Base):
    """OVAL Schema Definition model - stores main patch definitions."""

    __tablename__ = 'oval_schema_definitions'

    id = Column(Integer, primary_key=True)
    definition_id = Column(String(255), unique=True, nullable=False)
    release_version = Column(String(10), nullable=False)
    title = Column(Text)
    description = Column(Text)
    severity = Column(String(50))
    family = Column(String(50))
    class_type = Column(String(20), nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), nullable=False)

    # Relationships
    criteria = relationship("OVALSchemaCriteria", back_populates="definition", cascade="all, delete-orphan")
    references = relationship("OVALSchemaReference", back_populates="definition", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<OVALSchemaDefinition(id={self.id}, definition_id='{self.definition_id}', release='{self.release_version}')>"


class OVALSchemaTest(Base):
    """OVAL Schema Test model - stores dpkginfo_test elements."""

    __tablename__ = 'oval_schema_tests'

    id = Column(Integer, primary_key=True)
    test_id = Column(String(255), unique=True, nullable=False)
    test_type = Column(String(50), nullable=False)
    check_existence = Column(String(50))
    check_operation = Column(String(20))
    comment = Column(Text)
    object_ref = Column(String(255))
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    # Relationships
    states = relationship("OVALSchemaState", secondary="oval_schema_test_states", back_populates="tests")

    def __repr__(self):
        return f"<OVALSchemaTest(id={self.id}, test_id='{self.test_id}', type='{self.test_type}')>"


class OVALSchemaObject(Base):
    """OVAL Schema Object model - stores package references."""

    __tablename__ = 'oval_schema_objects'

    id = Column(Integer, primary_key=True)
    object_id = Column(String(255), unique=True, nullable=False)
    object_type = Column(String(50), nullable=False)
    package_name = Column(String(255))
    architecture = Column(String(20))
    variable_ref = Column(String(255))
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    def __repr__(self):
        return f"<OVALSchemaObject(id={self.id}, object_id='{self.object_id}', package='{self.package_name}')>"


class OVALSchemaState(Base):
    """OVAL Schema State model - stores version constraints."""

    __tablename__ = 'oval_schema_states'

    id = Column(Integer, primary_key=True)
    state_id = Column(String(255), unique=True, nullable=False)
    state_type = Column(String(50), nullable=False)
    package_name = Column(String(255))
    evr_operation = Column(String(20))
    evr_value = Column(String(255))
    arch_operation = Column(String(20))
    arch_value = Column(String(20))
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    # Relationships
    tests = relationship("OVALSchemaTest", secondary="oval_schema_test_states", back_populates="states")

    def __repr__(self):
        return f"<OVALSchemaState(id={self.id}, state_id='{self.state_id}', package='{self.package_name}', evr='{self.evr_operation} {self.evr_value}')>"


class OVALSchemaCriteria(Base):
    """OVAL Schema Criteria model - stores logic trees."""

    __tablename__ = 'oval_schema_criteria'

    id = Column(Integer, primary_key=True)
    definition_id = Column(Integer, ForeignKey('oval_schema_definitions.id', ondelete='CASCADE'), nullable=False)
    parent_id = Column(Integer, ForeignKey('oval_schema_criteria.id', ondelete='CASCADE'))
    operator = Column(String(10), nullable=False)
    test_ref = Column(String(255))
    extend_definition_ref = Column(String(255))
    comment = Column(Text)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    # Relationships
    definition = relationship("OVALSchemaDefinition", back_populates="criteria")
    parent = relationship("OVALSchemaCriteria", remote_side=[id], back_populates="children")
    children = relationship("OVALSchemaCriteria", back_populates="parent", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<OVALSchemaCriteria(id={self.id}, operator='{self.operator}', test_ref='{self.test_ref}')>"


class OVALSchemaReference(Base):
    """OVAL Schema Reference model - stores CVE/USN mappings."""

    __tablename__ = 'oval_schema_references'

    id = Column(Integer, primary_key=True)
    definition_id = Column(Integer, ForeignKey('oval_schema_definitions.id', ondelete='CASCADE'), nullable=False)
    source = Column(String(50))
    ref_id = Column(String(100), nullable=False)
    ref_url = Column(Text)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    # Relationships
    definition = relationship("OVALSchemaDefinition", back_populates="references")

    def __repr__(self):
        return f"<OVALSchemaReference(id={self.id}, source='{self.source}', ref_id='{self.ref_id}')>"


class OVALSchemaTestState(Base):
    """OVAL Schema Test-State relationship model - many-to-many mapping."""

    __tablename__ = 'oval_schema_test_states'

    test_id = Column(Integer, ForeignKey('oval_schema_tests.id', ondelete='CASCADE'), primary_key=True)
    state_id = Column(Integer, ForeignKey('oval_schema_states.id', ondelete='CASCADE'), primary_key=True)

    def __repr__(self):
        return f"<OVALSchemaTestState(test_id={self.test_id}, state_id={self.state_id})>"


class OVALSchemaVariable(Base):
    """OVAL Schema Variable model - stores OVAL variables."""

    __tablename__ = 'oval_schema_variables'

    id = Column(Integer, primary_key=True)
    variable_id = Column(String(255), unique=True, nullable=False)
    variable_type = Column(String(50), nullable=False)
    datatype = Column(String(50))
    comment = Column(Text)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    # Relationships
    values = relationship("OVALSchemaVariableValue", back_populates="variable", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<OVALSchemaVariable(id={self.id}, variable_id='{self.variable_id}', type='{self.variable_type}')>"


class OVALSchemaVariableValue(Base):
    """OVAL Schema Variable Value model - stores multiple values per variable."""

    __tablename__ = 'oval_schema_variable_values'

    id = Column(Integer, primary_key=True)
    variable_id = Column(Integer, ForeignKey('oval_schema_variables.id', ondelete='CASCADE'), nullable=False)
    value = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    # Relationships
    variable = relationship("OVALSchemaVariable", back_populates="values")

    def __repr__(self):
        return f"<OVALSchemaVariableValue(id={self.id}, variable_id={self.variable_id}, value='{self.value}')>"
