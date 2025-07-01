"""
Schema-Based Ubuntu OVAL Source
Proper OVAL XML parsing using schema-aware approach for maximum accuracy.
"""

import logging
import requests
import bz2
import xml.etree.ElementTree as ET
import os
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from sqlalchemy.orm import Session
from sqlalchemy import text
from ..models.base import get_db
from ..models.oval_schema import (
    OVALSchemaDefinition, OVALSchemaTest, OVALSchemaObject,
    OVALSchemaState, OVALSchemaCriteria, OVALSchemaReference,
    OVALSchemaTestState, OVALSchemaVariable, OVALSchemaVariableValue
)
from .base_vulnerability_source import BaseOVALSource
from .oval_evaluation_engine import OVALEvaluationEngine

logger = logging.getLogger(__name__)


class SchemaBasedOVALSource(BaseOVALSource):
    """Schema-aware OVAL parser for Ubuntu OVAL files."""

    def __init__(self):
        super().__init__("ubuntu_oval_schema", "Ubuntu")
        self.oval_base_url = "https://security-metadata.canonical.com/oval"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnerabilityScanner/1.0 (Security Research)',
            'Accept-Encoding': 'gzip, deflate'
        })

        # Ubuntu release mapping
        self.ubuntu_releases = {
            '16.04': {
                'codename': 'xenial',
                'filename': 'com.ubuntu.xenial.usn.oval.xml.bz2',
                'version': '16.04'
            },
            '18.04': {
                'codename': 'bionic',
                'filename': 'com.ubuntu.bionic.usn.oval.xml.bz2',
                'version': '18.04'
            },
            '20.04': {
                'codename': 'focal',
                'filename': 'com.ubuntu.focal.usn.oval.xml.bz2',
                'version': '20.04'
            },
            '22.04': {
                'codename': 'jammy',
                'filename': 'com.ubuntu.jammy.usn.oval.xml.bz2',
                'version': '22.04'
            },
            '24.04': {
                'codename': 'noble',
                'filename': 'com.ubuntu.noble.usn.oval.xml.bz2',
                'version': '24.04'
            }
        }

        # Set up cache directory
        self.cache_dir = Path("/tmp/oval_cache")
        self.cache_dir.mkdir(exist_ok=True)

        # Cache settings
        self.cache_max_age_hours = 24  # Cache files for 24 hours

        # Initialize OVAL evaluation engine
        self.evaluation_engine = OVALEvaluationEngine()

        # Define XML namespaces for OVAL parsing
        self.namespaces = {
            'oval-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
            'linux-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
            'oval-com': 'http://oval.mitre.org/XMLSchema/oval-common-5'
        }

        logger.info("Schema-Based Ubuntu OVAL Source initialized")

    def get_oval_url(self, release: str) -> str:
        """Get the OVAL download URL for a specific release."""
        if release not in self.ubuntu_releases:
            raise ValueError(f"Unsupported Ubuntu release: {release}")

        filename = self.ubuntu_releases[release]['filename']
        return f"{self.oval_base_url}/{filename}"

    def _get_cache_path(self, release: str) -> Path:
        """Get the cache file path for a release."""
        filename = self.ubuntu_releases[release]['filename']
        # Remove .bz2 extension since we store decompressed data
        cache_filename = filename.replace('.bz2', '')
        return self.cache_dir / f"{release}_{cache_filename}"

    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cached file is still valid."""
        if not cache_path.exists():
            return False

        # Check file age
        file_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        max_age = timedelta(hours=self.cache_max_age_hours)

        return file_age < max_age

    def _save_to_cache(self, data: bytes, cache_path: Path) -> bool:
        """Save data to cache file."""
        try:
            with open(cache_path, 'wb') as f:
                f.write(data)
            logger.info(f"Saved {len(data)} bytes to cache: {cache_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving to cache {cache_path}: {e}")
            return False

    def _load_from_cache(self, cache_path: Path) -> Optional[bytes]:
        """Load data from cache file."""
        try:
            with open(cache_path, 'rb') as f:
                data = f.read()
            logger.info(f"Loaded {len(data)} bytes from cache: {cache_path}")
            return data
        except Exception as e:
            logger.error(f"Error loading from cache {cache_path}: {e}")
            return None

    def download_oval_file(self, release: str) -> Optional[bytes]:
        """Download and decompress OVAL file for a specific release with caching."""
        cache_path = self._get_cache_path(release)

        # Try to load from cache first
        if self._is_cache_valid(cache_path):
            logger.info(f"Using cached OVAL data for Ubuntu {release}")
            cached_data = self._load_from_cache(cache_path)
            if cached_data:
                return cached_data

        try:
            url = self.get_oval_url(release)
            logger.info(f"Downloading fresh OVAL data for Ubuntu {release} from {url}")

            response = self.session.get(url, timeout=600)  # 10 minutes timeout
            response.raise_for_status()

            # Decompress bz2 data
            decompressed_data = bz2.decompress(response.content)
            logger.info(f"Downloaded and decompressed {len(decompressed_data)} bytes for Ubuntu {release}")

            # Save to cache
            self._save_to_cache(decompressed_data, cache_path)

            return decompressed_data

        except Exception as e:
            logger.error(f"Error downloading OVAL file for Ubuntu {release}: {e}")

            # Try to use stale cache as fallback
            if cache_path.exists():
                logger.warning(f"Download failed, attempting to use stale cache for {release}")
                return self._load_from_cache(cache_path)

            return None

    def parse_oval_xml(self, oval_data: bytes, release: str) -> Dict:
        """Parse OVAL XML using schema-aware approach."""
        try:
            root = ET.fromstring(oval_data)

            # Extract all sections
            definitions = self._parse_definitions(root, release)
            tests = self._parse_tests(root)
            objects = self._parse_objects(root)
            states = self._parse_states(root)
            variables = self._parse_variables(root)

            return {
                'definitions': definitions,
                'tests': tests,
                'objects': objects,
                'states': states,
                'variables': variables
            }

        except Exception as e:
            logger.error(f"Error parsing OVAL XML: {e}")
            return {}

    def _parse_definitions(self, root: ET.Element, release: str) -> List[Dict]:
        """Parse OVAL definitions section."""
        definitions = []

        definitions_elem = root.find('oval-def:definitions', self.namespaces)
        if definitions_elem is None:
            return definitions

        for definition_elem in definitions_elem.findall('oval-def:definition', self.namespaces):
            # Only process patch definitions
            class_type = definition_elem.get('class', '')
            if class_type != 'patch':
                continue

            definition = self._parse_single_definition(definition_elem, release)
            if definition:
                definitions.append(definition)

        return definitions

    def _parse_single_definition(self, definition_elem: ET.Element, release: str) -> Optional[Dict]:
        """Parse a single OVAL definition."""
        try:
            def_id = definition_elem.get('id', '')
            if not def_id:
                return None

            # Extract metadata
            metadata = definition_elem.find('oval-def:metadata', self.namespaces)
            if metadata is None:
                return None

            title_elem = metadata.find('oval-def:title', self.namespaces)
            title = title_elem.text if title_elem is not None else ''

            description_elem = metadata.find('oval-def:description', self.namespaces)
            description = description_elem.text if description_elem is not None else ''

            # Extract affected information
            affected = metadata.find('oval-def:affected', self.namespaces)
            family = affected.get('family', '') if affected is not None else ''

            # Extract severity from advisory
            advisory = metadata.find('oval-def:advisory', self.namespaces)
            severity = ''
            if advisory is not None:
                severity_elem = advisory.find('oval-def:severity', self.namespaces)
                if severity_elem is not None:
                    severity = severity_elem.text

            # Extract references (CVEs, USNs)
            references = []
            for ref in metadata.findall('oval-def:reference', self.namespaces):
                ref_data = {
                    'source': ref.get('source', ''),
                    'ref_id': ref.get('ref_id', ''),
                    'ref_url': ref.get('ref_url', '')
                }
                if ref_data['ref_id']:
                    references.append(ref_data)

            # Parse criteria structure
            criteria = self._parse_criteria(definition_elem)

            return {
                'definition_id': def_id,
                'title': title,
                'description': description,
                'severity': severity,
                'family': family,
                'class_type': definition_elem.get('class', ''),
                'release': release,
                'references': references,
                'criteria': criteria
            }

        except Exception as e:
            logger.error(f"Error parsing definition: {e}")
            return None

    def _parse_criteria(self, definition_elem: ET.Element) -> Optional[Dict]:
        """Parse OVAL criteria structure."""
        criteria_elem = definition_elem.find('oval-def:criteria', self.namespaces)
        if criteria_elem is None:
            return None

        return self._parse_criteria_recursive(criteria_elem)

    def _parse_criteria_recursive(self, criteria_elem: ET.Element) -> Dict:
        """Recursively parse criteria structure."""
        criteria = {
            'operator': criteria_elem.get('operator', 'AND'),
            'criteria': [],
            'criterion': [],
            'extend_definition': []
        }

        # Parse nested criteria
        for nested_criteria in criteria_elem.findall('oval-def:criteria', self.namespaces):
            criteria['criteria'].append(self._parse_criteria_recursive(nested_criteria))

        # Parse criterion elements
        for criterion in criteria_elem.findall('oval-def:criterion', self.namespaces):
            criteria['criterion'].append({
                'test_ref': criterion.get('test_ref', ''),
                'comment': criterion.get('comment', '')
            })

        # Parse extend_definition elements
        for extend_def in criteria_elem.findall('oval-def:extend_definition', self.namespaces):
            criteria['extend_definition'].append({
                'definition_ref': extend_def.get('definition_ref', ''),
                'comment': extend_def.get('comment', ''),
                'applicability_check': extend_def.get('applicability_check', 'false')
            })

        return criteria

    def _parse_tests(self, root: ET.Element) -> Dict[str, Dict]:
        """Parse OVAL tests section."""
        tests = {}

        tests_elem = root.find('oval-def:tests', self.namespaces)
        if tests_elem is None:
            return tests

        # Parse dpkginfo_test elements (Ubuntu package tests)
        for test_elem in tests_elem.findall('linux-def:dpkginfo_test', self.namespaces):
            test_id = test_elem.get('id', '')
            if not test_id:
                continue

            test_data = {
                'test_id': test_id,
                'test_type': 'dpkginfo_test',
                'check_existence': test_elem.get('check_existence', 'at_least_one_exists'),
                'check': test_elem.get('check', 'all'),
                'comment': test_elem.get('comment', ''),
                'object_ref': '',
                'state_refs': []
            }

            # Extract object reference
            object_elem = test_elem.find('linux-def:object', self.namespaces)
            if object_elem is not None:
                test_data['object_ref'] = object_elem.get('object_ref', '')

            # Extract state references
            for state_elem in test_elem.findall('linux-def:state', self.namespaces):
                state_ref = state_elem.get('state_ref', '')
                if state_ref:
                    test_data['state_refs'].append(state_ref)

            tests[test_id] = test_data

        return tests

    def _parse_objects(self, root: ET.Element) -> Dict[str, Dict]:
        """Parse OVAL objects section."""
        objects = {}

        objects_elem = root.find('oval-def:objects', self.namespaces)
        if objects_elem is None:
            return objects

        # First, parse variables to resolve references
        variables = self._parse_variables(root)

        # Parse dpkginfo_object elements
        for obj_elem in objects_elem.findall('linux-def:dpkginfo_object', self.namespaces):
            obj_id = obj_elem.get('id', '')
            if not obj_id:
                continue

            obj_data = {
                'object_id': obj_id,
                'object_type': 'dpkginfo_object',
                'package_name': '',
                'architecture': '',
                'variable_ref': ''
            }

            # Extract package name - check for variable reference first
            name_elem = obj_elem.find('linux-def:name', self.namespaces)
            if name_elem is not None:
                var_ref = name_elem.get('var_ref')
                if var_ref and var_ref in variables:
                    # Resolve variable reference to get actual package names
                    obj_data['variable_ref'] = var_ref
                    # For now, use the first package name from the variable
                    # In a complete implementation, we'd create multiple objects
                    variable_values = variables[var_ref].get('values', [])
                    if variable_values:
                        obj_data['package_name'] = variable_values[0]
                else:
                    # Direct package name (no variable reference)
                    obj_data['package_name'] = name_elem.text or ''

            # Extract architecture (if specified)
            arch_elem = obj_elem.find('linux-def:arch', self.namespaces)
            if arch_elem is not None:
                obj_data['architecture'] = arch_elem.text or ''

            objects[obj_id] = obj_data

        return objects

    def _parse_states(self, root: ET.Element) -> Dict[str, Dict]:
        """Parse OVAL states section."""
        states = {}

        states_elem = root.find('oval-def:states', self.namespaces)
        if states_elem is None:
            return states

        # Parse dpkginfo_state elements
        for state_elem in states_elem.findall('linux-def:dpkginfo_state', self.namespaces):
            state_id = state_elem.get('id', '')
            if not state_id:
                continue

            state_data = {
                'state_id': state_id,
                'state_type': 'dpkginfo_state',
                'package_name': '',
                'evr_operation': '',
                'evr_value': '',
                'arch_operation': '',
                'arch_value': ''
            }

            # Extract package name constraint
            name_elem = state_elem.find('linux-def:name', self.namespaces)
            if name_elem is not None:
                state_data['package_name'] = name_elem.text or ''

            # Extract EVR (Epoch-Version-Release) constraint
            evr_elem = state_elem.find('linux-def:evr', self.namespaces)
            if evr_elem is not None:
                state_data['evr_operation'] = evr_elem.get('operation', 'equals')
                state_data['evr_value'] = evr_elem.text or ''

            # Extract architecture constraint
            arch_elem = state_elem.find('linux-def:arch', self.namespaces)
            if arch_elem is not None:
                state_data['arch_operation'] = arch_elem.get('operation', 'equals')
                state_data['arch_value'] = arch_elem.text or ''

            states[state_id] = state_data

        return states

    def _parse_variables(self, root: ET.Element) -> Dict[str, Dict]:
        """Parse OVAL variables section."""
        variables = {}

        variables_elem = root.find('oval-def:variables', self.namespaces)
        if variables_elem is None:
            return variables

        # Parse constant_variable elements
        for var_elem in variables_elem.findall('oval-def:constant_variable', self.namespaces):
            var_id = var_elem.get('id', '')
            if not var_id:
                continue

            var_data = {
                'variable_id': var_id,
                'variable_type': 'constant_variable',
                'datatype': var_elem.get('datatype', 'string'),
                'comment': var_elem.get('comment', ''),
                'values': []
            }

            # Extract all values for this variable
            for value_elem in var_elem.findall('oval-def:value', self.namespaces):
                if value_elem.text:
                    var_data['values'].append(value_elem.text)

            variables[var_id] = var_data

        return variables

    def evaluate_vulnerability(self, definition_id: str, package_name: str,
                             package_version: str, release: str) -> Dict:
        """Evaluate if a package version is vulnerable according to OVAL definition."""
        try:
            # This would be implemented to load the parsed OVAL data from database
            # and evaluate the criteria tree against the installed package

            # For now, return a placeholder
            return {
                'vulnerable': False,
                'confidence': 0.95,
                'evaluation_path': [],
                'fixed_version': None
            }

        except Exception as e:
            logger.error(f"Error evaluating vulnerability: {e}")
            return {
                'vulnerable': True,  # Default to vulnerable on error
                'confidence': 0.5,
                'evaluation_path': [],
                'fixed_version': None,
                'error': str(e)
            }

    def download_and_cache_data(self, release: str = None, **kwargs) -> bool:
        """Download and cache OVAL data using schema-based approach."""
        if not release:
            release = '22.04'  # Default to current LTS

        try:
            # Download OVAL file
            oval_data = self.download_oval_file(release)
            if not oval_data:
                return False

            # Parse using schema-aware approach
            logger.info(f"Parsing OVAL XML for Ubuntu {release} using schema-based approach")
            parsed_data = self.parse_oval_xml(oval_data, release)

            if not parsed_data:
                logger.error("Failed to parse OVAL XML")
                return False

            # Store in database
            logger.info(f"Storing parsed OVAL data in database for Ubuntu {release}")
            stored_count = self._store_parsed_data(parsed_data, release)

            logger.info(f"Successfully stored {stored_count} OVAL definitions for Ubuntu {release}")
            logger.info(f"Parsed {len(parsed_data.get('definitions', []))} definitions")
            logger.info(f"Parsed {len(parsed_data.get('tests', {}))} tests")
            logger.info(f"Parsed {len(parsed_data.get('objects', {}))} objects")
            logger.info(f"Parsed {len(parsed_data.get('states', {}))} states")
            logger.info(f"Parsed {len(parsed_data.get('variables', {}))} variables")

            return True

        except Exception as e:
            logger.error(f"Error in schema-based OVAL processing: {e}")
            return False

    def _store_parsed_data(self, parsed_data: Dict, release: str) -> int:
        """Store parsed OVAL data in the database."""
        db = next(get_db())
        stored_count = 0

        try:
            # Clear existing data for this release to avoid duplicates
            logger.info(f"Clearing existing OVAL data for Ubuntu {release}")

            # Clear in proper order due to foreign key constraints
            # First clear definitions (which cascade to criteria and references)
            db.query(OVALSchemaDefinition).filter(
                OVALSchemaDefinition.release_version == release
            ).delete()

            # Clear test-state relationships
            db.execute(text("DELETE FROM oval_schema_test_states"))

            # Clear tests, objects, states, variables (no foreign key dependencies)
            db.execute(text("DELETE FROM oval_schema_tests"))
            db.execute(text("DELETE FROM oval_schema_objects"))
            db.execute(text("DELETE FROM oval_schema_states"))
            db.execute(text("DELETE FROM oval_schema_variable_values"))
            db.execute(text("DELETE FROM oval_schema_variables"))

            db.commit()

            # Store definitions and related data
            definitions = parsed_data.get('definitions', [])
            tests = parsed_data.get('tests', {})
            objects = parsed_data.get('objects', {})
            states = parsed_data.get('states', {})
            variables = parsed_data.get('variables', {})

            # First, store variables, objects and states (no dependencies)
            variable_id_map = self._store_variables(db, variables)
            object_id_map = self._store_objects(db, objects)
            state_id_map = self._store_states(db, states)

            # Then store tests (depends on objects and states)
            test_id_map = self._store_tests(db, tests, object_id_map, state_id_map)

            # Finally store definitions with criteria and references
            for definition_data in definitions:
                try:
                    definition = self._store_definition(db, definition_data)
                    if definition:
                        stored_count += 1

                        # Store references
                        self._store_references(db, definition.id, definition_data.get('references', []))

                        # Store criteria
                        if definition_data.get('criteria'):
                            self._store_criteria(db, definition.id, definition_data['criteria'], test_id_map)

                except Exception as e:
                    logger.error(f"Error storing definition {definition_data.get('definition_id')}: {e}")
                    continue

            db.commit()
            logger.info(f"Successfully committed {stored_count} definitions to database")

        except Exception as e:
            logger.error(f"Error storing parsed data: {e}")
            db.rollback()
            raise
        finally:
            db.close()

        return stored_count

    def _store_variables(self, db: Session, variables: Dict) -> Dict[str, int]:
        """Store OVAL variables and return mapping of variable_id to database id."""
        variable_id_map = {}

        for var_id, var_data in variables.items():
            try:
                variable = OVALSchemaVariable(
                    variable_id=var_data['variable_id'],
                    variable_type=var_data['variable_type'],
                    datatype=var_data.get('datatype'),
                    comment=var_data.get('comment')
                )
                db.add(variable)
                db.flush()  # Get the ID
                variable_id_map[var_id] = variable.id

                # Store variable values
                for value in var_data.get('values', []):
                    var_value = OVALSchemaVariableValue(
                        variable_id=variable.id,
                        value=value
                    )
                    db.add(var_value)

            except Exception as e:
                logger.error(f"Error storing variable {var_id}: {e}")
                continue

        return variable_id_map

    def _store_objects(self, db: Session, objects: Dict) -> Dict[str, int]:
        """Store OVAL objects and return mapping of object_id to database id."""
        object_id_map = {}

        for obj_id, obj_data in objects.items():
            try:
                obj = OVALSchemaObject(
                    object_id=obj_data['object_id'],
                    object_type=obj_data['object_type'],
                    package_name=obj_data.get('package_name'),
                    architecture=obj_data.get('architecture'),
                    variable_ref=obj_data.get('variable_ref')
                )
                db.add(obj)
                db.flush()  # Get the ID
                object_id_map[obj_id] = obj.id

            except Exception as e:
                logger.error(f"Error storing object {obj_id}: {e}")
                continue

        return object_id_map

    def _store_states(self, db: Session, states: Dict) -> Dict[str, int]:
        """Store OVAL states and return mapping of state_id to database id."""
        state_id_map = {}

        for state_id, state_data in states.items():
            try:
                state = OVALSchemaState(
                    state_id=state_data['state_id'],
                    state_type=state_data['state_type'],
                    package_name=state_data.get('package_name'),
                    evr_operation=state_data.get('evr_operation'),
                    evr_value=state_data.get('evr_value'),
                    arch_operation=state_data.get('arch_operation'),
                    arch_value=state_data.get('arch_value')
                )
                db.add(state)
                db.flush()  # Get the ID
                state_id_map[state_id] = state.id

            except Exception as e:
                logger.error(f"Error storing state {state_id}: {e}")
                continue

        return state_id_map

    def _store_tests(self, db: Session, tests: Dict, object_id_map: Dict, state_id_map: Dict) -> Dict[str, int]:
        """Store OVAL tests and return mapping of test_id to database id."""
        test_id_map = {}

        for test_id, test_data in tests.items():
            try:
                test = OVALSchemaTest(
                    test_id=test_data['test_id'],
                    test_type=test_data['test_type'],
                    check_existence=test_data.get('check_existence'),
                    check_operation=test_data.get('check'),
                    comment=test_data.get('comment'),
                    object_ref=test_data.get('object_ref')
                )
                db.add(test)
                db.flush()  # Get the ID
                test_id_map[test_id] = test.id

                # Create test-state relationships
                for state_ref in test_data.get('state_refs', []):
                    if state_ref in state_id_map:
                        test_state = OVALSchemaTestState(
                            test_id=test.id,
                            state_id=state_id_map[state_ref]
                        )
                        db.add(test_state)

            except Exception as e:
                logger.error(f"Error storing test {test_id}: {e}")
                continue

        return test_id_map

    def _store_definition(self, db: Session, definition_data: Dict) -> Optional[OVALSchemaDefinition]:
        """Store a single OVAL definition."""
        try:
            definition = OVALSchemaDefinition(
                definition_id=definition_data['definition_id'],
                release_version=definition_data['release'],
                title=definition_data.get('title'),
                description=definition_data.get('description'),
                severity=definition_data.get('severity'),
                family=definition_data.get('family'),
                class_type=definition_data['class_type']
            )
            db.add(definition)
            db.flush()  # Get the ID
            return definition

        except Exception as e:
            logger.error(f"Error storing definition {definition_data.get('definition_id')}: {e}")
            return None

    def _store_references(self, db: Session, definition_id: int, references: List[Dict]):
        """Store OVAL references for a definition."""
        for ref_data in references:
            try:
                reference = OVALSchemaReference(
                    definition_id=definition_id,
                    source=ref_data.get('source'),
                    ref_id=ref_data['ref_id'],
                    ref_url=ref_data.get('ref_url')
                )
                db.add(reference)

            except Exception as e:
                logger.error(f"Error storing reference {ref_data.get('ref_id')}: {e}")
                continue

    def _store_criteria(self, db: Session, definition_id: int, criteria_data: Dict,
                       test_id_map: Dict, parent_id: Optional[int] = None):
        """Recursively store OVAL criteria."""
        try:
            # Store the current criteria node
            criteria = OVALSchemaCriteria(
                definition_id=definition_id,
                parent_id=parent_id,
                operator=criteria_data['operator'],
                comment=criteria_data.get('comment')
            )
            db.add(criteria)
            db.flush()  # Get the ID

            # Store criterion elements (test references)
            for criterion in criteria_data.get('criterion', []):
                test_ref = criterion.get('test_ref')
                if test_ref:
                    criterion_node = OVALSchemaCriteria(
                        definition_id=definition_id,
                        parent_id=criteria.id,
                        operator='LEAF',  # Leaf node
                        test_ref=test_ref,
                        comment=criterion.get('comment')
                    )
                    db.add(criterion_node)

            # Store extend_definition elements
            for extend_def in criteria_data.get('extend_definition', []):
                extend_node = OVALSchemaCriteria(
                    definition_id=definition_id,
                    parent_id=criteria.id,
                    operator='EXTEND',  # Extend definition
                    extend_definition_ref=extend_def.get('definition_ref'),
                    comment=extend_def.get('comment')
                )
                db.add(extend_node)

            # Recursively store nested criteria
            for nested_criteria in criteria_data.get('criteria', []):
                self._store_criteria(db, definition_id, nested_criteria, test_id_map, criteria.id)

        except Exception as e:
            logger.error(f"Error storing criteria: {e}")

    def lookup_vulnerability_info(self, cve_id: str, package_name: str,
                                release: str = '22.04', **kwargs) -> Optional[Dict]:
        """Look up vulnerability using schema-based evaluation."""
        try:
            # Get package version from kwargs or use a default for testing
            package_version = kwargs.get('package_version', '7.81.0-1ubuntu1.13')

            # Use the evaluation engine to assess vulnerability
            result = self.evaluation_engine.evaluate_vulnerability(
                cve_id, package_name, package_version, release
            )

            # Convert evaluation result to lookup format
            return {
                'found': result.get('vulnerable', False),
                'source': 'Schema-Based OVAL Evaluation',
                'fixed_version': result.get('fixed_version'),
                'severity': result.get('severity'),
                'confidence': result.get('confidence', 0.95),
                'reason': result.get('reason', ''),
                'evaluation_path': result.get('evaluation_path', []),
                'definition_id': result.get('definition_id'),
                'title': result.get('title')
            }

        except Exception as e:
            logger.error(f"Error in schema-based vulnerability lookup for {cve_id}: {e}")
            return {
                'found': False,
                'source': 'Schema-Based OVAL Evaluation',
                'reason': f'Evaluation error: {str(e)}',
                'error': str(e)
            }

    def get_package_vulnerabilities(self, package_name: str,
                                  release: str = '22.04', **kwargs) -> List[Dict]:
        """Get vulnerabilities using schema-based OVAL data with variable resolution."""
        vulnerabilities = []

        try:
            db = next(get_db())

            # Query OVAL schema tables directly using our variable resolution
            result = db.execute(text("""
                SELECT DISTINCT
                    r.ref_id as cve_id,
                    d.definition_id,
                    d.title,
                    d.description,
                    d.severity,
                    o.package_name,
                    o.variable_ref,
                    s.evr_operation,
                    s.evr_value
                FROM oval_schema_references r
                JOIN oval_schema_definitions d ON r.definition_id = d.id
                JOIN oval_schema_criteria c ON c.definition_id = d.id
                JOIN oval_schema_tests t ON t.test_id = c.test_ref
                JOIN oval_schema_objects o ON o.object_id = t.object_ref
                LEFT JOIN oval_schema_test_states ts ON ts.test_id = t.id
                LEFT JOIN oval_schema_states s ON s.id = ts.state_id
                WHERE o.package_name = :package_name
                AND d.release_version = :release
                AND r.ref_id LIKE 'CVE-%'
                ORDER BY r.ref_id DESC
            """), {
                'package_name': package_name,
                'release': release
            })

            for row in result.fetchall():
                cve_id, definition_id, title, description, severity, pkg_name, variable_ref, evr_operation, evr_value = row

                vulnerability = {
                    'cve_id': cve_id,
                    'definition_id': definition_id,
                    'title': title or f"{cve_id} vulnerability",
                    'description': description or '',
                    'summary': description or '',  # Add summary field
                    'severity': severity or 'Unknown',
                    'package_name': package_name,
                    'release': release,
                    'source': 'Ubuntu Schema-Based OVAL',
                    'confidence_score': 0.95,
                    'variable_ref': variable_ref,
                    'evr_operation': evr_operation,
                    'evr_value': evr_value,
                    'fixed_version': evr_value if evr_operation == 'less than' else None,
                    'not_fixed_yet': evr_operation is None or evr_value is None,
                    'cvss_score': self._map_severity_to_cvss(severity),  # Add CVSS score mapping
                    'published_date': None,  # Could be extracted from metadata if needed
                    'priority': severity  # Map severity to priority
                }
                vulnerabilities.append(vulnerability)

            logger.info(f"Found {len(vulnerabilities)} vulnerabilities for {package_name} using schema-based OVAL")

        except Exception as e:
            logger.error(f"Error getting package vulnerabilities for {package_name}: {e}")
        finally:
            if 'db' in locals():
                db.close()

        return vulnerabilities

    def should_update_data(self, release: str = None, **kwargs) -> bool:
        """Check if we should download fresh OVAL data for a release."""
        if not release:
            release = '22.04'

        # For now, always return True to test parsing
        return True

    def parse_oval_definition(self, definition_element: Any) -> Dict:
        """Parse an OVAL definition element (compatibility method)."""
        return self._parse_single_definition(definition_element, '22.04') or {}

    def extract_package_info(self, definition: Dict, definition_element: Any = None) -> List[Dict]:
        """Extract package information from an OVAL definition (compatibility method)."""
        # This is handled by the schema-based approach
        return []

    def _map_severity_to_cvss(self, severity: str) -> Optional[float]:
        """Map Ubuntu severity levels to approximate CVSS scores."""
        if not severity:
            return None

        severity_lower = severity.lower().strip()

        # Ubuntu severity to CVSS mapping
        severity_mapping = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'negligible': 1.0,
            'unknown': None
        }

        return severity_mapping.get(severity_lower, None)

    def get_cache_stats(self) -> Dict:
        """Get statistics about cached OVAL data."""
        return {
            'source_name': self.source_name,
            'source_type': self.source_type,
            'backend': 'Schema-Based OVAL Parser',
            'status': 'Development'
        }
