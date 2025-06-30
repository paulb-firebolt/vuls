"""
OVAL Evaluation Engine
Implements proper OVAL criteria evaluation logic for vulnerability assessment.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple, Any, Union
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from ..models.base import get_db
from ..models.oval_schema import (
    OVALSchemaDefinition, OVALSchemaTest, OVALSchemaObject,
    OVALSchemaState, OVALSchemaCriteria, OVALSchemaReference
)

logger = logging.getLogger(__name__)


class OVALEvaluationEngine:
    """OVAL evaluation engine for processing criteria trees and vulnerability assessment."""

    def __init__(self):
        self.evaluation_cache = {}  # Cache for test evaluations
        logger.info("OVAL Evaluation Engine initialized")

    def evaluate_vulnerability(self, cve_id: str, package_name: str,
                             package_version: str, release: str = '22.04') -> Dict:
        """
        Evaluate if a package version is vulnerable according to OVAL definitions.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2023-38546')
            package_name: Package name (e.g., 'curl')
            package_version: Installed package version (e.g., '7.81.0-1ubuntu1.13')
            release: Ubuntu release (e.g., '22.04')

        Returns:
            Dict with vulnerability assessment results
        """
        try:
            db = next(get_db())
            try:
                # Find OVAL definitions for this CVE
                definitions = self._find_definitions_for_cve(db, cve_id, release)

                if not definitions:
                    return {
                        'vulnerable': False,
                        'confidence': 0.95,
                        'reason': f'No OVAL definitions found for {cve_id}',
                        'source': 'OVAL Evaluation Engine',
                        'evaluation_path': [],
                        'fixed_version': None
                    }

                # Evaluate each definition
                for definition in definitions:
                    result = self._evaluate_definition(
                        db, definition, package_name, package_version, release
                    )

                    if result['vulnerable']:
                        return result

                # If no definition matched as vulnerable
                return {
                    'vulnerable': False,
                    'confidence': 0.95,
                    'reason': f'Package {package_name} not vulnerable according to OVAL criteria',
                    'source': 'OVAL Evaluation Engine',
                    'evaluation_path': [],
                    'fixed_version': None
                }

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Error evaluating vulnerability {cve_id} for {package_name}: {e}")
            return {
                'vulnerable': True,  # Default to vulnerable on error for safety
                'confidence': 0.5,
                'reason': f'Evaluation error: {str(e)}',
                'source': 'OVAL Evaluation Engine',
                'evaluation_path': [],
                'fixed_version': None,
                'error': str(e)
            }

    def _find_definitions_for_cve(self, db: Session, cve_id: str, release: str) -> List[OVALSchemaDefinition]:
        """Find OVAL definitions that reference a specific CVE."""
        return db.query(OVALSchemaDefinition).join(OVALSchemaReference).filter(
            and_(
                OVALSchemaReference.ref_id == cve_id,
                OVALSchemaDefinition.release_version == release,
                OVALSchemaDefinition.class_type == 'patch'
            )
        ).all()

    def _evaluate_definition(self, db: Session, definition: OVALSchemaDefinition,
                           package_name: str, package_version: str, release: str) -> Dict:
        """Evaluate a single OVAL definition against a package."""
        try:
            logger.debug(f"Evaluating definition {definition.definition_id} for {package_name}")

            # Get the root criteria for this definition
            root_criteria = db.query(OVALSchemaCriteria).filter(
                and_(
                    OVALSchemaCriteria.definition_id == definition.id,
                    OVALSchemaCriteria.parent_id.is_(None)
                )
            ).first()

            if not root_criteria:
                return {
                    'vulnerable': False,
                    'confidence': 0.8,
                    'reason': 'No root criteria found',
                    'source': 'OVAL Evaluation Engine',
                    'evaluation_path': [],
                    'fixed_version': None
                }

            # Evaluate the criteria tree
            evaluation_result = self._evaluate_criteria(
                db, root_criteria, package_name, package_version, release
            )

            # Extract fixed version if vulnerable
            fixed_version = None
            if evaluation_result['result']:
                fixed_version = self._extract_fixed_version(db, definition, package_name)

            return {
                'vulnerable': evaluation_result['result'],
                'confidence': 0.95,
                'reason': evaluation_result['reason'],
                'source': 'OVAL Evaluation Engine',
                'evaluation_path': evaluation_result['path'],
                'fixed_version': fixed_version,
                'definition_id': definition.definition_id,
                'title': definition.title
            }

        except Exception as e:
            logger.error(f"Error evaluating definition {definition.definition_id}: {e}")
            return {
                'vulnerable': True,  # Default to vulnerable on error
                'confidence': 0.5,
                'reason': f'Definition evaluation error: {str(e)}',
                'source': 'OVAL Evaluation Engine',
                'evaluation_path': [],
                'fixed_version': None,
                'error': str(e)
            }

    def _evaluate_criteria(self, db: Session, criteria: OVALSchemaCriteria,
                         package_name: str, package_version: str, release: str) -> Dict:
        """Recursively evaluate OVAL criteria."""
        try:
            evaluation_path = [f"Criteria {criteria.id} ({criteria.operator})"]

            # Handle leaf nodes (test references)
            if criteria.test_ref:
                test_result = self._evaluate_test(
                    db, criteria.test_ref, package_name, package_version, release
                )
                evaluation_path.extend(test_result['path'])
                return {
                    'result': test_result['result'],
                    'reason': test_result['reason'],
                    'path': evaluation_path
                }

            # Handle extend definition references
            if criteria.extend_definition_ref:
                # For now, assume extend definitions are true (would need recursive lookup)
                evaluation_path.append(f"Extend definition: {criteria.extend_definition_ref} (assumed true)")
                return {
                    'result': True,
                    'reason': 'Extended definition assumed true',
                    'path': evaluation_path
                }

            # Handle criteria with children
            child_criteria = db.query(OVALSchemaCriteria).filter(
                OVALSchemaCriteria.parent_id == criteria.id
            ).all()

            if not child_criteria:
                return {
                    'result': False,
                    'reason': 'No child criteria (default false)',
                    'path': evaluation_path
                }

            # Evaluate children based on operator
            child_results = []
            for child in child_criteria:
                child_result = self._evaluate_criteria(
                    db, child, package_name, package_version, release
                )
                child_results.append(child_result)
                evaluation_path.extend(child_result['path'])

            # Apply logical operator
            if criteria.operator == 'AND':
                final_result = all(r['result'] for r in child_results)
                reason = f"AND operation: {len([r for r in child_results if r['result']])}/{len(child_results)} true"
            elif criteria.operator == 'OR':
                final_result = any(r['result'] for r in child_results)
                reason = f"OR operation: {len([r for r in child_results if r['result']])}/{len(child_results)} true"
            else:
                final_result = True
                reason = f"Unknown operator {criteria.operator} (default true)"

            return {
                'result': final_result,
                'reason': reason,
                'path': evaluation_path
            }

        except Exception as e:
            logger.error(f"Error evaluating criteria {criteria.id}: {e}")
            return {
                'result': True,  # Default to true on error for safety
                'reason': f'Criteria evaluation error: {str(e)}',
                'path': [f"Error in criteria {criteria.id}"]
            }

    def _evaluate_test(self, db: Session, test_ref: str, package_name: str,
                      package_version: str, release: str) -> Dict:
        """Evaluate an OVAL test."""
        try:
            # Check cache first
            cache_key = f"{test_ref}:{package_name}:{package_version}"
            if cache_key in self.evaluation_cache:
                return self.evaluation_cache[cache_key]

            # Find the test
            test = db.query(OVALSchemaTest).filter(
                OVALSchemaTest.test_id == test_ref
            ).first()

            if not test:
                result = {
                    'result': True,
                    'reason': f'Test {test_ref} not found (default true)',
                    'path': [f"Test {test_ref}: not found"]
                }
                self.evaluation_cache[cache_key] = result
                return result

            # Get the object this test references
            if not test.object_ref:
                result = {
                    'result': True,
                    'reason': 'No object reference (default true)',
                    'path': [f"Test {test_ref}: no object reference"]
                }
                self.evaluation_cache[cache_key] = result
                return result

            obj = db.query(OVALSchemaObject).filter(
                OVALSchemaObject.object_id == test.object_ref
            ).first()

            if not obj:
                result = {
                    'result': True,
                    'reason': f'Object {test.object_ref} not found (default true)',
                    'path': [f"Test {test_ref}: object not found"]
                }
                self.evaluation_cache[cache_key] = result
                return result

            # Check if this test applies to our package
            if obj.package_name and obj.package_name != package_name:
                result = {
                    'result': False,
                    'reason': f'Test applies to {obj.package_name}, not {package_name}',
                    'path': [f"Test {test_ref}: package mismatch"]
                }
                self.evaluation_cache[cache_key] = result
                return result

            # If object has no package name, we need to evaluate the states to see if they apply
            # (Many OVAL objects don't have package names but the states do)
            if not obj.package_name:
                # Continue to state evaluation - don't filter out yet
                pass

            # Evaluate states
            states = test.states
            if not states:
                result = {
                    'result': True,
                    'reason': 'No states to evaluate (default true)',
                    'path': [f"Test {test_ref}: no states"]
                }
                self.evaluation_cache[cache_key] = result
                return result

            # Evaluate each state
            state_results = []
            for state in states:
                state_result = self._evaluate_state(state, package_name, package_version)
                state_results.append(state_result)

            # Apply test check operation
            if test.check_operation == 'all':
                final_result = all(r['result'] for r in state_results)
                reason = f"All states must match: {len([r for r in state_results if r['result']])}/{len(state_results)} matched"
            elif test.check_operation == 'at least one':
                final_result = any(r['result'] for r in state_results)
                reason = f"At least one state must match: {len([r for r in state_results if r['result']])}/{len(state_results)} matched"
            else:
                final_result = any(r['result'] for r in state_results)
                reason = f"Default (any) state match: {len([r for r in state_results if r['result']])}/{len(state_results)} matched"

            result = {
                'result': final_result,
                'reason': reason,
                'path': [f"Test {test_ref}: {reason}"] + [r['reason'] for r in state_results]
            }

            self.evaluation_cache[cache_key] = result
            return result

        except Exception as e:
            logger.error(f"Error evaluating test {test_ref}: {e}")
            result = {
                'result': True,  # Default to true on error
                'reason': f'Test evaluation error: {str(e)}',
                'path': [f"Test {test_ref}: error"]
            }
            self.evaluation_cache[cache_key] = result
            return result

    def _evaluate_state(self, state: OVALSchemaState, package_name: str, package_version: str) -> Dict:
        """Evaluate an OVAL state against a package version."""
        try:
            # Check package name constraint
            if state.package_name and state.package_name != package_name:
                return {
                    'result': False,
                    'reason': f'State package {state.package_name} != {package_name}'
                }

            # Check EVR (Epoch-Version-Release) constraint
            if state.evr_operation and state.evr_value:
                version_result = self._compare_versions(
                    package_version, state.evr_operation, state.evr_value
                )
                return {
                    'result': version_result,
                    'reason': f'Version {package_version} {state.evr_operation} {state.evr_value}: {version_result}'
                }

            # If no specific constraints, assume it matches
            return {
                'result': True,
                'reason': 'No specific constraints (default true)'
            }

        except Exception as e:
            logger.error(f"Error evaluating state {state.state_id}: {e}")
            return {
                'result': True,  # Default to true on error
                'reason': f'State evaluation error: {str(e)}'
            }

    def _compare_versions(self, installed_version: str, operation: str, target_version: str) -> bool:
        """Compare package versions using OVAL operations."""
        try:
            # Use dpkg version comparison for Ubuntu packages
            from subprocess import run, PIPE

            # Normalize versions for comparison
            installed = self._normalize_version(installed_version)
            target = self._normalize_version(target_version)

            # Use dpkg --compare-versions for accurate Ubuntu version comparison
            if operation == 'less than':
                result = run(['dpkg', '--compare-versions', installed, 'lt', target],
                           capture_output=True)
                return result.returncode == 0
            elif operation == 'less than or equal':
                result = run(['dpkg', '--compare-versions', installed, 'le', target],
                           capture_output=True)
                return result.returncode == 0
            elif operation == 'greater than':
                result = run(['dpkg', '--compare-versions', installed, 'gt', target],
                           capture_output=True)
                return result.returncode == 0
            elif operation == 'greater than or equal':
                result = run(['dpkg', '--compare-versions', installed, 'ge', target],
                           capture_output=True)
                return result.returncode == 0
            elif operation == 'equals':
                result = run(['dpkg', '--compare-versions', installed, 'eq', target],
                           capture_output=True)
                return result.returncode == 0
            elif operation == 'not equal':
                result = run(['dpkg', '--compare-versions', installed, 'ne', target],
                           capture_output=True)
                return result.returncode == 0
            else:
                logger.warning(f"Unknown version operation: {operation}")
                return False

        except Exception as e:
            logger.error(f"Error comparing versions {installed_version} {operation} {target_version}: {e}")
            # Fallback to string comparison
            return self._fallback_version_compare(installed_version, operation, target_version)

    def _normalize_version(self, version: str) -> str:
        """Normalize version string for comparison."""
        # Remove epoch if present (e.g., "1:7.81.0-1ubuntu1.14" -> "7.81.0-1ubuntu1.14")
        if ':' in version:
            version = version.split(':', 1)[1]
        return version

    def _fallback_version_compare(self, installed: str, operation: str, target: str) -> bool:
        """Fallback version comparison using string/numeric comparison."""
        try:
            # Simple lexicographic comparison as fallback
            if operation == 'less than':
                return installed < target
            elif operation == 'less than or equal':
                return installed <= target
            elif operation == 'greater than':
                return installed > target
            elif operation == 'greater than or equal':
                return installed >= target
            elif operation == 'equals':
                return installed == target
            elif operation == 'not equal':
                return installed != target
            else:
                return False
        except Exception:
            return False

    def _extract_fixed_version(self, db: Session, definition: OVALSchemaDefinition, package_name: str) -> Optional[str]:
        """Extract the fixed version from OVAL definition states."""
        try:
            # Find states that reference the package and have version constraints
            states = db.query(OVALSchemaState).filter(
                and_(
                    OVALSchemaState.package_name == package_name,
                    OVALSchemaState.evr_operation.in_(['greater than or equal', 'equals']),
                    OVALSchemaState.evr_value.isnot(None)
                )
            ).all()

            # Look for the highest version that represents the fix
            fixed_versions = []
            for state in states:
                if state.evr_value:
                    fixed_versions.append(state.evr_value)

            if fixed_versions:
                # Return the first fixed version found (could be enhanced to find the "best" one)
                return fixed_versions[0]

            return None

        except Exception as e:
            logger.error(f"Error extracting fixed version: {e}")
            return None

    def clear_cache(self):
        """Clear the evaluation cache."""
        self.evaluation_cache.clear()
        logger.info("OVAL evaluation cache cleared")
