#!/usr/bin/env python3
"""
Test script for OVAL validation framework.
Demonstrates comparison between current and schema-based OVAL engines.
"""

from ..services.oval_validation_service import OVALValidationService

def main():
    print("OVAL Validation Framework Test")
    print("=" * 60)

    # Initialize validation service
    validator = OVALValidationService()

    # Test cases - known vulnerabilities
    test_cases = [
        ('CVE-2023-38546', 'curl', '22.04'),
        ('CVE-2023-38545', 'curl', '22.04'),
        ('CVE-2024-3094', 'xz-utils', '22.04'),  # XZ backdoor
    ]

    print(f"Testing {len(test_cases)} vulnerability lookups...")
    print()

    for i, (cve_id, package_name, release) in enumerate(test_cases, 1):
        print(f"Test {i}: {cve_id} in {package_name} ({release})")
        print("-" * 40)

        validation = validator.validate_vulnerability_lookup(cve_id, package_name, release)

        print(f"Status: {validation.get('status')}")
        print(f"Agreement: {validation.get('agreement')}")

        current = validation.get('current_engine', {})
        schema = validation.get('schema_engine', {})

        print(f"Current engine: found={current.get('found')}, fixed_version={current.get('fixed_version')}")
        print(f"Schema engine:  found={schema.get('found')}, fixed_version={schema.get('fixed_version')}")

        if validation.get('differences'):
            print("Differences:")
            for diff in validation['differences']:
                print(f"  {diff['field']}: current={diff['current']}, schema={diff['schema']}")

        print()

    # Generate validation report
    print("Generating validation report...")
    report = validator.generate_validation_report()

    print(f"Validation Summary:")
    print(f"  Total validations: {report['total_validations']}")
    print(f"  Agreements: {report['summary']['agreement']}")
    print(f"  Disagreements: {report['summary']['disagreement']}")
    print(f"  Errors: {report['summary']['errors']}")
    print(f"  Agreement rate: {report['summary']['agreement_rate']:.2%}")

    print()
    print("Next Steps:")
    print("1. Implement full schema-based OVAL evaluation engine")
    print("2. Add database schema for storing parsed OVAL data")
    print("3. Implement proper OVAL criteria evaluation logic")
    print("4. Add EVR (Epoch-Version-Release) comparison functions")
    print("5. Test against larger vulnerability datasets")

    print()
    print("Framework Benefits:")
    print("✓ File-based caching prevents hammering OVAL sources")
    print("✓ Schema-aware parsing for maximum accuracy")
    print("✓ Validation framework for comparing engines")
    print("✓ Comprehensive logging and error handling")
    print("✓ Extensible architecture for future enhancements")

if __name__ == "__main__":
    main()
