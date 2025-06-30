#!/usr/bin/env python3
"""
OVAL Data Management CLI
Provides command-line interface for managing Ubuntu OVAL vulnerability data.
"""

import sys
import os
import argparse
import logging
from datetime import datetime

# Add the web-app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'web-app'))

from app.services.unified_ubuntu_security import unified_ubuntu_security
from app.services.ubuntu_oval_source import UbuntuOVALSource
from app.services.ubuntu_security_lookup import UbuntuSecurityLookup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def cmd_status(args):
    """Show status of all vulnerability data sources."""
    print("Ubuntu Vulnerability Data Status")
    print("=" * 50)

    try:
        stats = unified_ubuntu_security.get_comprehensive_stats()

        print(f"\nSummary:")
        print(f"  Active Sources: {stats['summary']['active_sources']}/{stats['summary']['total_sources']}")
        print(f"  Total Vulnerabilities: {stats['summary']['total_vulnerabilities']:,}")
        print(f"  Last Update: {stats['summary']['last_update']}")

        print(f"\nUSN Data:")
        usn_stats = stats['sources'].get('usn', {})
        if usn_stats.get('error'):
            print(f"  Status: ERROR - {usn_stats['error']}")
        else:
            print(f"  Last Download: {usn_stats.get('last_download')}")
            print(f"  Total USNs: {usn_stats.get('unique_usns', 0):,}")
            print(f"  Unique CVEs: {usn_stats.get('unique_cves', 0):,}")
            print(f"  Total Records: {usn_stats.get('total_records', 0):,}")

        print(f"\nOVAL Data:")
        oval_stats = stats['sources'].get('oval', {})
        if oval_stats.get('error'):
            print(f"  Status: ERROR - {oval_stats['error']}")
        else:
            releases = oval_stats.get('releases', {})
            for release, release_stats in releases.items():
                print(f"  Ubuntu {release}:")
                print(f"    Last Download: {release_stats.get('last_download')}")
                print(f"    Definitions: {release_stats.get('definitions_count', 0):,}")
                print(f"    Packages: {release_stats.get('packages_count', 0):,}")
                print(f"    CVEs: {release_stats.get('cves_count', 0):,}")
                if release_stats.get('file_size'):
                    size_mb = release_stats['file_size'] / (1024 * 1024)
                    print(f"    File Size: {size_mb:.1f} MB")

    except Exception as e:
        print(f"Error getting status: {e}")
        return 1

    return 0


def cmd_update(args):
    """Update vulnerability data."""
    print("Updating Ubuntu Vulnerability Data")
    print("=" * 50)

    try:
        if args.source == 'all':
            print("Updating all data sources...")
            results = unified_ubuntu_security.update_all_data(force=args.force)

            print(f"\nResults:")
            print(f"  USN: {'✅ Success' if results.get('usn') else '❌ Failed'}")
            print(f"  OVAL: {'✅ Success' if results.get('oval') else '❌ Failed'}")

            if results.get('error'):
                print(f"  Error: {results['error']}")
                return 1

        elif args.source == 'usn':
            print("Updating USN data...")
            usn_source = UbuntuSecurityLookup()
            if args.force:
                success = usn_source.force_update()
            else:
                success = usn_source.download_and_cache_ubuntu_data()

            print(f"USN update: {'✅ Success' if success else '❌ Failed'}")
            if not success:
                return 1

        elif args.source == 'oval':
            print("Updating OVAL data...")
            oval_source = UbuntuOVALSource()

            if args.release:
                releases = [args.release]
            else:
                releases = ['22.04', '24.04']

            success = True
            for release in releases:
                print(f"  Updating Ubuntu {release}...")
                if args.force or oval_source.should_update_data(release=release):
                    result = oval_source.download_and_cache_data(release=release)
                    print(f"    Ubuntu {release}: {'✅ Success' if result else '❌ Failed'}")
                    if not result:
                        success = False
                else:
                    print(f"    Ubuntu {release}: ⏭️  Up to date")

            if not success:
                return 1

        print(f"\n✅ Update completed at {datetime.now()}")

    except Exception as e:
        print(f"❌ Update failed: {e}")
        return 1

    return 0


def cmd_lookup(args):
    """Look up vulnerability information."""
    print(f"Looking up {args.cve} in {args.package} (Ubuntu {args.release})")
    print("=" * 50)

    try:
        result = unified_ubuntu_security.lookup_vulnerability(
            cve_id=args.cve,
            package_name=args.package,
            release=args.release,
            prefer_source=args.prefer_source
        )

        combined = result.get('combined', {})

        if combined.get('found'):
            print(f"✅ Vulnerability found")
            print(f"Primary Source: {combined.get('primary_source')}")
            print(f"Status: {combined.get('status')}")
            print(f"Fixed Version: {combined.get('fixed_version', 'N/A')}")
            print(f"Severity: {combined.get('priority') or combined.get('severity', 'N/A')}")
            print(f"Confidence: {combined.get('confidence_score', 0):.2f}")

            if combined.get('description'):
                print(f"\nDescription:")
                print(f"  {combined['description'][:200]}...")

            # Show source details
            sources = result.get('sources', {})
            if len(sources) > 1:
                print(f"\nSource Details:")
                for source_name, source_data in sources.items():
                    if isinstance(source_data, dict) and source_data.get('found'):
                        print(f"  {source_name.upper()}: {source_data.get('status', 'N/A')}")
        else:
            print(f"❌ Vulnerability not found")
            print(f"Reason: {combined.get('reason', 'Unknown')}")
            print(f"Sources consulted: {', '.join(combined.get('sources_consulted', []))}")

    except Exception as e:
        print(f"❌ Lookup failed: {e}")
        return 1

    return 0


def cmd_package(args):
    """Analyze all vulnerabilities for a package."""
    print(f"Analyzing package '{args.package}' (Ubuntu {args.release})")
    print("=" * 50)

    try:
        result = unified_ubuntu_security.get_package_vulnerabilities(
            package_name=args.package,
            release=args.release
        )

        combined = result.get('combined', [])

        if combined:
            print(f"Found {len(combined)} vulnerabilities:")

            for vuln in combined[:args.limit]:
                cve_id = vuln.get('cve_id')
                status = vuln.get('status', 'unknown')
                severity = vuln.get('priority') or vuln.get('severity', 'N/A')
                sources = list(vuln.get('sources', {}).keys())

                print(f"  {cve_id}: {status} ({severity}) - Sources: {', '.join(sources)}")

            if len(combined) > args.limit:
                print(f"  ... and {len(combined) - args.limit} more")
        else:
            print("No vulnerabilities found for this package")

    except Exception as e:
        print(f"❌ Package analysis failed: {e}")
        return 1

    return 0


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="Manage Ubuntu OVAL vulnerability data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s status                           # Show data status
  %(prog)s update --source all              # Update all sources
  %(prog)s update --source oval --force     # Force OVAL update
  %(prog)s lookup CVE-2023-47100 perl       # Look up specific CVE
  %(prog)s package openssl --release 24.04  # Analyze package
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Status command
    status_parser = subparsers.add_parser('status', help='Show vulnerability data status')

    # Update command
    update_parser = subparsers.add_parser('update', help='Update vulnerability data')
    update_parser.add_argument('--source', choices=['all', 'usn', 'oval'], default='all',
                              help='Data source to update (default: all)')
    update_parser.add_argument('--release', choices=['22.04', '24.04'],
                              help='Ubuntu release for OVAL updates')
    update_parser.add_argument('--force', action='store_true',
                              help='Force update even if data is current')

    # Lookup command
    lookup_parser = subparsers.add_parser('lookup', help='Look up specific vulnerability')
    lookup_parser.add_argument('cve', help='CVE identifier (e.g., CVE-2023-47100)')
    lookup_parser.add_argument('package', help='Package name (e.g., perl)')
    lookup_parser.add_argument('--release', default='22.04', choices=['22.04', '24.04'],
                              help='Ubuntu release (default: 22.04)')
    lookup_parser.add_argument('--prefer-source', choices=['usn', 'oval'], default='usn',
                              help='Preferred data source (default: usn)')

    # Package command
    package_parser = subparsers.add_parser('package', help='Analyze package vulnerabilities')
    package_parser.add_argument('package', help='Package name (e.g., openssl)')
    package_parser.add_argument('--release', default='22.04', choices=['22.04', '24.04'],
                               help='Ubuntu release (default: 22.04)')
    package_parser.add_argument('--limit', type=int, default=10,
                               help='Maximum vulnerabilities to show (default: 10)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Execute command
    if args.command == 'status':
        return cmd_status(args)
    elif args.command == 'update':
        return cmd_update(args)
    elif args.command == 'lookup':
        return cmd_lookup(args)
    elif args.command == 'package':
        return cmd_package(args)
    else:
        print(f"Unknown command: {args.command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
