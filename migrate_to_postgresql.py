#!/usr/bin/env python3

import sqlite3
import psycopg2
import psycopg2.extras
import logging
import sys
from typing import Dict, List, Tuple
import argparse
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DatabaseMigrator:
    """Migrates vulnerability databases from SQLite to PostgreSQL."""

    def __init__(self, pg_config: Dict[str, str]):
        self.pg_config = pg_config
        self.pg_conn = None

    def connect_postgresql(self):
        """Connect to PostgreSQL database."""
        try:
            self.pg_conn = psycopg2.connect(
                host=self.pg_config['host'],
                port=self.pg_config['port'],
                database=self.pg_config['database'],
                user=self.pg_config['user'],
                password=self.pg_config['password']
            )
            self.pg_conn.autocommit = False
            logger.info("Connected to PostgreSQL successfully")
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            raise

    def create_schema(self):
        """Create PostgreSQL schema from SQL file."""
        try:
            with open('postgresql_schema.sql', 'r') as f:
                schema_sql = f.read()

            with self.pg_conn.cursor() as cursor:
                cursor.execute(schema_sql)
                self.pg_conn.commit()
                logger.info("PostgreSQL schema created successfully")
        except Exception as e:
            logger.error(f"Failed to create schema: {e}")
            self.pg_conn.rollback()
            raise

    def migrate_cve_database(self, sqlite_path: str):
        """Migrate CVE database from SQLite to PostgreSQL."""
        logger.info(f"Starting CVE database migration from {sqlite_path}")

        try:
            sqlite_conn = sqlite3.connect(sqlite_path)
            sqlite_conn.row_factory = sqlite3.Row

            # Migration mapping: (sqlite_table, pg_table, columns)
            tables_to_migrate = [
                ('fetch_meta', 'fetch_meta_cve', ['created_at', 'updated_at', 'deleted_at', 'go_cve_dict_revision', 'schema_version', 'last_fetched_at']),
                ('nvds', 'nvds', ['cve_id', 'published_date', 'last_modified_date']),
                ('nvd_descriptions', 'nvd_descriptions', ['nvd_id', 'lang', 'value']),
                ('nvd_cvss2_extras', 'nvd_cvss2_extras', ['nvd_id', 'source', 'type', 'vector_string', 'access_vector', 'access_complexity', 'authentication', 'confidentiality_impact', 'integrity_impact', 'availability_impact', 'base_score', 'severity', 'exploitability_score', 'impact_score', 'obtain_all_privilege', 'obtain_user_privilege', 'obtain_other_privilege', 'user_interaction_required']),
                ('nvd_cvss3', 'nvd_cvss3', ['nvd_id', 'source', 'type', 'vector_string', 'attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction', 'scope', 'confidentiality_impact', 'integrity_impact', 'availability_impact', 'base_score', 'base_severity', 'exploitability_score', 'impact_score']),
                ('nvd_cvss40', 'nvd_cvss40', ['nvd_id', 'source', 'type', 'vector_string', 'base_score', 'base_severity', 'threat_score', 'threat_severity', 'environmental_score', 'environmental_severity']),
                ('nvd_cwes', 'nvd_cwes', ['nvd_id', 'source', 'type', 'cwe_id']),
                ('nvd_cpes', 'nvd_cpes', ['nvd_id', 'uri', 'formatted_string', 'well_formed_name', 'part', 'vendor', 'product', 'version', 'update', 'edition', 'language', 'software_edition', 'target_sw', 'target_hw', 'other', 'version_start_excluding', 'version_start_including', 'version_end_excluding', 'version_end_including']),
            ]

            for sqlite_table, pg_table, columns in tables_to_migrate:
                self._migrate_table(sqlite_conn, sqlite_table, pg_table, columns)

            sqlite_conn.close()
            logger.info("CVE database migration completed successfully")

        except Exception as e:
            logger.error(f"CVE database migration failed: {e}")
            raise

    def migrate_oval_database(self, sqlite_path: str):
        """Migrate OVAL database from SQLite to PostgreSQL."""
        logger.info(f"Starting OVAL database migration from {sqlite_path}")

        try:
            sqlite_conn = sqlite3.connect(sqlite_path)
            sqlite_conn.row_factory = sqlite3.Row

            # Migration mapping: (sqlite_table, pg_table, columns)
            tables_to_migrate = [
                ('fetch_meta', 'fetch_meta_oval', ['created_at', 'updated_at', 'deleted_at', 'goval_dict_revision', 'schema_version', 'last_fetched_at']),
                ('roots', 'roots', ['family', 'os_version', 'timestamp']),
                ('definitions', 'definitions', ['root_id', 'definition_id', 'title', 'description']),
                ('packages', 'packages', ['definition_id', 'name', 'version', 'arch', 'not_fixed_yet', 'modularity_label']),
                ('references', 'references', ['definition_id', 'source', 'ref_id', 'ref_url']),
                ('advisories', 'advisories', ['definition_id', 'severity', 'affected_repository', 'issued', 'updated']),
                ('cves', 'cves', ['advisory_id', 'cve_id', 'cvss2', 'cvss3', 'cwe', 'impact', 'href', 'public']),
                ('bugzillas', 'bugzillas', ['advisory_id', 'bugzilla_id', 'url', 'title']),
                ('resolutions', 'resolutions', ['advisory_id', 'state']),
                ('components', 'components', ['resolution_id', 'component']),
                ('debians', 'debians', ['definition_id']),
            ]

            for sqlite_table, pg_table, columns in tables_to_migrate:
                self._migrate_table(sqlite_conn, sqlite_table, pg_table, columns)

            sqlite_conn.close()
            logger.info("OVAL database migration completed successfully")

        except Exception as e:
            logger.error(f"OVAL database migration failed: {e}")
            raise

    def migrate_gost_database(self, sqlite_path: str):
        """Migrate GOST database from SQLite to PostgreSQL."""
        logger.info(f"Starting GOST database migration from {sqlite_path}")

        try:
            sqlite_conn = sqlite3.connect(sqlite_path)
            sqlite_conn.row_factory = sqlite3.Row

            # Migration mapping: (sqlite_table, pg_table, columns)
            tables_to_migrate = [
                ('fetch_meta', 'fetch_meta_gost', ['created_at', 'updated_at', 'deleted_at', 'gost_revision', 'schema_version', 'last_fetched_at']),
                ('ubuntu_cves', 'ubuntu_cves', ['public_date_at_usn', 'crd', 'candidate', 'public_date', 'description', 'ubuntu_description', 'priority', 'discovered_by', 'assigned_to']),
                ('ubuntu_patches', 'ubuntu_patches', ['ubuntu_cve_id', 'package_name']),
                ('redhat_cves', 'redhat_cves', ['threat_severity', 'public_date', 'iava', 'cwe', 'statement', 'acknowledgement', 'mitigation', 'name', 'document_distribution']),
                ('redhat_details', 'redhat_details', ['redhat_cve_id', 'detail']),
                ('redhat_references', 'redhat_references', ['redhat_cve_id', 'reference']),
                ('redhat_bugzillas', 'redhat_bugzillas', ['redhat_cve_id', 'description', 'bugzilla_id', 'url']),
                ('redhat_cvsses', 'redhat_cvsses', ['redhat_cve_id', 'cvss_base_score', 'cvss_scoring_vector', 'status']),
                ('redhat_cvss3', 'redhat_cvss3', ['redhat_cve_id', 'cvss3_base_score', 'cvss3_scoring_vector', 'status']),
                ('redhat_affected_releases', 'redhat_affected_releases', ['redhat_cve_id', 'product_name', 'release_date', 'advisory', 'package', 'cpe']),
                ('redhat_package_states', 'redhat_package_states', ['redhat_cve_id', 'product_name', 'fix_state', 'package_name', 'cpe']),
            ]

            # Check for optional tables that might exist
            cursor = sqlite_conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            existing_tables = {row[0] for row in cursor.fetchall()}

            # Add optional tables if they exist
            optional_tables = [
                ('debian_cves', 'debian_cves', ['package', 'cve_id', 'fixed_version', 'urgency', 'remote', 'description']),
                ('microsoft_cves', 'microsoft_cves', ['cve_id', 'impact', 'severity', 'exploitability', 'vector', 'complexity', 'authentication', 'confidentiality_impact', 'integrity_impact', 'availability_impact']),
            ]

            for sqlite_table, pg_table, columns in optional_tables:
                if sqlite_table in existing_tables:
                    tables_to_migrate.append((sqlite_table, pg_table, columns))

            for sqlite_table, pg_table, columns in tables_to_migrate:
                self._migrate_table(sqlite_conn, sqlite_table, pg_table, columns)

            sqlite_conn.close()
            logger.info("GOST database migration completed successfully")

        except Exception as e:
            logger.error(f"GOST database migration failed: {e}")
            raise

    def _migrate_table(self, sqlite_conn: sqlite3.Connection, sqlite_table: str, pg_table: str, columns: List[str]):
        """Migrate a single table from SQLite to PostgreSQL."""
        try:
            # Check if SQLite table exists
            cursor = sqlite_conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (sqlite_table,))
            if not cursor.fetchone():
                logger.warning(f"Table {sqlite_table} does not exist in SQLite database, skipping")
                return

            # Get row count for progress tracking
            cursor.execute(f"SELECT COUNT(*) FROM {sqlite_table}")
            total_rows = cursor.fetchone()[0]

            if total_rows == 0:
                logger.info(f"Table {sqlite_table} is empty, skipping")
                return

            logger.info(f"Migrating table {sqlite_table} -> {pg_table} ({total_rows:,} rows)")

            # Clear existing data in PostgreSQL table
            with self.pg_conn.cursor() as pg_cursor:
                pg_cursor.execute(f"TRUNCATE TABLE {pg_table} RESTART IDENTITY CASCADE")

            # Prepare column lists
            columns_str = ', '.join(columns)
            placeholders = ', '.join(['%s'] * len(columns))

            # Batch size for efficient migration
            batch_size = 1000
            migrated_rows = 0

            # Read data from SQLite in batches
            cursor.execute(f"SELECT {columns_str} FROM {sqlite_table}")

            while True:
                rows = cursor.fetchmany(batch_size)
                if not rows:
                    break

                # Convert SQLite rows to tuples, handling None values and data type conversions
                batch_data = []
                for row in rows:
                    converted_row = []
                    for i, value in enumerate(row):
                        # Convert SQLite numeric boolean to PostgreSQL boolean
                        if columns[i] in ['obtain_all_privilege', 'obtain_user_privilege', 'obtain_other_privilege', 'user_interaction_required', 'not_fixed_yet']:
                            converted_row.append(bool(value) if value is not None else None)
                        else:
                            converted_row.append(value)
                    batch_data.append(tuple(converted_row))

                # Insert batch into PostgreSQL
                with self.pg_conn.cursor() as pg_cursor:
                    insert_sql = f"INSERT INTO {pg_table} ({columns_str}) VALUES ({placeholders})"
                    psycopg2.extras.execute_batch(pg_cursor, insert_sql, batch_data)

                migrated_rows += len(rows)

                # Progress update
                if migrated_rows % 10000 == 0:
                    logger.info(f"  Migrated {migrated_rows:,}/{total_rows:,} rows ({migrated_rows/total_rows*100:.1f}%)")

            # Commit the transaction
            self.pg_conn.commit()
            logger.info(f"  Completed migration of {sqlite_table}: {migrated_rows:,} rows")

        except Exception as e:
            logger.error(f"Failed to migrate table {sqlite_table}: {e}")
            self.pg_conn.rollback()
            raise

    def verify_migration(self):
        """Verify that the migration was successful by comparing row counts."""
        logger.info("Verifying migration...")

        verification_queries = [
            ("CVE Database", [
                ("nvds", "SELECT COUNT(*) FROM nvds"),
                ("nvd_descriptions", "SELECT COUNT(*) FROM nvd_descriptions"),
                ("nvd_cvss3", "SELECT COUNT(*) FROM nvd_cvss3"),
            ]),
            ("GOST Database", [
                ("ubuntu_cves", "SELECT COUNT(*) FROM ubuntu_cves"),
                ("ubuntu_patches", "SELECT COUNT(*) FROM ubuntu_patches"),
                ("redhat_cves", "SELECT COUNT(*) FROM redhat_cves"),
            ]),
            ("OVAL Database", [
                ("definitions", "SELECT COUNT(*) FROM definitions"),
                ("packages", "SELECT COUNT(*) FROM packages"),
            ]),
        ]

        try:
            with self.pg_conn.cursor() as cursor:
                for db_name, queries in verification_queries:
                    logger.info(f"\n{db_name} verification:")
                    for table_name, query in queries:
                        try:
                            cursor.execute(query)
                            count = cursor.fetchone()[0]
                            logger.info(f"  {table_name}: {count:,} rows")
                        except Exception as e:
                            logger.warning(f"  {table_name}: Could not verify ({e})")

            logger.info("\nMigration verification completed")

        except Exception as e:
            logger.error(f"Verification failed: {e}")

    def close_connections(self):
        """Close database connections."""
        if self.pg_conn:
            self.pg_conn.close()
            logger.info("PostgreSQL connection closed")


def main():
    parser = argparse.ArgumentParser(description="Migrate vulnerability databases from SQLite to PostgreSQL")
    parser.add_argument("--pg-host", default="localhost", help="PostgreSQL host")
    parser.add_argument("--pg-port", default="5432", help="PostgreSQL port")
    parser.add_argument("--pg-database", default="vuls", help="PostgreSQL database name")
    parser.add_argument("--pg-user", default="vuls", help="PostgreSQL username")
    parser.add_argument("--pg-password", default="SuperSecretKey", help="PostgreSQL password")
    parser.add_argument("--cve-db", default="./db/cve.sqlite3", help="Path to CVE SQLite database")
    parser.add_argument("--oval-db", default="./db/oval.sqlite3", help="Path to OVAL SQLite database")
    parser.add_argument("--gost-db", default="./db/gost.sqlite3", help="Path to GOST SQLite database")
    parser.add_argument("--create-schema", action="store_true", help="Create PostgreSQL schema")
    parser.add_argument("--migrate-cve", action="store_true", help="Migrate CVE database")
    parser.add_argument("--migrate-oval", action="store_true", help="Migrate OVAL database")
    parser.add_argument("--migrate-gost", action="store_true", help="Migrate GOST database")
    parser.add_argument("--migrate-all", action="store_true", help="Migrate all databases")

    args = parser.parse_args()

    # PostgreSQL configuration
    pg_config = {
        'host': args.pg_host,
        'port': args.pg_port,
        'database': args.pg_database,
        'user': args.pg_user,
        'password': args.pg_password,
    }

    migrator = DatabaseMigrator(pg_config)

    try:
        migrator.connect_postgresql()

        if args.create_schema or args.migrate_all:
            migrator.create_schema()

        if args.migrate_cve or args.migrate_all:
            migrator.migrate_cve_database(args.cve_db)

        if args.migrate_oval or args.migrate_all:
            migrator.migrate_oval_database(args.oval_db)

        if args.migrate_gost or args.migrate_all:
            migrator.migrate_gost_database(args.gost_db)

        if args.migrate_all or args.migrate_cve or args.migrate_oval or args.migrate_gost:
            migrator.verify_migration()

        logger.info("Migration completed successfully!")

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        sys.exit(1)

    finally:
        migrator.close_connections()


if __name__ == "__main__":
    main()
