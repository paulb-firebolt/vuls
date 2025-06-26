#!/usr/bin/env python3

import sqlite3
import psycopg2
import psycopg2.extras
import logging
import sys
import time
from typing import Dict, List
import argparse
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class VulsDatabaseSync:
    """Syncs vulnerability databases from SQLite (used by Vuls) to PostgreSQL for better performance."""

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

    def create_schema_if_needed(self):
        """Create PostgreSQL schema if it doesn't exist."""
        try:
            with open('postgresql_schema.sql', 'r') as f:
                schema_sql = f.read()

            with self.pg_conn.cursor() as cursor:
                cursor.execute(schema_sql)
                self.pg_conn.commit()
                logger.info("PostgreSQL schema verified/created successfully")
        except Exception as e:
            logger.error(f"Failed to create schema: {e}")
            self.pg_conn.rollback()
            raise

    def sync_databases(self, cve_db_path: str, oval_db_path: str, gost_db_path: str, force_full_sync: bool = False):
        """Sync all databases from SQLite to PostgreSQL."""
        logger.info("Starting database synchronization...")

        try:
            # Check if we need full sync or incremental sync
            if force_full_sync or self._needs_full_sync():
                logger.info("Performing full synchronization...")
                self._full_sync_cve_database(cve_db_path)
                self._full_sync_oval_database(oval_db_path)
                self._full_sync_gost_database(gost_db_path)
            else:
                logger.info("Performing incremental synchronization...")
                self._incremental_sync_cve_database(cve_db_path)
                self._incremental_sync_oval_database(oval_db_path)
                self._incremental_sync_gost_database(gost_db_path)

            # Update sync metadata
            self._update_sync_metadata()

            logger.info("Database synchronization completed successfully")

        except Exception as e:
            logger.error(f"Database synchronization failed: {e}")
            raise

    def _needs_full_sync(self) -> bool:
        """Check if we need a full sync based on metadata."""
        try:
            with self.pg_conn.cursor() as cursor:
                # Check if we have any sync metadata
                cursor.execute("SELECT COUNT(*) FROM fetch_meta_cve")
                cve_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM ubuntu_cves")
                gost_count = cursor.fetchone()[0]

                # If either is empty, we need full sync
                return cve_count == 0 or gost_count == 0

        except Exception as e:
            logger.debug(f"Error checking sync status: {e}")
            return True  # Default to full sync if we can't determine

    def _full_sync_cve_database(self, sqlite_path: str):
        """Perform full sync of CVE database."""
        logger.info(f"Full sync of CVE database from {sqlite_path}")

        try:
            sqlite_conn = sqlite3.connect(sqlite_path)
            sqlite_conn.row_factory = sqlite3.Row

            # Clear existing data
            with self.pg_conn.cursor() as cursor:
                cursor.execute("TRUNCATE TABLE nvd_descriptions, nvd_cvss3, nvd_cvss2_extras, nvd_cwes, nvd_cpes, nvds, fetch_meta_cve RESTART IDENTITY CASCADE")

            # Sync tables in dependency order
            self._sync_table(sqlite_conn, 'fetch_meta', 'fetch_meta_cve',
                           ['created_at', 'updated_at', 'deleted_at', 'go_cve_dict_revision', 'schema_version', 'last_fetched_at'])

            self._sync_table(sqlite_conn, 'nvds', 'nvds',
                           ['cve_id', 'published_date', 'last_modified_date'])

            self._sync_table(sqlite_conn, 'nvd_descriptions', 'nvd_descriptions',
                           ['nvd_id', 'lang', 'value'])

            self._sync_table(sqlite_conn, 'nvd_cvss3', 'nvd_cvss3',
                           ['nvd_id', 'source', 'type', 'vector_string', 'attack_vector', 'attack_complexity',
                            'privileges_required', 'user_interaction', 'scope', 'confidentiality_impact',
                            'integrity_impact', 'availability_impact', 'base_score', 'base_severity',
                            'exploitability_score', 'impact_score'])

            sqlite_conn.close()
            self.pg_conn.commit()

        except Exception as e:
            logger.error(f"CVE database full sync failed: {e}")
            self.pg_conn.rollback()
            raise

    def _full_sync_oval_database(self, sqlite_path: str):
        """Perform full sync of OVAL database."""
        logger.info(f"Full sync of OVAL database from {sqlite_path}")

        try:
            sqlite_conn = sqlite3.connect(sqlite_path)
            sqlite_conn.row_factory = sqlite3.Row

            # Clear existing data
            with self.pg_conn.cursor() as cursor:
                cursor.execute("TRUNCATE TABLE packages, references, advisories, cves, bugzillas, resolutions, components, debians, definitions, roots, fetch_meta_oval RESTART IDENTITY CASCADE")

            # Sync tables in dependency order
            self._sync_table(sqlite_conn, 'fetch_meta', 'fetch_meta_oval',
                           ['created_at', 'updated_at', 'deleted_at', 'goval_dict_revision', 'schema_version', 'last_fetched_at'])

            self._sync_table(sqlite_conn, 'roots', 'roots',
                           ['family', 'os_version', 'timestamp'])

            self._sync_table(sqlite_conn, 'definitions', 'definitions',
                           ['root_id', 'definition_id', 'title', 'description'])

            self._sync_table(sqlite_conn, 'packages', 'packages',
                           ['definition_id', 'name', 'version', 'arch', 'not_fixed_yet', 'modularity_label'])

            self._sync_table(sqlite_conn, 'debians', 'debians',
                           ['definition_id'])

            sqlite_conn.close()
            self.pg_conn.commit()

        except Exception as e:
            logger.error(f"OVAL database full sync failed: {e}")
            self.pg_conn.rollback()
            raise

    def _full_sync_gost_database(self, sqlite_path: str):
        """Perform full sync of GOST database."""
        logger.info(f"Full sync of GOST database from {sqlite_path}")

        try:
            sqlite_conn = sqlite3.connect(sqlite_path)
            sqlite_conn.row_factory = sqlite3.Row

            # Clear existing data
            with self.pg_conn.cursor() as cursor:
                cursor.execute("TRUNCATE TABLE ubuntu_patches, ubuntu_cves, redhat_details, redhat_references, redhat_bugzillas, redhat_cvsses, redhat_cvss3, redhat_affected_releases, redhat_package_states, redhat_cves, fetch_meta_gost RESTART IDENTITY CASCADE")

            # Sync tables in dependency order
            self._sync_table(sqlite_conn, 'fetch_meta', 'fetch_meta_gost',
                           ['created_at', 'updated_at', 'deleted_at', 'gost_revision', 'schema_version', 'last_fetched_at'])

            self._sync_table(sqlite_conn, 'ubuntu_cves', 'ubuntu_cves',
                           ['public_date_at_usn', 'crd', 'candidate', 'public_date', 'description', 'ubuntu_description', 'priority', 'discovered_by', 'assigned_to'])

            self._sync_table(sqlite_conn, 'ubuntu_patches', 'ubuntu_patches',
                           ['ubuntu_cve_id', 'package_name'])

            self._sync_table(sqlite_conn, 'redhat_cves', 'redhat_cves',
                           ['threat_severity', 'public_date', 'iava', 'cwe', 'statement', 'acknowledgement', 'mitigation', 'name', 'document_distribution'])

            sqlite_conn.close()
            self.pg_conn.commit()

        except Exception as e:
            logger.error(f"GOST database full sync failed: {e}")
            self.pg_conn.rollback()
            raise

    def _incremental_sync_cve_database(self, sqlite_path: str):
        """Perform incremental sync of CVE database based on last_fetched_at."""
        logger.info(f"Incremental sync of CVE database from {sqlite_path}")

        try:
            # Get last sync time from PostgreSQL
            with self.pg_conn.cursor() as cursor:
                cursor.execute("SELECT MAX(last_fetched_at) FROM fetch_meta_cve")
                last_sync = cursor.fetchone()[0]

            if not last_sync:
                logger.info("No previous sync found, performing full sync")
                self._full_sync_cve_database(sqlite_path)
                return

            sqlite_conn = sqlite3.connect(sqlite_path)
            sqlite_conn.row_factory = sqlite3.Row

            # Check if SQLite has newer data
            cursor = sqlite_conn.cursor()
            cursor.execute("SELECT MAX(last_fetched_at) FROM fetch_meta")
            sqlite_last_fetch = cursor.fetchone()[0]

            if not sqlite_last_fetch or sqlite_last_fetch <= last_sync:
                logger.info("CVE database is up to date")
                sqlite_conn.close()
                return

            logger.info(f"Syncing CVE data newer than {last_sync}")

            # For simplicity, we'll do a full sync for now
            # In production, you might want to implement true incremental sync
            self._full_sync_cve_database(sqlite_path)

        except Exception as e:
            logger.error(f"CVE database incremental sync failed: {e}")
            raise

    def _incremental_sync_oval_database(self, sqlite_path: str):
        """Perform incremental sync of OVAL database."""
        logger.info(f"Incremental sync of OVAL database from {sqlite_path}")
        # For simplicity, perform full sync
        # In production, implement proper incremental logic
        self._full_sync_oval_database(sqlite_path)

    def _incremental_sync_gost_database(self, sqlite_path: str):
        """Perform incremental sync of GOST database."""
        logger.info(f"Incremental sync of GOST database from {sqlite_path}")
        # For simplicity, perform full sync
        # In production, implement proper incremental logic
        self._full_sync_gost_database(sqlite_path)

    def _sync_table(self, sqlite_conn: sqlite3.Connection, sqlite_table: str, pg_table: str, columns: List[str]):
        """Sync a single table from SQLite to PostgreSQL."""
        try:
            # Check if SQLite table exists
            cursor = sqlite_conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (sqlite_table,))
            if not cursor.fetchone():
                logger.warning(f"Table {sqlite_table} does not exist in SQLite database, skipping")
                return

            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {sqlite_table}")
            total_rows = cursor.fetchone()[0]

            if total_rows == 0:
                logger.info(f"Table {sqlite_table} is empty, skipping")
                return

            logger.info(f"Syncing table {sqlite_table} -> {pg_table} ({total_rows:,} rows)")

            # Prepare column lists
            columns_str = ', '.join(columns)
            placeholders = ', '.join(['%s'] * len(columns))

            # Batch size for efficient sync
            batch_size = 1000
            synced_rows = 0

            # Read data from SQLite in batches
            cursor.execute(f"SELECT {columns_str} FROM {sqlite_table}")

            while True:
                rows = cursor.fetchmany(batch_size)
                if not rows:
                    break

                # Convert SQLite rows to tuples, handling data type conversions
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

                synced_rows += len(rows)

                # Progress update
                if synced_rows % 10000 == 0:
                    logger.info(f"  Synced {synced_rows:,}/{total_rows:,} rows ({synced_rows/total_rows*100:.1f}%)")

            logger.info(f"  Completed sync of {sqlite_table}: {synced_rows:,} rows")

        except Exception as e:
            logger.error(f"Failed to sync table {sqlite_table}: {e}")
            raise

    def _update_sync_metadata(self):
        """Update sync metadata in PostgreSQL."""
        try:
            with self.pg_conn.cursor() as cursor:
                # Create a sync log table if it doesn't exist
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sync_log (
                        id SERIAL PRIMARY KEY,
                        sync_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        sync_type VARCHAR(50),
                        status VARCHAR(20)
                    )
                """)

                # Insert sync record
                cursor.execute(
                    "INSERT INTO sync_log (sync_type, status) VALUES (%s, %s)",
                    ('full_sync', 'completed')
                )

                self.pg_conn.commit()

        except Exception as e:
            logger.warning(f"Failed to update sync metadata: {e}")

    def close_connection(self):
        """Close PostgreSQL connection."""
        if self.pg_conn:
            self.pg_conn.close()
            logger.info("PostgreSQL connection closed")


def main():
    parser = argparse.ArgumentParser(description="Sync vulnerability databases from SQLite to PostgreSQL")
    parser.add_argument("--pg-host", default="localhost", help="PostgreSQL host")
    parser.add_argument("--pg-port", default="5432", help="PostgreSQL port")
    parser.add_argument("--pg-database", default="vuls", help="PostgreSQL database name")
    parser.add_argument("--pg-user", default="vuls", help="PostgreSQL username")
    parser.add_argument("--pg-password", default="SuperSecretKey", help="PostgreSQL password")
    parser.add_argument("--cve-db", default="./db/cve.sqlite3", help="Path to CVE SQLite database")
    parser.add_argument("--oval-db", default="./db/oval.sqlite3", help="Path to OVAL SQLite database")
    parser.add_argument("--gost-db", default="./db/gost.sqlite3", help="Path to GOST SQLite database")
    parser.add_argument("--force-full-sync", action="store_true", help="Force full synchronization")
    parser.add_argument("--watch", action="store_true", help="Watch for changes and sync automatically")
    parser.add_argument("--watch-interval", type=int, default=300, help="Watch interval in seconds (default: 300)")

    args = parser.parse_args()

    # PostgreSQL configuration
    pg_config = {
        'host': args.pg_host,
        'port': args.pg_port,
        'database': args.pg_database,
        'user': args.pg_user,
        'password': args.pg_password,
    }

    sync_tool = VulsDatabaseSync(pg_config)

    try:
        sync_tool.connect_postgresql()
        sync_tool.create_schema_if_needed()

        if args.watch:
            logger.info(f"Starting watch mode with {args.watch_interval}s interval...")
            while True:
                try:
                    sync_tool.sync_databases(args.cve_db, args.oval_db, args.gost_db, args.force_full_sync)
                    logger.info(f"Sync completed, waiting {args.watch_interval} seconds...")
                    time.sleep(args.watch_interval)
                except KeyboardInterrupt:
                    logger.info("Watch mode interrupted by user")
                    break
                except Exception as e:
                    logger.error(f"Sync failed: {e}, retrying in {args.watch_interval} seconds...")
                    time.sleep(args.watch_interval)
        else:
            sync_tool.sync_databases(args.cve_db, args.oval_db, args.gost_db, args.force_full_sync)

        logger.info("Synchronization completed successfully!")

    except Exception as e:
        logger.error(f"Synchronization failed: {e}")
        sys.exit(1)

    finally:
        sync_tool.close_connection()


if __name__ == "__main__":
    main()
