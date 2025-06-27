"""Utility functions for parsing and working with Vuls configuration files"""

import os
import logging
from typing import Dict, List, Optional
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # Fallback for older Python versions

logger = logging.getLogger(__name__)


class VulsConfigParser:
    """Parser for Vuls configuration files"""

    def __init__(self, config_path: str = "/app/config/config.toml"):
        self.config_path = config_path
        self._config_data = None

    def load_config(self) -> Dict:
        """Load and parse the Vuls configuration file"""
        if self._config_data is not None:
            return self._config_data

        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                logger.warning(f"Vuls config file not found at {self.config_path}")
                return {}

            with open(config_file, 'rb') as f:
                self._config_data = tomllib.load(f)

            logger.info(f"Successfully loaded Vuls config from {self.config_path}")
            return self._config_data

        except Exception as e:
            logger.error(f"Error loading Vuls config from {self.config_path}: {e}")
            return {}

    def get_servers(self) -> Dict[str, Dict]:
        """Extract server configurations from the Vuls config"""
        config = self.load_config()

        # The servers are nested under the 'servers' key in the TOML structure
        return config.get('servers', {})

    def get_host_list(self) -> List[Dict[str, str]]:
        """Get a list of hosts with their configurations for the web application"""
        servers = self.get_servers()
        hosts = []

        for server_name, server_config in servers.items():
            host_info = {
                'name': server_name,
                'hostname': server_config.get('host', server_name),
                'scan_mode': server_config.get('scanMode', ['fast'])[0] if server_config.get('scanMode') else 'fast',
                'description': f"Host from Vuls config: {server_name}",
                'config': server_config
            }
            hosts.append(host_info)

        logger.info(f"Found {len(hosts)} hosts in Vuls config")
        return hosts

    def get_default_config(self) -> Dict:
        """Get the default configuration section"""
        config = self.load_config()
        return config.get('default', {})

    def get_database_config(self) -> Dict:
        """Get database configuration sections"""
        config = self.load_config()
        db_config = {}

        # Extract database configurations
        for section in ['ovalDict', 'gost', 'cveDict']:
            if section in config:
                db_config[section] = config[section]

        return db_config

    def reload_config(self):
        """Force reload of the configuration file"""
        self._config_data = None
        return self.load_config()


def sync_hosts_from_vuls_config(db_session, config_path: str = "/app/config/config.toml") -> Dict[str, int]:
    """
    Synchronize hosts from Vuls config file to the database

    Returns:
        Dict with counts of created, updated, and total hosts
    """
    from ..models.host import Host

    parser = VulsConfigParser(config_path)
    vuls_hosts = parser.get_host_list()

    stats = {
        'total': len(vuls_hosts),
        'created': 0,
        'updated': 0,
        'errors': 0
    }

    for host_info in vuls_hosts:
        try:
            # Check if host already exists (by name or hostname)
            existing_host = db_session.query(Host).filter(
                (Host.name == host_info['name']) |
                (Host.hostname == host_info['hostname'])
            ).first()

            if existing_host:
                # Update existing host
                existing_host.hostname = host_info['hostname']
                existing_host.description = host_info['description']
                existing_host.scan_mode = host_info['scan_mode']
                existing_host.vuls_config = host_info['config']
                stats['updated'] += 1
                logger.info(f"Updated host: {host_info['name']}")
            else:
                # Create new host
                new_host = Host(
                    name=host_info['name'],
                    hostname=host_info['hostname'],
                    description=host_info['description'],
                    scan_mode=host_info['scan_mode'],
                    vuls_config=host_info['config']
                )
                db_session.add(new_host)
                stats['created'] += 1
                logger.info(f"Created host: {host_info['name']}")

        except Exception as e:
            logger.error(f"Error processing host {host_info['name']}: {e}")
            stats['errors'] += 1

    try:
        db_session.commit()
        logger.info(f"Host sync completed: {stats}")
    except Exception as e:
        logger.error(f"Error committing host sync: {e}")
        db_session.rollback()
        stats['errors'] += len(vuls_hosts)
        stats['created'] = 0
        stats['updated'] = 0

    return stats


def get_vuls_config_info(config_path: str = "/app/config/config.toml") -> Dict:
    """Get summary information about the Vuls configuration"""
    parser = VulsConfigParser(config_path)

    return {
        'config_path': config_path,
        'config_exists': Path(config_path).exists(),
        'servers': parser.get_servers(),
        'host_count': len(parser.get_host_list()),
        'default_config': parser.get_default_config(),
        'database_config': parser.get_database_config()
    }
