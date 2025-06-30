#!/usr/bin/env python3
"""
Apply database migrations for the Ubuntu OVAL integration
"""

import sys
import os
import subprocess

def apply_migrations():
    """Apply Alembic migrations"""
    try:
        print("Applying database migrations...")

        # Change to web-app directory
        web_app_dir = os.path.join(os.path.dirname(__file__), 'web-app')

        # Run alembic upgrade
        result = subprocess.run(
            ['uv', 'run', 'alembic', 'upgrade', 'head'],
            cwd=web_app_dir,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("✅ Database migrations applied successfully!")
            print(result.stdout)
            return True
        else:
            print("❌ Migration failed:")
            print(result.stderr)
            return False

    except Exception as e:
        print(f"❌ Error applying migrations: {e}")
        return False

def main():
    """Main function"""
    print("Ubuntu OVAL Database Migration")
    print("=" * 40)

    success = apply_migrations()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
