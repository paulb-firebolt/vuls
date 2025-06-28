# Alembic Database Migration Setup

This document explains how Alembic has been retrospectively added to the Vuls Web application to manage database migrations.

## Overview

Alembic is a database migration tool for SQLAlchemy that allows you to manage database schema changes over time. It has been successfully added to this project even though the database already contained data.

## What Was Done

### Initial Setup
- Alembic was already configured in `alembic.ini` with the correct database connection
- The `alembic/` directory was initialized with migration scripts
- The `env.py` file was configured to import your SQLAlchemy models

### Baseline Migration
- Created an initial migration (`20a5eb9f1fd1_initial_migration_baseline_from_.py`) that captures the current database state
- This migration contains only `pass` statements because your models and database schema were already in sync
- The database was "stamped" with this migration version using `alembic stamp head`

### Verification
- Alembic now tracks the current database version in the `alembic_version` table
- Future migrations will be applied incrementally from this baseline

## Usage

### Creating New Migrations

When you modify your SQLAlchemy models, create a new migration:

```bash
cd web-app
docker run --rm -v $(pwd):/app -w /app --network vuls_default \
  -e DATABASE_URL=postgresql+psycopg://vuls:SuperSecretKey@vuls-db:5432/vuls \
  $(docker build -q -f Dockerfile.dev .) \
  bash -c "uv run alembic revision --autogenerate -m 'Description of your changes'"
```

### Applying Migrations

To apply pending migrations to the database:

```bash
# Apply all pending migrations
docker run --rm -v $(pwd):/app -w /app --network vuls_default \
  -e DATABASE_URL=postgresql+psycopg://vuls:SuperSecretKey@vuls-db:5432/vuls \
  $(docker build -q -f Dockerfile.dev .) \
  bash -c "uv run alembic upgrade head"
```

### Rolling Back Migrations

To rollback to a previous migration:

```bash
# Rollback to previous migration
docker run --rm -v $(pwd):/app -w /app --network vuls_default \
  -e DATABASE_URL=postgresql+psycopg://vuls:SuperSecretKey@vuls-db:5432/vuls \
  $(docker build -q -f Dockerfile.dev .) \
  bash -c "uv run alembic downgrade -1"
```

### Checking Migration Status

```bash
# Show current migration version
docker run --rm -v $(pwd):/app -w /app --network vuls_default \
  -e DATABASE_URL=postgresql+psycopg://vuls:SuperSecretKey@vuls-db:5432/vuls \
  $(docker build -q -f Dockerfile.dev .) \
  bash -c "uv run alembic current"
```

## Best Practices

### Always Review Generated Migrations
- Alembic's autogenerate feature is powerful but not perfect
- Always review the generated migration files before applying them
- Check for correct column types, foreign key constraints, and index creation/deletion

### Test Migrations
- Test migrations on a copy of production data
- Ensure both upgrade and downgrade paths work
- Verify that data is preserved correctly

### Version Control
- Always commit migration files to version control
- Never edit applied migration files
- If you need to fix a migration, create a new one

## Current Status

- **Baseline Migration**: `20a5eb9f1fd1_initial_migration_baseline_from_`
- **Database Version**: Up to date with models
- **Alembic Version Table**: `alembic_version` tracks current migration
- **All existing data**: Preserved and unaffected

The database is now fully managed by Alembic and ready for future schema changes.
