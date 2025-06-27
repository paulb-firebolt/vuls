# Upgrade Notes

## psycopg2 to psycopg3 Migration (2025-06-27)

### Changes Made

1. **Dependencies Updated**
   - Replaced `psycopg2-binary>=2.9.10` with `psycopg[binary]>=3.1.0` in `pyproject.toml`
   - psycopg3 version 3.2.9 was installed

2. **Database URL Updated**
   - Changed database URL dialect from `postgresql://` to `postgresql+psycopg://`
   - Updated in `web-app/app/config.py` (default configuration)
   - Updated in `compose.yml` (all service environment variables)

3. **Compatibility**
   - No code changes required as SQLAlchemy handles the driver abstraction
   - All existing models and database operations remain unchanged
   - Docker configuration remains the same (libpq-dev still required)

### Benefits of psycopg3

- Better performance and memory usage
- Improved async support
- Better type annotations
- More modern codebase
- Active development and support

### Testing

- All models import successfully
- Database engine creation works correctly
- SQLAlchemy integration verified
- No breaking changes to existing functionality

### Rollback Instructions

If rollback is needed:

1. Change `psycopg[binary]>=3.1.0` back to `psycopg2-binary>=2.9.10` in `pyproject.toml`
2. Change all `postgresql+psycopg://` URLs back to `postgresql://`
3. Run `uv sync` to reinstall dependencies
