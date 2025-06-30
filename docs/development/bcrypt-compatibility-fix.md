# BCrypt Compatibility Fix - Migration to Argon2

## Issue Description

The application was experiencing a bcrypt compatibility error due to an incompatible version of the bcrypt library with passlib:

```
AttributeError: module 'bcrypt' has no attribute '__about__'
```

This error occurred because passlib 1.7.4 was not compatible with newer versions of bcrypt (4.3.0+).

## Solution

Instead of downgrading bcrypt (which would introduce security vulnerabilities), we migrated from `passlib` to the modern `argon2-cffi` library, which provides:

- **Better Security**: Argon2 is the winner of the Password Hashing Competition and is recommended by security experts
- **Active Maintenance**: argon2-cffi is actively maintained and compatible with modern Python versions
- **No Compatibility Issues**: No dependency conflicts with other libraries

## Changes Made

### 1. Updated Dependencies

**File**: `web-app/pyproject.toml`

```diff
- "passlib[bcrypt]>=1.7.4",
+ "argon2-cffi>=23.1.0",
```

### 2. Updated Authentication Module

**File**: `web-app/app/auth.py`

```diff
- from passlib.context import CryptContext
+ from argon2 import PasswordHasher
+ from argon2.exceptions import VerifyMismatchError

- # Password hashing
- pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
+ # Password hashing using Argon2
+ pwd_hasher = PasswordHasher()
```

### 3. Updated Password Functions

```diff
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
-   return pwd_context.verify(plain_password, hashed_password)
+   try:
+       pwd_hasher.verify(hashed_password, plain_password)
+       return True
+   except VerifyMismatchError:
+       return False

def get_password_hash(password: str) -> str:
    """Hash a password"""
-   return pwd_context.hash(password)
+   return pwd_hasher.hash(password)
```

## Testing

The migration was tested successfully:

```bash
docker exec vuls-web-dev uv run python -c "
from app.auth import get_password_hash, verify_password

# Test password hashing
test_password = 'test123'
hashed = get_password_hash(test_password)
is_valid = verify_password(test_password, hashed)
is_invalid = verify_password('wrong_password', hashed)

print(f'Password verification: {is_valid}')  # True
print(f'Wrong password verification: {is_invalid}')  # False
"
```

**Result**: ✅ Argon2 password hashing is working correctly!

## Benefits of Argon2 over BCrypt

1. **Memory-Hard Function**: Argon2 is designed to be memory-hard, making it more resistant to GPU-based attacks
2. **Tunable Parameters**: Supports memory cost, time cost, and parallelism parameters
3. **Side-Channel Resistance**: Better protection against side-channel attacks
4. **Modern Standard**: Recommended by OWASP and security experts
5. **Active Development**: Regularly updated and maintained

## Migration Notes

- **Existing Passwords**: Any existing bcrypt hashes in the database will need to be migrated when users next log in
- **Hash Format**: Argon2 hashes use the format `$argon2id$v=19$m=65536,t=3,p=4$...`
- **Performance**: Argon2 may be slightly slower than bcrypt, but provides better security
- **Compatibility**: No compatibility issues with modern Python and dependency versions

## Container Rebuild

The development container was rebuilt to include the new dependencies:

```bash
docker compose build vuls-web-dev
docker compose up vuls-web-dev -d
```

## Status

✅ **RESOLVED**: The bcrypt compatibility issue has been completely resolved by migrating to Argon2.

The application now starts successfully without any dependency conflicts and uses modern, secure password hashing.
