"""All check modules, in the order the report lists them."""
from . import (password_policy, lockout, enumeration, storage,
               session, mfa, password_reset)

ALL_CHECKS = [password_policy, lockout, enumeration, storage,
              session, mfa, password_reset]
