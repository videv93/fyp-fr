# Access Control

## Description
Failure to use function modifiers or use of tx.origin for authorization, leading to unauthorized access.

## Examples
- Missing function modifiers like onlyOwner
- Using tx.origin for authorization
- Public functions with privileged operations

## Common Patterns
- Sensitive functions without access modifiers
- Use of tx.origin in authorization checks

## Detection Strategy
Identify functions performing privileged operations without proper access control modifiers.
