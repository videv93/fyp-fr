# Arithmetic

## Description
Integer overflows or underflows due to unbound arithmetic operations.

## Examples
- Unchecked mathematical operations
- Using SafeMath library incorrectly

## Common Patterns
- Arithmetic operations without overflow checks
- Use of deprecated SafeMath patterns

## Detection Strategy
Check for mathematical operations without SafeMath or Solidity 0.8+ checked math.
