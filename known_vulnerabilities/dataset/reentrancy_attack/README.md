# Reentrancy Attack

## Description
Reentrant function calls make a contract behave in an unexpected way by allowing repeated entry before previous invocations complete.

## Examples
- External calls before state changes
- Using .call.value() without the checks-effects-interactions pattern

## Common Patterns
- Low-level calls (call/value) followed by state changes
- Recursive calls to functions modifying state

## Detection Strategy
Check for external calls followed by state changes. Verify the use of the checks-effects-interactions pattern.
