# Unchecked Low Level Calls

## Description
Low-level calls like call(), callcode(), delegatecall(), or send() fail and are not checked, leading to unexpected behavior.

## Examples
- Unchecked call()/send() return values
- Using delegatecall with user-controllable addresses

## Common Patterns
- Low-level calls without success checks
- Delegatecall to user-controlled addresses

## Detection Strategy
Identify call/delegatecall usage without checking return values or validating target addresses.
