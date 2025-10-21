# Unauthorized Transfer

## Description
The contract allows transferring tokens from an address different from the message sender without checking the approval of the address owner.

## Examples
- Direct transfer of tokens from arbitrary addresses
- Lack of require statement checking msg.sender approval

## Common Patterns
- Transfer function without allowance checks
- No verifyEIP712 or signature-based validation

## Detection Strategy
Identify transfer functions that do not verify allowance or approval mechanisms.
