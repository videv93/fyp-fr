# Front Running

## Description
Two dependent transactions that invoke the same contract are included in one block, allowing malicious actors to exploit the order of execution.

## Examples
- Transactions with predictable outcomes
- Unprotected state changes

## Common Patterns
- Predictable transaction ordering
- Lack of commit-reveal schemes

## Detection Strategy
Identify transactions with predictable outcomes or unprotected state changes.
