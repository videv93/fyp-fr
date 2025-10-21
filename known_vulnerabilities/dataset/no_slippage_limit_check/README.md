# No Slippage Limit Check

## Description
No slippage limit check was performed to prevent sandwich attacks.

## Examples
- Missing minReceived checks in swaps
- Lack of slip limit in liquidity operations

## Common Patterns
- Unbounded price calculations in swaps
- Liquidity additions without limit checks

## Detection Strategy
Identify liquidity-related operations without slippage limit or minimum value checks.
