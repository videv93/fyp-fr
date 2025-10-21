# First Deposit

## Description
First depositor can break minting of shares or drain the liquidity of all users.

## Examples
- No dilution mechanism for the first deposit
- First depositor sets the total supply arbitrarily

## Common Patterns
- totalSupply() == 0 check without proper distribution
- Minting all shares to the first depositor

## Detection Strategy
Identify first deposit conditions without proper liquidity dilution mechanisms.
