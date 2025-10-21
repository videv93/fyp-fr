# Price Manipulation

## Description
Liquidity token value/price can be manipulated to cause flashloan attacks.

## Examples
- Using AMM reserves to determine token price
- Manipulation of liquidity pool balances

## Common Patterns
- Usage of getPrice, getRate, totalSupply, balanceOf in liquidity calculations
- AMM-based calculations without external verification

## Detection Strategy
Identify price calculations based on AMM reserves, balanceOf, or totalSupply without external validation.
