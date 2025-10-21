# Bad Randomness

## Description
Malicious miners can bias the outcome of pseudo-random number generation.

## Examples
- Using block.timestamp or blockhash for randomness
- Relying on miner-controllable variables

## Common Patterns
- Use of block.timestamp or blockhash in randomness generation
- Predictable random number sources

## Detection Strategy
Check for reliance on block variables or other miner-controllable inputs for randomness.
