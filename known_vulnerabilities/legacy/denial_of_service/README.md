# Denial Of Service

## Description
The contract is overwhelmed with time-consuming computations, causing it to become unresponsive.

## Examples
- Unbounded loops or expensive operations
- External calls that can fail repeatedly

## Common Patterns
- Loops without gas limits
- External calls in loops

## Detection Strategy
Identify loops or external calls that could consume excessive gas or fail repeatedly.
