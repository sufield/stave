"""Mutation operators for the mutation-testing framework.

Each operator module exposes a `mutations(observation: dict) ->
list[Mutation]` function that produces zero or more candidate
mutations from a safe observation. mutate.py imports operators
from this package and aggregates their output.

A Mutation is a (name, path, before, after, observation) tuple
where `observation` is a deep-copy of the input with the single
property at `path` changed from `before` to `after`. Each
mutation alters exactly one property — compound mutations are
exponential and out of scope for the MVP framework.
"""
