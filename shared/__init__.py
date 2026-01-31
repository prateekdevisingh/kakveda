"""Root import aliases.

The codebase primarily lives under `services/`, but tests and some execution paths
use `pythonpath=.`. This small package provides stable imports like `shared.*`
that forward to `services.shared.*`.
"""
