"""Makes the tests a package, so shared helpers can be imported from conftest.

Without this, mypy sees conftest.py under two names — once as a top-level module
and once as tests.conftest — and refuses to check either. pytest is happy with
the directory either way.
"""
