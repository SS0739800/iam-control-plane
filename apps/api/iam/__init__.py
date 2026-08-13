"""IAM control plane API.

Package layout:

    config.py        environment-backed settings
    db.py            engine construction and session dependency
    logging_setup.py structured JSON logging
    main.py          FastAPI application factory
    models/          SQLAlchemy declarative models (P1)
    routers/         HTTP surfaces, mounted under /api by main.py
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
