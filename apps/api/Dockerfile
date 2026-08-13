# syntax=docker/dockerfile:1
#
# Two stages. The builder compiles xmlsec against libxml2 and keeps the
# toolchain out of the runtime image; the runtime stage ships only the venv and
# the shared libraries it links against.

# =============================================================================
# Stage 1 — build the virtualenv, including the xmlsec/lxml pair
# =============================================================================
FROM python:3.12-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# A compiler and headers, only needed to build xmlsec and lxml from source.
#
# libxslt1-dev looks unnecessary since nothing here uses XSLT, but lxml links
# against it. Leave it out and the code compiles fine and then the linking step
# fails with nothing more helpful than "ld returned 1 exit status".
RUN apt-get update && apt-get install --no-install-recommends -y \
        build-essential \
        pkg-config \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY requirements.txt requirements-saml.txt ./

RUN pip install -r requirements.txt

# ---------------------------------------------------------------------------
# READ THIS BEFORE CHANGING IT. The prebuilt lxml package comes with its own copy
# of libxml2, while xmlsec built from source uses the system one. Load both into
# one process and it CRASHES while running, not while installing. No Python error,
# no stack trace, just a dead process. Horrible to debug.
#
# Both have to be built from source together, with --no-binary. Don't merge this
# into the line above to save time.
# See docs/adr/0004-build-xmlsec-from-source.md.
# ---------------------------------------------------------------------------
RUN pip install --no-binary lxml,xmlsec -r requirements-saml.txt

# Check they actually work together now, while we're building, instead of finding
# out on the first login in P2. It calls init() rather than just importing,
# because the import can succeed even when the linking is broken.
RUN python -c "import lxml.etree; import xmlsec; xmlsec.init(); print('xmlsec ok')"

# =============================================================================
# Stage 2 — runtime
# =============================================================================
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:$PATH"

# Just the libraries needed to run, no compiler and no headers. libxslt1.1 is the
# runtime half of libxslt1-dev above. Leave it out and instead of a build error you
# get an ImportError the first time the app starts.
RUN apt-get update && apt-get install --no-install-recommends -y \
        libxml2 \
        libxslt1.1 \
        libxmlsec1 \
        libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin iam

COPY --from=builder /opt/venv /opt/venv

WORKDIR /srv
COPY --chown=iam:iam . .

USER iam

# Stamped by CI from the commit being built; surfaced on /api/health.
ARG GIT_SHA=dev
ENV GIT_SHA=${GIT_SHA}

EXPOSE 8000

# Check again here. This stage has a different set of libraries than the builder,
# so a missing one would otherwise only turn up during P2.
RUN python -c "import xmlsec; xmlsec.init(); print('xmlsec ok in runtime')"

# compose overrides this with --reload for local development.
CMD ["uvicorn", "iam.main:app", "--host", "0.0.0.0", "--port", "8000"]
