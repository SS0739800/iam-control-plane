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

# Headers and a compiler, needed only to build xmlsec and lxml from source.
#
# libxslt1-dev is not optional even though nothing here obviously wants XSLT:
# lxml links etree against -lxslt and -lexslt, so without it the compile succeeds
# and the LINK fails with a bare "ld returned 1 exit status".
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
# THE TRAP. A prebuilt lxml wheel bundles its own libxml2; a source-built
# xmlsec links against the system one. Loading both into one process then
# SEGFAULTS AT RUNTIME rather than failing at install time, which is a
# miserable thing to debug from a stack trace that does not exist.
#
# Both must be built from source, in one resolution, with --no-binary. Do not
# "optimise" this into the layer above.
# See docs/adr/0004-build-xmlsec-from-source.md.
# ---------------------------------------------------------------------------
RUN pip install --no-binary lxml,xmlsec -r requirements-saml.txt

# Prove the pairing loads now, at build time, rather than on the first SAML
# request in P2. xmlsec.init() is the real smoke test — the import alone can
# succeed on a broken link.
RUN python -c "import lxml.etree; import xmlsec; xmlsec.init(); print('xmlsec ok')"

# =============================================================================
# Stage 2 — runtime
# =============================================================================
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:$PATH"

# Runtime shared libraries only — no -dev packages, no compiler. libxslt1.1 is
# the runtime counterpart of libxslt1-dev above; lxml's etree.so is linked
# against it, so omitting it turns the build-time link error into an ImportError.
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

# Re-verify in the runtime image: this stage has different shared libraries than
# the builder, so a missing runtime package would otherwise surface in P2.
RUN python -c "import xmlsec; xmlsec.init(); print('xmlsec ok in runtime')"

# compose overrides this with --reload for local development.
CMD ["uvicorn", "iam.main:app", "--host", "0.0.0.0", "--port", "8000"]
