# syntax=docker/dockerfile:1
#
# The production console: the API and the built frontend in one image, one process.
# See docs/adr/0008-one-server-serves-both-halves-in-production.md.
#
# This lives at the repository root rather than under apps/ because it needs both
# apps/web and apps/api in its build context. apps/api/Dockerfile stays as it is —
# it is what compose builds for local work, and what CI builds to prove the xmlsec
# pairing still links.
#
#   docker build -t iam-console .
#   fly deploy                        (reads fly.toml, which points here)

# =============================================================================
# Stage 1 — the frontend bundle
# =============================================================================
FROM node:24-slim AS web

WORKDIR /web

# Copied separately so editing a component does not reinstall node_modules.
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci

COPY apps/web/ ./

# NODE_ENV is set only for the build step. Setting it earlier would make `npm ci`
# skip devDependencies, and vite itself is one of those.
RUN NODE_ENV=production npm run build

# =============================================================================
# Stage 2 — the virtualenv, including the xmlsec/lxml pair
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
COPY apps/api/requirements.txt apps/api/requirements-saml.txt ./

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

# Check they actually work together now, while we're building, rather than on the
# first login. init() rather than a bare import, because the import can succeed
# even when the linking is broken.
RUN python -c "import lxml.etree; import xmlsec; xmlsec.init(); print('xmlsec ok')"

# =============================================================================
# Stage 3 — runtime
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
COPY --chown=iam:iam apps/api/ ./

# The bundle, and the setting that makes the app serve it. Both here rather than in
# fly.toml: an image that contains a frontend and does not serve it is a confusing
# thing to debug, so the two travel together.
COPY --from=web --chown=iam:iam /web/dist /srv/static
ENV STATIC_DIR=/srv/static

# Production means production. app_env is the switch behind the placeholder-secret
# check, the refusal to run the development actor, and the address rules for
# outbound provisioning. Set here so a forgotten fly secret cannot leave a
# production machine running in development mode.
ENV APP_ENV=production

USER iam

# Stamped by CI from the commit being built; surfaced on /api/health.
ARG GIT_SHA=dev
ENV GIT_SHA=${GIT_SHA}

EXPOSE 8000

# Check again here. This stage has a different set of shared libraries than the
# builder, so a missing one would otherwise only turn up on the first login.
RUN python -c "import xmlsec; xmlsec.init(); print('xmlsec ok in runtime')"

# And check the bundle arrived. A blank site in front of a healthy API is the
# failure this image is most likely to ship, and the app refuses to start without
# an index.html — so failing here means finding out at build time instead.
RUN test -f /srv/static/index.html || (echo "the frontend bundle is missing" && exit 1)

# No --reload, no --workers. One process per machine; Fly scales by adding
# machines, and two uvicorn workers in one container would double the database
# pool without doubling anything useful.
CMD ["uvicorn", "iam.main:app", "--host", "0.0.0.0", "--port", "8000"]
