# syntax=docker/dockerfile:1
#
# Two targets. `dev` runs the Vite dev server behind Caddy for local work;
# `build` produces the static bundle that Caddy serves directly in P7.

# =============================================================================
# dev — Vite dev server, proxied by Caddy on :8080
# =============================================================================
FROM node:24-slim AS dev

ENV NODE_ENV=development

WORKDIR /srv

# Copied separately so a source edit does not invalidate the install layer.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev"]

# =============================================================================
# build — static bundle for production
# =============================================================================
FROM dev AS build

# NODE_ENV=production would make `npm ci` skip devDependencies, and vite itself
# is a devDependency, so it is set only for the build step.
RUN NODE_ENV=production npm run build

# Output lives at /srv/dist. P7 copies it into the Caddy image rather than
# running Node in production at all.
