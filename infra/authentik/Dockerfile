# authentik, with our SAML application and SCIM provider baked in.
#
# The only reason this file exists is that compose mounts the blueprints from the
# host and Fly has no host to mount from. Same blueprints, same official image —
# they just have to be inside it.
#
# Nothing else is changed. authentik is somebody else's software and this is not the
# place to start patching it.

ARG AUTHENTIK_TAG=latest
FROM ghcr.io/goauthentik/server:${AUTHENTIK_TAG}

# The worker applies these; the server reads them too, which is why compose mounts
# them into both. Here there is one image, so both process groups get them by
# construction.
COPY blueprints/ /blueprints/custom/
