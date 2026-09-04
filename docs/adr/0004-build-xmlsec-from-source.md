# 4. Build xmlsec and lxml from source, together

- **Status:** accepted
- **Date:** 2026-08-10

## Context

SAML signature validation needs `python3-saml`, which needs `xmlsec`, which links
against `libxml2` — the same library `lxml` uses.

The published `lxml` wheel statically bundles its own `libxml2`. A source-built
`xmlsec` links against the system one. Load both into a single process and the
two copies collide.

The failure mode is what makes this worth a record: **it does not fail at install
time.** `pip install` succeeds, imports succeed, and the process segfaults later
when a signature is actually verified. There is no Python traceback, because the
process is gone. Debugging that from scratch, mid-P2, would cost a day.

There is a second reason this needs writing down: the fix looks like a
pessimisation. `--no-binary` makes the Docker build minutes slower, and the
natural instinct of anyone tidying the Dockerfile is to remove it.

## Decision

Build both from source, in one resolution, in the builder stage:

```dockerfile
RUN pip install --no-binary lxml,xmlsec -r requirements-saml.txt
```

Supporting decisions:

- **`requirements-saml.txt` is separate** from `requirements.txt`. It needs
  native headers and cannot install into a Windows venv, so keeping it apart
  means `pip install -r requirements-dev.txt` works on every developer machine.
- **The build asserts the pairing loads.** Both the builder and the runtime stage
  run `python -c "import xmlsec; xmlsec.init()"`. `init()` rather than a bare
  import, because the import alone can succeed on a broken link. The runtime
  stage repeats the check because it has a different set of shared libraries.
- **All Python work happens in Linux containers.** `xmlsec` has no usable Windows
  wheels; native Windows development is not a supported path for this dependency.
- **CI builds the API image on every run.** It is the slowest job and it is the
  one that stops this regressing.

## Consequences

- First Docker build takes several minutes. Layer caching makes subsequent ones
  cheap, and CI caches to the GitHub Actions cache backend.
- The local `.venv` on Windows has no SAML stack. Anything importing
  `xmlsec` must be exercised in the container or in CI, not natively.
- `libxmlsec1-dev` and the compiler live only in the builder stage; the runtime
  image gets the shared libraries only.
- Do not merge the two `pip install` lines in the Dockerfile. `--no-binary` must
  apply to `lxml` and `xmlsec` together and to nothing else.
