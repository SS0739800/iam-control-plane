# 1. Record architecture decisions

- **Status:** accepted
- **Date:** 2026-08-10

## Context

This project makes a number of choices that look wrong without their reasoning
attached — not using the auth system that ships with our own database, refusing
to add a CORS layer, compiling a dependency from source when a wheel exists. Six
weeks later those look like oversights, and somebody tries to "fix" them.

There is also a second audience. This is a portfolio project, and an engineer
reviewing it will read a short decision record before they read source. "Here is
what I chose and what I gave up" is a clearer signal than any amount of code.

## Decision

Every decision that constrains future work gets a numbered file in `docs/adr/`,
written when the decision is made rather than reconstructed later.

An ADR is warranted when the decision is hard to reverse, when a reasonable
engineer would pick differently, or when the obvious-looking alternative is a
trap. Routine choices — a library version, a file layout — do not need one.

Records are immutable. A decision that changes gets a new ADR that supersedes
the old one; the original stays as written so the reasoning at the time survives.

## Consequences

- Code review can point at a rationale rather than relitigating it.
- Anything with a `# do not simplify this` comment should carry an ADR reference,
  and does.
- Roughly fifteen minutes of writing per decision.
