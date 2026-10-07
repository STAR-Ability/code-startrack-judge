# Architecture decision records

ADRs preserve why important architecture exists. They supplement the [versioned contracts](../contracts/README.md); they cannot override them or resolve an open contract question by inference.

Use sequential four-digit IDs and the [template](template.md). Status is Proposed, Accepted, Superseded or Rejected. A superseding ADR links both ways and leaves the historical decision intact. Record reasons, operational consequences, meaningful alternatives and conditions for revisiting. A library syntax preference or trivial coding choice does not need an ADR.

These initial records are **Accepted as engineering direction already constrained by the supplied contracts**. Accepted status is not proof that code exists or deployment has passed validation. Their open questions and verification gates remain binding.

| ID | Decision | Status |
|---|---|---|
| [0001](0001-service-ownership.md) | Preserve judge/backend/algorithm ownership boundaries | Accepted |
| [0002](0002-persistent-asynchronous-judging.md) | PostgreSQL asynchronous facts and transactional callback outbox | Accepted |
| [0003](0003-immutable-problem-history.md) | Immutable problem/package history and frozen execution context | Accepted |
| [0004](0004-explicit-package-compatibility.md) | Preserve originals and use an explicit problem-package adapter | Accepted |
| [0005](0005-mature-linux-sandbox.md) | Pinned upstream sandbox with Linux security validation | Accepted |
