<!-- Thanks for contributing! For a bigger change, please link the issue where the approach was agreed.
The title is the squashed commit's subject: imperative, at most 72 characters, with references at the
end in parentheses, e.g. "Bound image loads with a shared spool (0.4-d1)". This description is its
body. -->

## Why

<!-- The problem, and why this is the way to solve it. -->

## What changes

<!-- What behaves differently, as bullets, rather than which files changed. -->

## Tested

<!-- What ran: the tests you added (a hostile case for every rule), the checks, anything you checked
against a real Docker. And what didn't, with why. -->

## Refs

<!-- The issue, roadmap item or finding, e.g. "Fixes #123", "0.4-d2", "RT-04". -->

## Checklist

- [ ] Tests cover the change (a fix has a test that fails without it)
- [ ] `make check` passes in the development container
- [ ] Bodies are read with Docker's own types, unknown fields refused
- [ ] What YorvoGate allows, refuses or reads is documented in `docs/`
