<!-- Thanks for contributing! For a bigger change, please link the issue where the approach was agreed.
The title is the squashed commit's subject: imperative, at most 72 characters, saying what the code
does, e.g. "Bound image loads with a shared spool". This description is its body. Both are public:
nothing internal (plan or finding codes, who reviewed or decided) in either. -->

## Why

<!-- The problem, and why this is the way to solve it. -->

## What changes

<!-- What behaves differently, as bullets, rather than which files changed. -->

## Tested

<!-- What ran: the tests you added (a hostile case for every rule), the checks, anything you checked
against a real Docker. And what didn't, with why. -->

## Refs

<!-- What a reader can open: an issue or pull request ("Fixes #123"), a published advisory, an RFC,
upstream docs. Leave it out when there's none. -->

## Checklist

- [ ] Tests cover the change (a fix has a test that fails without it)
- [ ] `make check` passes in the development container
- [ ] Bodies are read with Docker's own types, unknown fields refused
- [ ] What YorvoGate allows, refuses or reads is documented in `docs/`
