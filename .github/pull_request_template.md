<!-- Thanks for contributing! For a bigger change, please link the issue where the approach was agreed. -->

## What and why

<!-- What changes, and why. Link the issue, e.g. "Fixes #123". -->

## How it was tested

<!-- The tests you added (a hostile case for every rule), and anything you checked against a real Docker. -->

## Checklist

- [ ] Tests cover the change (a fix has a test that fails without it)
- [ ] `make check` passes in the development container
- [ ] Bodies are read with Docker's own types, unknown fields refused
- [ ] What YorvoGate allows, refuses or reads is documented in `docs/`
