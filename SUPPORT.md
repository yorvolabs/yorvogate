# Getting help

- **Documentation:** start with the [README](README.md) and the guides in [docs/](docs/).
- **Bugs:** if something doesn't work as documented, [open an issue](https://github.com/yorvolabs/yorvogate/issues/new/choose) with the steps to reproduce it.
- **Feature requests:** open an issue describing the problem you want to solve.
- **Security issues:** follow the [security policy](SECURITY.md); don't open a public issue.

YorvoGate is young and maintained by a small team, so answers can take a few days.

## Docker Engine

**Certified Docker Engine majors:** 29

Each release says which Docker Engine majors it's certified for (its release notes, and the line above on its branch). A certified major is tested on its newest patch every night, both image stores and a hardened daemon, and was reviewed against that major's API handlers. A Docker that isn't certified may work, but isn't tested or reviewed: run a certified one.

- **A new API version within a certified major:** a YorvoGate release supporting it within **14 days** of the Docker Engine release that introduces it. Until then nothing breaks: YorvoGate advertises the newest API version it serves, so clients (the CLI, Compose, SDKs) ask for that one, which Docker still serves. They just don't get the new version's additions through the gate.
- **A new Docker major** is certified after a review, not by its API version alone: a new major can change what fields and query keys YorvoGate already allows mean, and YorvoGate decides them against that major's handlers. There's no promised time, but a new major is certified before the newest certified one stops receiving security fixes, or the open issue says why not. The review is tracked in a `docker-compat` issue from the day the major is released.
- **Which API versions a build serves:** `yorvogate version --json` (`api.min`, `api.max`).

A nightly job opens a `docker-compat` issue when Docker's newest release has a newer API version, or a new major, or when the conformance suite fails on a certified major's newest patch.
