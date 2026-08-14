# Testing Guide

This guide describes a testing model that can be adapted to repositories that
combine Python, shell scripts, configuration management, command-line tools,
and container-backed integration tests. The main sections are intentionally
repository-neutral. The final appendix records how this repository currently
implements the model and which dependency versions it constrains.

## Testing Model

Use the smallest test layer that can establish the behavior being claimed.
Fast, deterministic tests should form the default suite. Tests that download
artifacts, start services, modify network namespaces, or require a container
engine should normally be separate, opt-in integration lanes.

A practical split is:

| Layer | Typical driver | Purpose | Default suite |
|---|---|---|---|
| Source contract | pytest | Check defaults, task ordering, schemas, and safety invariants | Yes |
| Render or command behavior | pytest plus subprocesses | Render configuration, invoke helpers, and check success and failure paths | Yes |
| Disposable system integration | Bash plus a container engine | Exercise packages, systemd, networking, native validators, and idempotency | Usually no |
| Environment acceptance | An operator workflow or dedicated harness | Prove behavior on a realistic disposable or staging environment | No |

The layers are not interchangeable. A source assertion does not prove runtime
behavior, and a successful syntax check does not prove convergence or
idempotency. Documentation should state what each test proves and what remains
outside its scope.

## Choosing Python Or Bash

Choose Python and pytest when tests benefit from:

- Fixtures and automatic temporary-directory cleanup.
- Parametrized boundary and invalid-input cases.
- Structured parsing of JSON, YAML, or generated files.
- Precise assertions and readable failure diagnostics.
- Mocking or controlled replacement of external commands.
- Parallel execution with worker-local isolation.
- Testing a command-line program through a subprocess while retaining Python
  for setup and assertions.

Choose Bash when the scenario is fundamentally a shell-level integration:

- Starting and stopping disposable containers or services.
- Exercising systemd, package managers, networking, signals, or process state.
- Composing several native command-line tools where Python would only add a
  second orchestration layer.
- Verifying an image, package, or service in an environment close to its target
  operating system.

Do not use Bash merely because the program under test is a shell script. A
shell program can often be tested more safely from pytest, with isolated input,
captured output, explicit timeouts, and parametrized failure cases. Conversely,
do not rewrite a clear container lifecycle test in Python only to make every
test use the same language.

## Python Test Implementation

### Configure Pytest Centrally

Keep collection and safety settings in `pyproject.toml` or another supported
pytest configuration file. A typical configuration defines:

- A single test root such as `tests/python`.
- A predictable file pattern such as `test_*.py`.
- A minimum supported pytest version.
- Strict configuration and strict marker validation.
- Registered markers for special groups, especially serial tests.
- Warning behavior that does not silently hide new warnings.
- Required plugins when the suite depends on their command-line options.
- Strict handling of unexpected passes for tests marked `xfail`.

For example:

```toml
[tool.pytest.ini_options]
testpaths = ["tests/python"]
python_files = ["test_*.py"]
addopts = [
  "--strict-config",
  "--strict-markers",
  "--tb=short",
  "-ra",
]
filterwarnings = ["default"]
markers = [
  "serial: tests that must not run concurrently",
]
xfail_strict = true
```

If parallel execution is required, declare and pin the parallelization plugin
as a test dependency. Requiring the plugin in pytest configuration prevents a
missing plugin from silently changing the test command's meaning.

### Isolate Every Test

Shared fixtures should establish a known environment rather than inheriting a
developer's workstation state. Common fixtures include:

- `repo_root`: resolves and validates the repository root.
- `tmp_path`: provides invocation-local temporary state.
- A worker name: distinguishes pytest-xdist workers.
- A worker-local test directory: prevents parallel tests from sharing files.
- A sanitized environment: sets temporary `HOME`, cache, configuration, and
  tool-specific temporary directories.
- A command runner: invokes subprocesses from a known directory with the
  sanitized environment.

Only inherit environment variables that tests genuinely require, such as
`PATH` or certificate trust paths. Do not inherit credentials, SSH agent
sockets, production configuration, or unrelated tool settings by default.

Set temporary locations explicitly for tools that otherwise write into the
source tree or the user's home directory. For Python and pytest, disabling
bytecode and cache writes is useful when tests run against a read-only source
mount.

### Use A Safe Subprocess Harness

Command tests should invoke argument arrays, not shell command strings. A
reusable subprocess harness should:

- Record the argument vector, exit status, standard output, standard error, and
  duration.
- Set `stdin` to a non-interactive source so a test cannot wait for input.
- Apply an explicit timeout.
- Start the child in its own process session.
- On timeout, terminate the owned process group and escalate if necessary.
- Preserve partial output in timeout diagnostics.
- Provide explicit success and failure assertions.
- Redact tokens, temporary credentials, or other sensitive values from failure
  messages.

Starting a separate process session is important when a tested helper creates
children. Killing only the direct process can leave descendants running and
make later tests flaky. Cleanup must target only the process group owned by the
test so unrelated processes are not affected.

### Test Observable Contracts

Useful Python test patterns include:

- **Source contracts:** verify safety defaults, required task ordering, or the
  absence of prohibited configuration.
- **Rendered output:** run the real renderer against a fixture, then assert the
  generated configuration, unit, or script content.
- **Command behavior:** invoke the real helper and assert exit status, output,
  file changes, and permissions.
- **Negative behavior:** prove invalid, unsafe, incomplete, or conflicting
  inputs fail before mutation.
- **Boundary behavior:** parametrize minimum, maximum, empty, malformed, and
  type-coercion cases.
- **Idempotency:** run convergence twice and require the second run to report no
  changes.
- **Candidate preservation:** prove failed validation does not replace the last
  valid configuration.
- **Mutation sensitivity:** deliberately alter a fixture or source sample and
  prove that a safety scanner or assertion detects the change.

Prefer semantic parsing over raw text matching when a stable parser exists.
Text assertions remain appropriate for shell fragments, ordering contracts, or
security-sensitive strings where exact output is itself the interface.

### Test External Configuration Tools

When testing tools such as Ansible, wrap the real executable in a small Python
helper that builds an argument list and delegates to the subprocess harness.
The helper can consistently support:

- An inventory path.
- Extra variables encoded as structured data.
- Limits or selectors.
- Syntax-check mode.
- Environment additions.
- A scenario-appropriate timeout.

Use small public fixtures with synthetic addresses and values. A render fixture
can redirect generated files into a temporary directory, allowing the role or
template to run without changing the test container or contacting managed
hosts.

### Separate Parallel And Serial Tests

Parallel execution is safe only when every test owns its files, ports,
processes, and resource names. Tests that coordinate child-process timing,
global locks, fixed ports, or shared external state should carry a registered
`serial` marker.

A parallel test target can run two disjoint selections:

```bash
python -m pytest -n "$TEST_WORKERS" -m "not serial"
python -m pytest -n 0 -m serial
```

The authoritative target should still run the complete suite serially unless
the project has established parallel execution as an equivalent merge oracle:

```bash
python -m pytest -n 0
```

The two parallel-target selections must be disjoint and together collect the
same tests as the authoritative suite. Parallel execution is a feedback
optimization, not evidence of additional coverage.

## Bash Integration Test Implementation

A Bash integration test should begin with strict error handling and define all
resources explicitly:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTAINER="example-integration-test-$$"

cleanup() {
  podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}
```

A robust scenario normally follows this sequence:

1. Check required commands and fixture inputs.
2. Allocate unique container, network, volume, and temporary-file names.
3. Install an `EXIT` trap before creating resources.
4. Start a disposable target environment.
5. Wait for readiness with a bounded retry loop.
6. Apply or invoke the real implementation.
7. Assert the exact expected state.
8. Exercise relevant rejection and failure paths.
9. Run convergence again and assert idempotency when applicable.
10. Let the trap remove all resources on success, failure, or interruption.

Avoid assertions that only check whether a command returned zero. Inspect the
resulting service state, generated configuration, file mode, image identity,
network behavior, or native validator output. For a negative case, fail the
test if the unsafe command unexpectedly succeeds.

Use immutable image digests for artifacts whose exact identity matters. If a
mutable operating-system tag is intentionally used, document that the test
tracks the current image published under that tag rather than a byte-for-byte
reproducible root filesystem.

Container-backed Bash tests may need the host's container engine even when the
normal test container deliberately hides its socket. One safe pattern is to
run the lifecycle harness on the host while invoking render or configuration
commands through the development-container wrapper. Keep this lane opt-in and
make the trust boundary explicit.

## Running Tests

Expose stable project commands through a Makefile or equivalent task runner.
Developers and CI should call those commands instead of duplicating lower-level
pytest, lint, or container options.

The following is an illustrative template for a repository adopting this
model, not a list of targets implemented by every repository:

```make
.PHONY: test test-parallel test-integration verify

TEST_RUNNER ?= ./scripts/in-container
PYTEST_ARGS ?=

test:
	$(TEST_RUNNER) python -m pytest -n 0 $(PYTEST_ARGS)

test-parallel:
	$(TEST_RUNNER) python -m pytest -n "$(TEST_WORKERS)" -m "not serial"
	$(TEST_RUNNER) python -m pytest -n 0 -m serial

test-integration:
	bash tests/integration/test-example.sh

verify: lint test
```

Typical developer commands are:

```bash
# Authoritative complete suite
make test

# Faster supplemental feedback
make test-parallel TEST_WORKERS=4

# One file
make test PYTEST_ARGS="-q tests/python/test_example.py"

# One test
make test PYTEST_ARGS="-q tests/python/test_example.py::test_rejects_invalid_input"

# Full local merge check
make verify

# Explicit system integration
make test-integration
```

Focused commands should use the same development image and sanitized
environment as the full suite. Running focused tests against a different host
Python installation can conceal dependency or operating-system differences.

## Development Containers

A development container gives local development and CI the same Python,
linters, shell utilities, and external tools without installing project
packages on the host.

### Build The Toolchain Image

The development `Containerfile` should:

- Start from an explicitly versioned base image.
- Use an immutable digest when reproducibility and supply-chain review require
  exact image identity.
- Install only required operating-system tools.
- Install development and test dependencies from separate manifests.
- Install external collections or plugins from versioned manifests.
- Set a stable working directory.

Separating development dependencies from direct test dependencies makes the
pinning policy visible. For example, linters may use a supported minor-version
range while the test runner and plugins are exact pins.

### Use Separate Development And Test Profiles

An interactive development profile can mount the repository read-write and,
when explicitly needed, selected private inputs read-only. A test profile
should be narrower:

- Mount the repository read-only.
- Overlay a dedicated writable scratch path.
- Use an invocation-local temporary home directory.
- Run as the invoking user's UID and GID.
- Disable writes such as Python bytecode and pytest caches.
- Do not mount private configuration, SSH files, secret stores, SSH agents, or
  container-engine sockets.
- Remove temporary state and preserve the wrapped command's exit status.
- Forward interruption signals and return conventional interruption statuses.

The profile is a security boundary and should have its own executable tests.
Those tests should verify mount modes, identity, scratch execution, forbidden
paths, exit-code propagation, signal handling, and cleanup.

### Rebuild Deliberately

A wrapper may build the image automatically when it does not exist, but it
cannot necessarily detect a stale existing image. Document which files require
a rebuild, normally:

- The development `Containerfile`.
- Development dependency manifests.
- Test dependency manifests.
- External collection or plugin manifests.

Provide an explicit command such as `make deps` or `make container-build` and
use it after any of those files change.

## Version Pinning Strategy

Not every dependency needs the same pinning policy. State the policy for each
category instead of describing all constraints as "pinned."

| Dependency type | Recommended constraint | Reason |
|---|---|---|
| Language base image | Version tag plus digest | Fixes interpreter and base filesystem identity |
| Test runner and required plugins | Exact version | Prevents collection and execution semantics from drifting independently |
| Direct test libraries | Exact version | Keeps parsing and assertion behavior reproducible |
| Development tools | Exact version or bounded minor range | Allows either full reproducibility or controlled compatible updates |
| External collections/plugins | Exact version | Avoids changes in generated or managed behavior |
| Service images under qualification | Immutable digest plus asserted version | Proves the tested artifact is the approved artifact |
| Disposable OS fixture | Digest when exact identity matters; documented tag otherwise | Balances reproducibility with tracking OS updates |
| OS packages installed during image build | Exact package versions or snapshot repository when required | A base digest alone does not freeze later package resolution |

An exact application version string is weaker than an image digest: a registry
tag can be republished. A digest is also not sufficient on its own when the
test requires a particular architecture or runtime identity, so inspect and
assert those properties where relevant.

Bounded ranges such as `>=X.Y,<X+1.0` are compatibility constraints, not exact
pins. They permit a newly resolved version after an image rebuild. This can be
appropriate for development tools, but it should not be presented as a fully
reproducible lock.

Toolchain verification should print effective versions and run the package
manager's dependency consistency check. This records what was actually tested
and catches an image whose installed packages no longer satisfy their declared
requirements.

## Adopting This Model In Another Repository

1. Inventory the current unit, command, integration, and acceptance tests.
2. Define what the default suite must prove and which expensive scenarios are
   opt-in.
3. Add central pytest configuration with strict markers and deterministic
   collection.
4. Add isolated temporary environment and subprocess fixtures.
5. Move deterministic shell-program tests into pytest where fixtures,
   parametrization, and timeout handling improve them.
6. Keep genuine service and container lifecycle scenarios as strict Bash
   integration tests with reliable cleanup.
7. Add stable Make targets for serial, parallel, integration, and aggregate
   verification lanes.
8. Build all tooling into a version-controlled development image.
9. Add a sanitized test-container profile and executable checks for its
   boundary.
10. Record exact pins, bounded ranges, mutable tags, and unpinned OS packages
    separately.
11. Configure CI to call the same authoritative targets used locally.
12. Document the limits of synthetic tests and retain explicit acceptance
    procedures for behavior that requires a real target environment.

## This Repository

This appendix records the current implementation. It is intentionally separate
from the reusable model above so the guide remains adaptable to other
repositories.

### Test Layout And Commands

- Python tests are collected from `tests/python/test_*.py`.
- Shared fixtures and the subprocess harness are in
  `tests/python/conftest.py`.
- Ansible invocation helpers are in `tests/python/ansible_test_helpers.py`.
- Synthetic Ansible fixtures are under `tests/fixtures/`.
- Opt-in Podman and system integration tests are under `tests/integration/`.
- `make test` runs the complete pytest suite serially and is authoritative.
- `make test-parallel` runs non-serial tests with two workers by default, then
  tests marked `serial` without xdist workers.
- `make verify` runs toolchain, test-profile, wrapper, YAML, Ansible lint, and
  authoritative serial pytest checks.
- `make verify-parallel` substitutes the supplemental parallel pytest lane.
- Integration scripts have dedicated `make test-*` targets and are outside the
  default verification lane.

All default test and lint targets use `scripts/in-container` with the sanitized
`test` profile. The source tree is mounted read-only at `/workspace`, while an
invocation-local directory is mounted read-write at `/workspace/.ansible`.
Private configuration, SSH material, the external secret store, the SSH agent,
and Podman sockets are not exposed.

Focused Python tests should also use the wrapper:

```bash
./scripts/in-container python -m pytest -q tests/python/test_harness.py
```

Run `make deps` after changing `Containerfile.dev`,
`requirements-dev.txt`, `requirements-test.txt`, or `requirements.yml`. The
wrapper builds a missing image but does not detect that an existing image is
stale.

### Current Version Constraints

The following values were read from the repository's dependency manifests and
development container definition:

| Component | Constraint | Pin type |
|---|---|---|
| Python base image | `python:3.14.7-slim-trixie` with SHA-256 digest | Exact image identity |
| pytest | `9.1.1` | Exact |
| pytest-xdist | `3.8.0` | Exact |
| PyYAML | `6.0.3` | Exact |
| ansible-core | `>=2.20,<2.21` | Bounded compatible range |
| ansible-lint | `>=26.4,<27.0` | Bounded compatible range |
| jsonschema | `>=4.25,<5.0` | Bounded compatible range |
| yamllint | `>=1.38,<2.0` | Bounded compatible range |
| `ansible.posix` collection | `2.2.2` | Exact |
| `community.general` collection | `12.6.0` | Exact |

The exact base-image reference in `Containerfile.dev` is:

```text
docker.io/library/python:3.14.7-slim-trixie@sha256:83c1cebb322d099ac9e3a3a532ba74b0146d702838b25e4c75c02fa81ffeb910
```

`requirements-test.txt` contains the exact Python test dependencies.
`requirements-dev.txt` contains bounded ranges for development tools.
`requirements.yml` contains exact Ansible collection versions, and
`pyproject.toml` also requires the exact pytest-xdist version.

Debian packages installed by `apt-get` are not individually version-pinned or
resolved through a snapshot repository. The base-image digest therefore fixes
the starting image but does not guarantee identical package resolution on every
future rebuild. Several disposable Rocky integration fixtures use the mutable
`10.1` tag. Selected service-image qualification tests instead use immutable
image digests and separately assert properties such as application version,
architecture, and runtime identity.

`make check-dev-toolchain` prints the effective Python, pip, pytest, Ansible,
lint, shell, cryptographic, Git, and GNU utility versions and runs
`python -m pip check`. This verifies the versions actually installed in the
current development image rather than relying only on manifest intent.
