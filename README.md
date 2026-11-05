# pod-security-audit

A read-only Python CLI that audits Kubernetes pod specs for three common
compliance risks — privileged containers, `hostPath` volume mounts, and
containers missing resource limits/requests — and prints a pass/fail
compliance report.

**Scope.** The default and tested mode reads static manifest files from a
directory (plain YAML, Helm/Kustomize output, or anything `kubectl` would
accept). An optional `--live` mode can query a real cluster via the
`kubernetes` Python client, but that path is not covered by the test suite
and is not exercised in CI — it needs a real kubeconfig/cluster to run. This
tool never mutates anything: no patches, no deletes, no annotations.

## Architecture

- `audit.py` — the whole tool. `audit_manifest_text` parses one (possibly
  multi-document) YAML file, unwraps the pod template out of `Pod`,
  `Deployment`, `DaemonSet`, `StatefulSet`, `Job`/`ReplicaSet`, and `CronJob`
  objects, and runs `audit_pod_spec` against each one. `audit_directory`
  walks a directory of `*.yaml`/`*.yml` files. `audit_live_cluster` is the
  optional live-cluster path (lazy-imports `kubernetes` so it's not a hard
  dependency for the file-based path).
- Findings are a flat list of `Finding(namespace, workload_kind,
  workload_name, container, rule, severity, detail)`, rendered as Markdown
  (a summary count + table) or JSON.

## Rules

| Rule | Severity | Trigger |
|---|---|---|
| `privileged-container` | HIGH | `securityContext.privileged: true` |
| `host-path-volume` | HIGH | any pod volume with a `hostPath` |
| `missing-resource-limits` | MEDIUM | a container missing any of `limits.cpu`, `limits.memory`, `requests.cpu`, `requests.memory` |

## Prerequisites

- Python 3.12+ (tested on 3.12; no version-specific syntax used)
- `pip install -r requirements.txt` (only `pyyaml` is required for the
  file-based path; `kubernetes` is only imported if you pass `--live`)

## Usage

```bash
# Audit a directory of manifests, print a Markdown report
python audit.py ./examples

# Machine-readable output for piping into another tool
python audit.py ./examples --format json

# CI gate: exit 1 only when there's a HIGH-severity finding (the default)
python audit.py ./manifests --fail-on high
python audit.py ./manifests --fail-on any     # fail on MEDIUM too
python audit.py ./manifests --fail-on never   # report only, always exit 0

# Optional: audit a live cluster instead of files (needs kubeconfig / in-cluster creds)
python audit.py --live
python audit.py --live --live-namespace payments
```

Sample input/output lives in [`examples/sample-manifests.yaml`](examples/sample-manifests.yaml) —
it deliberately includes one privileged pod, one `hostPath` mount, one
container with no resource limits, and one fully compliant deployment, so
you can see all three rules fire (and one not fire) in a single run:

```bash
python audit.py examples
```

## Security considerations

- The tool is **read-only**. The live-cluster path only ever calls
  `list_namespaced_pod` / `list_pod_for_all_namespaces` — no write verbs.
- For `--live`, scope the kubeconfig's RBAC to `get`/`list` on `pods` only;
  it needs nothing else.
- No secrets are read, logged, or required. Manifest `Secret` resources
  themselves are not a target kind and are ignored by the parser.
- Treat the output report as containing cluster topology (namespace and
  workload names) — handle it with the same sensitivity as `kubectl get
  pods -A` output.

## Idempotency

Pure read + report: running the tool any number of times against the same
input produces the same findings and has zero side effects on the cluster
or the manifest files.

## Tests

```bash
pip install -r requirements-test.txt
python -m unittest discover -s tests
```

Tests run entirely against the fixtures in `examples/` and inline YAML
strings — no cluster or network access required.
