"""Pod security compliance audit.

Scans Kubernetes pod specs (from static manifest files, or optionally a live
cluster) for three risk patterns: privileged containers, hostPath volume
mounts, and containers missing resource limits/requests. Produces a
compliance report and a non-zero exit code when violations are found.

This is read-only: it never mutates cluster state or manifests.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

# Workload kinds whose `spec.template.spec` is a pod spec.
_TEMPLATED_KINDS = {"Deployment", "DaemonSet", "StatefulSet", "Job", "ReplicaSet"}
_CRONJOB_KIND = "CronJob"
_POD_KIND = "Pod"

HIGH = "HIGH"
MEDIUM = "MEDIUM"


@dataclass(frozen=True)
class Finding:
    namespace: str
    workload_kind: str
    workload_name: str
    container: str | None
    rule: str
    severity: str
    detail: str


def _pod_specs_from_manifest(doc: dict[str, Any]) -> Iterable[tuple[str, str, str, dict[str, Any]]]:
    """Yield (namespace, kind, name, pod_spec) for every pod template in one manifest doc."""
    kind = doc.get("kind")
    metadata = doc.get("metadata", {}) or {}
    namespace = metadata.get("namespace", "default")
    name = metadata.get("name", "<unnamed>")

    if kind == _POD_KIND:
        pod_spec = doc.get("spec", {}) or {}
        yield namespace, kind, name, pod_spec
    elif kind in _TEMPLATED_KINDS:
        template = (doc.get("spec", {}) or {}).get("template", {}) or {}
        pod_spec = template.get("spec", {}) or {}
        yield namespace, kind, name, pod_spec
    elif kind == _CRONJOB_KIND:
        job_template = (doc.get("spec", {}) or {}).get("jobTemplate", {}) or {}
        pod_template = (job_template.get("spec", {}) or {}).get("template", {}) or {}
        pod_spec = pod_template.get("spec", {}) or {}
        yield namespace, kind, name, pod_spec


def _containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    return list(pod_spec.get("containers", []) or []) + list(pod_spec.get("initContainers", []) or [])


def audit_pod_spec(namespace: str, kind: str, name: str, pod_spec: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    for volume in pod_spec.get("volumes", []) or []:
        if "hostPath" in volume:
            findings.append(
                Finding(
                    namespace=namespace,
                    workload_kind=kind,
                    workload_name=name,
                    container=None,
                    rule="host-path-volume",
                    severity=HIGH,
                    detail=f"volume '{volume.get('name', '<unnamed>')}' mounts hostPath "
                    f"'{volume.get('hostPath', {}).get('path', '?')}'",
                )
            )

    for container in _containers(pod_spec):
        cname = container.get("name", "<unnamed>")
        security_context = container.get("securityContext", {}) or {}

        if security_context.get("privileged") is True:
            findings.append(
                Finding(
                    namespace,
                    kind,
                    name,
                    cname,
                    "privileged-container",
                    HIGH,
                    "securityContext.privileged is true",
                )
            )

        resources = container.get("resources", {}) or {}
        limits = resources.get("limits", {}) or {}
        requests = resources.get("requests", {}) or {}
        missing = [
            f"{kind_}.{field}"
            for kind_, bucket in (("limits", limits), ("requests", requests))
            for field in ("cpu", "memory")
            if field not in bucket
        ]
        if missing:
            findings.append(
                Finding(
                    namespace,
                    kind,
                    name,
                    cname,
                    "missing-resource-limits",
                    MEDIUM,
                    f"missing: {', '.join(missing)}",
                )
            )

    return findings


def audit_manifest_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for doc in yaml.safe_load_all(text):
        if not isinstance(doc, dict):
            continue
        for namespace, kind, name, pod_spec in _pod_specs_from_manifest(doc):
            findings.extend(audit_pod_spec(namespace, kind, name, pod_spec))
    return findings


def audit_directory(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in sorted(path.rglob("*")):
        if file_path.suffix not in (".yml", ".yaml"):
            continue
        findings.extend(audit_manifest_text(file_path.read_text(encoding="utf-8")))
    return findings


def audit_live_cluster(namespace: str | None) -> list[Finding]:  # pragma: no cover - needs a real cluster
    """Audit running pods via the Kubernetes API. Requires `kubernetes` and a kubeconfig/in-cluster
    context; not exercised by the test suite, which only covers the static-manifest path."""
    from kubernetes import client, config  # local import: optional dependency

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace) if namespace else v1.list_pod_for_all_namespaces()

    findings: list[Finding] = []
    for pod in pods.items:
        pod_spec = client.ApiClient().sanitize_for_serialization(pod.spec)
        findings.extend(audit_pod_spec(pod.metadata.namespace, "Pod", pod.metadata.name, pod_spec))
    return findings


def render_markdown(findings: list[Finding]) -> str:
    lines = ["# Pod security compliance report", ""]
    if not findings:
        lines.append("No violations found.")
        return "\n".join(lines)

    high = sum(1 for f in findings if f.severity == HIGH)
    medium = sum(1 for f in findings if f.severity == MEDIUM)
    lines.append(f"**{len(findings)} finding(s)** - {high} HIGH, {medium} MEDIUM")
    lines.append("")
    lines.append("| Severity | Namespace | Workload | Container | Rule | Detail |")
    lines.append("|---|---|---|---|---|---|")
    for f in sorted(findings, key=lambda x: (x.severity != HIGH, x.namespace, x.workload_name)):
        lines.append(
            f"| {f.severity} | {f.namespace} | {f.workload_kind}/{f.workload_name} | "
            f"{f.container or '-'} | {f.rule} | {f.detail} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, nargs="?", help="directory of manifest files to audit")
    parser.add_argument("--live", action="store_true", help="audit a live cluster instead of files")
    parser.add_argument("--live-namespace", default=None, help="restrict --live to one namespace")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    parser.add_argument(
        "--fail-on",
        choices=["high", "any", "never"],
        default="high",
        help="exit non-zero when findings at/above this severity exist (default: high)",
    )
    args = parser.parse_args(argv)

    if args.live:
        findings = audit_live_cluster(args.live_namespace)
    else:
        if args.path is None:
            parser.error("path is required unless --live is set")
        findings = audit_directory(args.path)

    if args.format == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(render_markdown(findings))

    if args.fail_on == "never":
        return 0
    if args.fail_on == "any" and findings:
        return 1
    if args.fail_on == "high" and any(f.severity == HIGH for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
