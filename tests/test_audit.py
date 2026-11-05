import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit import (  # noqa: E402
    HIGH,
    MEDIUM,
    audit_directory,
    audit_manifest_text,
    main,
    render_markdown,
)

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


class TestAuditRules(unittest.TestCase):
    def test_privileged_container_flagged_high(self):
        text = """
        apiVersion: v1
        kind: Pod
        metadata: {name: p, namespace: default}
        spec:
          containers:
            - name: c
              securityContext: {privileged: true}
              resources: {limits: {cpu: "1", memory: "1Gi"}, requests: {cpu: "1", memory: "1Gi"}}
        """
        findings = audit_manifest_text(text)
        rules = {f.rule for f in findings}
        self.assertIn("privileged-container", rules)
        self.assertTrue(all(f.severity == HIGH for f in findings if f.rule == "privileged-container"))

    def test_host_path_volume_flagged_high(self):
        text = """
        apiVersion: v1
        kind: Pod
        metadata: {name: p, namespace: default}
        spec:
          volumes:
            - name: v
              hostPath: {path: /etc}
          containers:
            - name: c
              resources: {limits: {cpu: "1", memory: "1Gi"}, requests: {cpu: "1", memory: "1Gi"}}
        """
        findings = audit_manifest_text(text)
        self.assertEqual([f for f in findings if f.rule == "host-path-volume"][0].severity, HIGH)

    def test_missing_resource_limits_flagged_medium(self):
        text = """
        apiVersion: v1
        kind: Pod
        metadata: {name: p, namespace: default}
        spec:
          containers:
            - name: c
        """
        findings = audit_manifest_text(text)
        limit_findings = [f for f in findings if f.rule == "missing-resource-limits"]
        self.assertEqual(len(limit_findings), 1)
        self.assertEqual(limit_findings[0].severity, MEDIUM)
        self.assertIn("limits.cpu", limit_findings[0].detail)
        self.assertIn("requests.memory", limit_findings[0].detail)

    def test_compliant_container_produces_no_findings(self):
        text = """
        apiVersion: v1
        kind: Pod
        metadata: {name: p, namespace: default}
        spec:
          containers:
            - name: c
              securityContext: {allowPrivilegeEscalation: false}
              resources: {limits: {cpu: "1", memory: "1Gi"}, requests: {cpu: "1", memory: "1Gi"}}
        """
        self.assertEqual(audit_manifest_text(text), [])

    def test_deployment_statefulset_daemonset_cronjob_templates_are_unwrapped(self):
        for kind in ("Deployment", "DaemonSet", "StatefulSet"):
            text = f"""
            apiVersion: apps/v1
            kind: {kind}
            metadata: {{name: p, namespace: default}}
            spec:
              template:
                spec:
                  containers:
                    - name: c
                      securityContext: {{privileged: true}}
            """
            findings = audit_manifest_text(text)
            self.assertTrue(
                any(f.rule == "privileged-container" for f in findings),
                f"expected privileged-container finding to unwrap {kind}",
            )

    def test_cronjob_job_template_is_unwrapped(self):
        text = """
        apiVersion: batch/v1
        kind: CronJob
        metadata: {name: p, namespace: default}
        spec:
          jobTemplate:
            spec:
              template:
                spec:
                  containers:
                    - name: c
                      securityContext: {privileged: true}
        """
        findings = audit_manifest_text(text)
        self.assertTrue(any(f.rule == "privileged-container" for f in findings))


class TestAuditDirectoryAndCli(unittest.TestCase):
    def test_sample_manifests_produce_expected_finding_counts(self):
        findings = audit_directory(EXAMPLES_DIR)
        rules = [f.rule for f in findings]
        self.assertEqual(rules.count("privileged-container"), 1)
        self.assertEqual(rules.count("host-path-volume"), 1)
        self.assertEqual(rules.count("missing-resource-limits"), 1)

    def test_render_markdown_includes_summary_counts(self):
        findings = audit_directory(EXAMPLES_DIR)
        report = render_markdown(findings)
        self.assertIn("finding(s)", report)
        self.assertIn("HIGH", report)

    def test_render_markdown_clean_report(self):
        self.assertIn("No violations found", render_markdown([]))

    def test_main_exits_nonzero_on_high_findings_by_default(self):
        exit_code = main([str(EXAMPLES_DIR), "--format", "json"])
        self.assertEqual(exit_code, 1)

    def test_main_exits_zero_when_fail_on_never(self):
        exit_code = main([str(EXAMPLES_DIR), "--fail-on", "never"])
        self.assertEqual(exit_code, 0)

    def test_main_requires_path_without_live(self):
        with self.assertRaises(SystemExit):
            main([])


if __name__ == "__main__":
    unittest.main()
