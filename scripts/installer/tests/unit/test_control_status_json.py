#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Unit tests for the machine-readable status mode of scripts/control.py (``--status --json``).

The compose and kubernetes back ends are mocked; nothing here needs a container runtime or a cluster.
"""

import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
for _path in (REPO_ROOT, SCRIPTS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import control  # noqa: E402  (scripts/control.py, which uses bare imports of its sibling modules)

CONTROL_PY = os.path.join(SCRIPTS_DIR, "control.py")

MALCOLM_TAG = "26.09.0"
COMPOSE_YAML = {
    "services": {
        "api": {"image": f"ghcr.io/idaholab/malcolm/api:{MALCOLM_TAG}", "profiles": ["malcolm"]},
        "nginx-proxy": {
            "image": f"ghcr.io/idaholab/malcolm/nginx-proxy:{MALCOLM_TAG}",
            "profiles": ["malcolm", "hedgehog"],
        },
        "opensearch": {"image": f"ghcr.io/idaholab/malcolm/opensearch:{MALCOLM_TAG}", "profiles": ["malcolm"]},
        "zeek-live": {"image": f"ghcr.io/idaholab/malcolm/zeek:{MALCOLM_TAG}", "profiles": ["hedgehog"]},
    }
}


def compose_record(service, state="running", health="healthy", status=None, image=None):
    return {
        "ID": "0123456789ab",
        "Name": f"malcolm-{service}-1",
        "Service": service,
        "Image": image or f"ghcr.io/idaholab/malcolm/{service}:{MALCOLM_TAG}",
        "State": state,
        "Health": health,
        "Status": status or ("Up 5 minutes (healthy)" if health == "healthy" else "Up 5 minutes"),
        "ExitCode": 0,
        "Labels": f"com.docker.compose.project=malcolm,com.docker.compose.service={service}",
    }


def ndjson(records):
    return [json.dumps(r) for r in records]


def fake_pod(service, ready=True, running=True, terminated_reason=None, waiting_reason=None, restarts=0):
    state = SimpleNamespace(running=None, terminated=None, waiting=None)
    if waiting_reason:
        state.waiting = SimpleNamespace(reason=waiting_reason)
    elif terminated_reason:
        state.terminated = SimpleNamespace(reason=terminated_reason, exit_code=1)
    elif running:
        state.running = SimpleNamespace(started_at="now")
    container = SimpleNamespace(
        name=f"{service}-container",
        image=f"ghcr.io/idaholab/malcolm/{service}:{MALCOLM_TAG}",
        ready=ready,
        restart_count=restarts,
        state=state,
    )
    return SimpleNamespace(
        metadata=SimpleNamespace(
            name=f"{service}-deployment-7fff7bf884-84prz", labels={"name": f"{service}-deployment"}
        ),
        spec=SimpleNamespace(node_name="worker-1"),
        status=SimpleNamespace(phase="Running" if running else "Pending", container_statuses=[container]),
    )


class FakeKubeClient:
    def __init__(self, pods=None, error=None):
        self._pods = pods or []
        self._error = error
        self.namespaces_queried = []

    def list_namespaced_pod(self, namespace, watch=False, **kwargs):
        self.namespaces_queried.append(namespace)
        if self._error:
            raise self._error
        return SimpleNamespace(items=self._pods)


class StatusJsonTestCase(unittest.TestCase):
    """Common fixture: swap control.py's module globals for the duration of each test."""

    def setUp(self):
        self._saved = {
            k: getattr(control, k)
            for k in ("args", "orchMode", "dockerComposeBin", "dockerComposeYaml", "kubeImported")
        }
        control.args = SimpleNamespace(
            composeProfile="malcolm",
            composeFile="/opt/malcolm/docker-compose.yml",
            service=None,
            noTmpDirOverride=True,
            verbose=0,
            namespace="malcolm",
            statusJson=True,
        )
        control.dockerComposeBin = ("docker", "compose")
        control.dockerComposeYaml = COMPOSE_YAML
        control.kubeImported = None

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(control, k, v)

    def run_status_json(self):
        """Run status_json() capturing stdout; assert stdout is exactly one JSON document."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = control.status_json()
        out = buf.getvalue()
        report = json.loads(out)  # raises if stdout is not a single JSON document
        self.assertEqual(out.strip(), json.dumps(report, indent=2))
        return exit_code, report


class TestComposeStatusJson(StatusJsonTestCase):
    def setUp(self):
        super().setUp()
        control.orchMode = control.OrchestrationFramework.DOCKER_COMPOSE

    def run_with_compose_output(self, err, lines):
        with mock.patch.object(control, "run_process", return_value=(err, lines)) as run_process:
            exit_code, report = self.run_status_json()
        self.assertEqual(run_process.call_count, 1)
        cmd = list(control.flatten(run_process.call_args.args[0]))
        self.assertEqual(cmd[:2], ["docker", "compose"])
        self.assertIn("ps", cmd)
        self.assertIn("--all", cmd)
        self.assertEqual(cmd[cmd.index("--format") + 1], "json")
        self.assertFalse(run_process.call_args.kwargs.get("stderr", True), "stderr must not be mixed into JSON output")
        return exit_code, report

    def test_all_healthy(self):
        lines = ndjson(
            [
                compose_record("api"),
                compose_record("nginx-proxy"),
                compose_record("opensearch"),
            ]
        )
        exit_code, report = self.run_with_compose_output(0, lines)
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_OK)
        self.assertEqual(report["runtime"], "docker_compose")
        self.assertEqual(report["summary"], {"total": 3, "running": 3, "unhealthy": 0, "stopped": 0, "healthy": True})
        self.assertNotIn("error", report)
        services = {s["service"]: s for s in report["services"]}
        self.assertEqual(sorted(services), ["api", "nginx-proxy", "opensearch"])
        self.assertEqual(services["api"]["name"], "malcolm-api-1")
        self.assertEqual(services["api"]["state"], "running")
        self.assertEqual(services["api"]["health"], "healthy")
        self.assertEqual(services["api"]["image"], "ghcr.io/idaholab/malcolm/api")
        self.assertEqual(services["api"]["image_tag"], MALCOLM_TAG)

    def test_all_healthy_without_healthchecks_is_healthy(self):
        lines = ndjson(
            [compose_record(s, health="", status="Up 5 minutes") for s in ("api", "nginx-proxy", "opensearch")]
        )
        exit_code, report = self.run_with_compose_output(0, lines)
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_OK)
        self.assertTrue(report["summary"]["healthy"])
        self.assertTrue(all(s["health"] is None for s in report["services"]))

    def test_one_unhealthy(self):
        lines = ndjson(
            [
                compose_record("api"),
                compose_record("nginx-proxy", health="unhealthy", status="Up 5 minutes (unhealthy)"),
                compose_record("opensearch"),
            ]
        )
        exit_code, report = self.run_with_compose_output(0, lines)
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_UNHEALTHY)
        self.assertEqual(report["summary"], {"total": 3, "running": 3, "unhealthy": 1, "stopped": 0, "healthy": False})
        services = {s["service"]: s for s in report["services"]}
        self.assertEqual(services["nginx-proxy"]["health"], "unhealthy")

    def test_starting_counts_as_not_yet_healthy(self):
        lines = ndjson(
            [
                compose_record("api", health="starting", status="Up 2 seconds (health: starting)"),
                compose_record("nginx-proxy"),
                compose_record("opensearch"),
            ]
        )
        exit_code, report = self.run_with_compose_output(0, lines)
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_UNHEALTHY)
        self.assertEqual(report["summary"]["unhealthy"], 1)

    def test_one_stopped(self):
        lines = ndjson(
            [
                compose_record("api"),
                compose_record("nginx-proxy"),
                compose_record("opensearch", state="exited", health="", status="Exited (137) 2 minutes ago"),
            ]
        )
        exit_code, report = self.run_with_compose_output(0, lines)
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_UNHEALTHY)
        self.assertEqual(report["summary"], {"total": 3, "running": 2, "unhealthy": 0, "stopped": 1, "healthy": False})
        services = {s["service"]: s for s in report["services"]}
        self.assertEqual(services["opensearch"]["state"], "exited")
        self.assertIsNone(services["opensearch"]["health"])

    def test_service_defined_but_not_created_counts_as_stopped(self):
        # only two of the three malcolm-profile services have containers; the hedgehog-only service must not appear
        lines = ndjson([compose_record("api"), compose_record("nginx-proxy")])
        exit_code, report = self.run_with_compose_output(0, lines)
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_UNHEALTHY)
        self.assertEqual(report["summary"], {"total": 3, "running": 2, "unhealthy": 0, "stopped": 1, "healthy": False})
        services = {s["service"]: s for s in report["services"]}
        self.assertNotIn("zeek-live", services)
        self.assertEqual(services["opensearch"]["state"], control.STATUS_STATE_NOT_CREATED)
        self.assertIsNone(services["opensearch"]["name"])
        self.assertEqual(services["opensearch"]["image"], "ghcr.io/idaholab/malcolm/opensearch")
        self.assertEqual(services["opensearch"]["image_tag"], MALCOLM_TAG)

    def test_nothing_running_is_not_healthy(self):
        exit_code, report = self.run_with_compose_output(0, [])
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_UNHEALTHY)
        self.assertEqual(report["summary"]["running"], 0)
        self.assertEqual(report["summary"]["stopped"], 3)
        self.assertFalse(report["summary"]["healthy"])

    def test_service_filter_limits_not_created_check(self):
        control.args.service = ["api"]
        lines = ndjson([compose_record("api")])
        exit_code, report = self.run_with_compose_output(0, lines)
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_OK)
        self.assertEqual([s["service"] for s in report["services"]], ["api"])

    def test_json_array_output_format(self):
        # older compose versions emit a single JSON array instead of one object per line
        records = [compose_record("api"), compose_record("nginx-proxy"), compose_record("opensearch")]
        exit_code, report = self.run_with_compose_output(0, json.dumps(records, indent=2).split("\n"))
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_OK)
        self.assertEqual(report["summary"]["running"], 3)

    def test_podman_style_health_in_status_string(self):
        rec = compose_record("api", health="", status="Up 5 minutes (unhealthy)")
        rec["Names"] = [rec.pop("Name")]
        rec.pop("Service")
        rec["Labels"] = {"com.docker.compose.service": "api"}
        lines = ndjson([rec, compose_record("nginx-proxy"), compose_record("opensearch")])
        exit_code, report = self.run_with_compose_output(0, lines)
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_UNHEALTHY)
        services = {s["service"]: s for s in report["services"]}
        self.assertEqual(services["api"]["name"], "malcolm-api-1")
        self.assertEqual(services["api"]["health"], "unhealthy")

    def test_malformed_output(self):
        lines = [
            "NAME   IMAGE   COMMAND   SERVICE   STATUS",
            "malcolm-api-1  ghcr.io/idaholab/malcolm/api:26.09.0  running",
        ]
        with self.assertLogs(level="ERROR"):
            exit_code, report = self.run_with_compose_output(0, lines)
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_ERROR)
        self.assertEqual(report["services"], [])
        self.assertFalse(report["summary"]["healthy"])
        self.assertIn("could not parse compose ps output as JSON", report["error"])

    def test_truncated_json_output(self):
        lines = ndjson([compose_record("api")]) + ['{"Name": "malcolm-nginx-proxy-1", "State": "runn']
        with self.assertLogs(level="ERROR"):
            exit_code, report = self.run_with_compose_output(0, lines)
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_ERROR)
        self.assertIn("error", report)

    def test_non_dict_json_output(self):
        with self.assertLogs(level="ERROR"):
            exit_code, report = self.run_with_compose_output(0, ['["not", "records"]'])
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_ERROR)
        self.assertIn("error", report)

    def test_compose_command_failure(self):
        with self.assertLogs(level="ERROR"):
            exit_code, report = self.run_with_compose_output(1, ["no configuration file provided: not found"])
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_ERROR)
        self.assertIn("exited with code 1", report["error"])
        self.assertFalse(report["summary"]["healthy"])


class TestKubernetesStatusJson(StatusJsonTestCase):
    def setUp(self):
        super().setUp()
        control.orchMode = control.OrchestrationFramework.KUBERNETES

    def use_client(self, client):
        control.kubeImported = SimpleNamespace(client=SimpleNamespace(CoreV1Api=lambda: client))
        return client

    def test_all_healthy(self):
        client = self.use_client(
            FakeKubeClient(pods=[fake_pod("api"), fake_pod("nginx-proxy"), fake_pod("opensearch")])
        )
        exit_code, report = self.run_status_json()
        self.assertEqual(client.namespaces_queried, ["malcolm"])
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_OK)
        self.assertEqual(report["runtime"], "kubernetes")
        self.assertEqual(report["summary"], {"total": 3, "running": 3, "unhealthy": 0, "stopped": 0, "healthy": True})
        services = {s["service"]: s for s in report["services"]}
        self.assertEqual(services["api"]["name"], "api-deployment-7fff7bf884-84prz")
        self.assertEqual(services["api"]["state"], "running")
        self.assertEqual(services["api"]["health"], "healthy")
        self.assertEqual(services["api"]["image"], "ghcr.io/idaholab/malcolm/api")
        self.assertEqual(services["api"]["image_tag"], MALCOLM_TAG)
        self.assertEqual(services["api"]["container"], "api-container")
        self.assertEqual(services["api"]["node"], "worker-1")

    def test_one_unhealthy(self):
        self.use_client(
            FakeKubeClient(pods=[fake_pod("api"), fake_pod("nginx-proxy", ready=False), fake_pod("opensearch")])
        )
        exit_code, report = self.run_status_json()
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_UNHEALTHY)
        self.assertEqual(report["summary"], {"total": 3, "running": 3, "unhealthy": 1, "stopped": 0, "healthy": False})
        services = {s["service"]: s for s in report["services"]}
        self.assertEqual(services["nginx-proxy"]["health"], "unhealthy")

    def test_one_stopped(self):
        self.use_client(
            FakeKubeClient(
                pods=[
                    fake_pod("api"),
                    fake_pod("nginx-proxy"),
                    fake_pod("opensearch", ready=False, running=False, waiting_reason="CrashLoopBackOff", restarts=7),
                ]
            )
        )
        exit_code, report = self.run_status_json()
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_UNHEALTHY)
        self.assertEqual(report["summary"], {"total": 3, "running": 2, "unhealthy": 0, "stopped": 1, "healthy": False})
        services = {s["service"]: s for s in report["services"]}
        self.assertEqual(services["opensearch"]["state"], "waiting")
        self.assertEqual(services["opensearch"]["status"], "Waiting (CrashLoopBackOff)")
        self.assertEqual(services["opensearch"]["restarts"], 7)

    def test_terminated_container(self):
        self.use_client(FakeKubeClient(pods=[fake_pod("api", ready=False, running=False, terminated_reason="Error")]))
        exit_code, report = self.run_status_json()
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_UNHEALTHY)
        self.assertEqual(report["services"][0]["state"], "exited")
        self.assertEqual(report["services"][0]["status"], "Terminated (Error)")

    def test_no_pods(self):
        self.use_client(FakeKubeClient(pods=[]))
        exit_code, report = self.run_status_json()
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_UNHEALTHY)
        self.assertEqual(report["summary"]["total"], 0)
        self.assertFalse(report["summary"]["healthy"])

    def test_malformed_pod_objects(self):
        # objects missing the expected attributes must not crash the report
        self.use_client(FakeKubeClient(pods=[SimpleNamespace(), object()]))
        exit_code, report = self.run_status_json()
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_UNHEALTHY)
        self.assertEqual(report["summary"]["total"], 2)
        self.assertEqual(report["summary"]["stopped"], 2)

    def test_api_error(self):
        self.use_client(FakeKubeClient(error=RuntimeError("Unauthorized")))
        with self.assertLogs(level="ERROR"):
            exit_code, report = self.run_status_json()
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_ERROR)
        self.assertEqual(report["runtime"], "kubernetes")
        self.assertIn("Unauthorized", report["error"])
        self.assertFalse(report["summary"]["healthy"])

    def test_client_library_unavailable(self):
        control.kubeImported = None
        with self.assertLogs(level="ERROR"):
            exit_code, report = self.run_status_json()
        self.assertEqual(exit_code, control.STATUS_JSON_EXIT_ERROR)
        self.assertIn("kubernetes", report["error"])


class TestStatusJsonHelpers(unittest.TestCase):
    def test_split_image_tag(self):
        self.assertEqual(
            control.split_image_tag("ghcr.io/idaholab/malcolm/api:26.09.0"), ("ghcr.io/idaholab/malcolm/api", "26.09.0")
        )
        self.assertEqual(
            control.split_image_tag("localhost:5000/malcolm/api:26.09.0"), ("localhost:5000/malcolm/api", "26.09.0")
        )
        self.assertEqual(control.split_image_tag("localhost:5000/malcolm/api"), ("localhost:5000/malcolm/api", None))
        self.assertEqual(control.split_image_tag("busybox"), ("busybox", None))
        self.assertEqual(control.split_image_tag("busybox:1.36@sha256:abcdef"), ("busybox", "1.36"))
        self.assertEqual(control.split_image_tag(None), (None, None))
        self.assertEqual(control.split_image_tag(""), (None, None))

    def test_parse_compose_ps_json_rejects_garbage(self):
        with self.assertRaises(ValueError):
            control.parse_compose_ps_json(["NAME  IMAGE", "foo  bar"])
        with self.assertRaises(ValueError):
            control.parse_compose_ps_json(["[1, 2, 3]"])
        self.assertEqual(control.parse_compose_ps_json([]), [])
        self.assertEqual(control.parse_compose_ps_json(["", "  "]), [])

    def test_build_status_report_counts(self):
        services = [
            {"service": "a", "name": "a1", "state": "running", "health": "healthy"},
            {"service": "b", "name": "b1", "state": "running", "health": None},
            {"service": "c", "name": "c1", "state": "running", "health": "unhealthy"},
            {"service": "d", "name": "d1", "state": "exited", "health": None},
            {"service": "e", "name": None, "state": "not created", "health": None},
        ]
        report = control.build_status_report(services, "docker_compose")
        self.assertEqual(report["summary"], {"total": 5, "running": 3, "unhealthy": 1, "stopped": 2, "healthy": False})
        self.assertEqual([s["service"] for s in report["services"]], ["a", "b", "c", "d", "e"])
        report = control.build_status_report(services[:2], "docker_compose")
        self.assertTrue(report["summary"]["healthy"])
        report = control.build_status_report(services[:2], "docker_compose", error="boom")
        self.assertFalse(report["summary"]["healthy"])
        self.assertEqual(report["error"], "boom")


class TestStatusJsonCommandLine(unittest.TestCase):
    """The argument parser is exercised through the real script; this exits before any container runtime is touched."""

    def run_control(self, *argv):
        return subprocess.run(
            [sys.executable, CONTROL_PY, *argv],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            env={**os.environ, "LOGLEVEL": "ERROR"},
        )

    def test_help_documents_json_flag(self):
        proc = self.run_control("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--json", proc.stdout.decode())

    def test_json_requires_status(self):
        proc = self.run_control("--json")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"", "nothing may be written to stdout in --json mode")
        self.assertIn("--json can only be used with --status", proc.stderr.decode())

    def test_json_rejects_other_operations(self):
        for other in ("--start", "--logs", "--urls", "--restart"):
            with self.subTest(other=other):
                proc = self.run_control("--status", "--json", other)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, b"")


if __name__ == "__main__":
    unittest.main()
