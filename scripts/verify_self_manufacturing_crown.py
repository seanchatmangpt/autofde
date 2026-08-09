#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from autofde.runtime import AuthorityEnvelope, RuntimeStore
from autofde.self_manufacture import SelfManufacturingRuntime


def run(cmd: list[str]) -> None:
    result = subprocess.run(cmd, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"command failed {result.returncode}: {' '.join(cmd)}\n{result.stdout}\n{result.stderr}")
    if result.stdout:
        print(result.stdout.strip())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lab-root", required=True)
    parser.add_argument("--ggen-root", required=True)
    parser.add_argument("--lab-revision", required=True)
    parser.add_argument("--ggen-revision", required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        state = tmp / "runtime.sqlite"
        world = tmp / "world"
        evidence = tmp / "evidence"
        first_store = RuntimeStore(state)
        first_runtime = SelfManufacturingRuntime(first_store, world, evidence)
        blocked = first_runtime.require_capability(
            observation={"kind": "greeting", "source": "crown"},
            capability="write-greeting",
            subject="local:self-manufacturing-crown",
            consequence="filesystem.write",
            idempotency_key="crown-occurrence-1",
            payload={"kind": "greeting", "source": "crown"},
            manufacture_spec={
                "kind": "filesystem_write",
                "path": "out/greeting.txt",
                "content": "hello from AutoFDE self-manufacturing crown\n",
                "match_all": {"kind": "greeting"},
            },
        )
        assert blocked["standing"] == "BLOCKED:CAPABILITY_ABSENT", blocked
        requirement_path = Path(blocked["requirement_path"])
        admission = tmp / "admission.json"
        powl = tmp / "work.powl.ttl"
        bundle = tmp / "bundle.json"
        manufacture = tmp / "manufacture.json"

        run([
            "python3",
            str(Path(args.lab_root) / "scripts" / "autofde_admit_requirement.py"),
            str(requirement_path),
            "--lab-revision", args.lab_revision,
            "--out", str(admission),
            "--powl-out", str(powl),
        ])
        run([
            "python3",
            str(Path(args.ggen_root) / "scripts" / "autofde_manufacture_bundle.py"),
            str(requirement_path), str(admission),
            "--ggen-revision", args.ggen_revision,
            "--bundle-out", str(bundle),
            "--receipt-out", str(manufacture),
        ])

        manufacture_receipt = json.loads(manufacture.read_text())
        reopened_store = RuntimeStore(state)
        resumed_runtime = SelfManufacturingRuntime(reopened_store, world, evidence)
        authority = AuthorityEnvelope(
            envelope_id="authority:self-manufacturing-crown",
            subject="local:self-manufacturing-crown",
            allowed_consequences=frozenset({"filesystem.write"}),
            capability_digest=manufacture_receipt["bundle_digest"],
        )
        result = resumed_runtime.promote_and_resume(
            requirement_path=requirement_path,
            admission_path=admission,
            powl_path=powl,
            bundle_payload_path=bundle,
            manufacture_receipt_path=manufacture,
            authority=authority,
        )
        assert result["standing"] == "ALIVE", result
        assert result["postcondition_verified"] is True
        assert result["replay_verified"] is True
        assert result["completed_activity_reexecuted"] is False
        assert result["actuation_calls"] == 1, result
        assert (world / "out" / "greeting.txt").read_text() == "hello from AutoFDE self-manufacturing crown\n"

        ocel = json.loads(Path(result["ocel_path"]).read_text())
        histories = {
            attribute["value"]
            for event in ocel["events"]
            for attribute in event["attributes"]
            if attribute["name"] == "history"
        }
        assert histories == {"operational", "engineering"}, histories
        assert len(ocel["events"]) == 7

        third_store = RuntimeStore(state)
        third_runtime = SelfManufacturingRuntime(third_store, world, evidence)
        replay = third_runtime.promote_and_resume(
            requirement_path=requirement_path,
            admission_path=admission,
            powl_path=powl,
            bundle_payload_path=bundle,
            manufacture_receipt_path=manufacture,
            authority=authority,
        )
        assert replay["standing"] == "ALIVE", replay
        assert replay["occurrence_id"] == result["occurrence_id"]
        assert replay["actuation_calls"] == 0, replay

        tampered = json.loads(bundle.read_text())
        tampered["program"]["content"] = "tampered"
        tampered_path = tmp / "tampered-bundle.json"
        tampered_path.write_text(json.dumps(tampered, indent=2, sort_keys=True) + "\n")
        refused = False
        try:
            third_runtime.promote_and_resume(
                requirement_path=requirement_path,
                admission_path=admission,
                powl_path=powl,
                bundle_payload_path=tampered_path,
                manufacture_receipt_path=manufacture,
                authority=authority,
            )
        except ValueError as exc:
            refused = "BUNDLE_DIGEST_DRIFT" in str(exc)
        assert refused, "tampered manufactured payload was not refused"

        receipt = {
            "standing": "ALIVE",
            "checkpoint": "AUTOFDE_SELF_MANUFACTURING_CROWN",
            "requirement_id": result["requirement_id"],
            "promotion_digest": result["promotion_digest"],
            "bundle_digest": result["bundle_digest"],
            "lab_revision": result["lab_revision"],
            "ggen_revision": result["ggen_revision"],
            "occurrence_id": result["occurrence_id"],
            "crash_restart_verified": True,
            "postcondition_verified": True,
            "replay_verified": True,
            "completed_activity_reexecuted": False,
            "ocel_histories": sorted(histories),
            "tamper_refusal_verified": True,
        }
        print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
