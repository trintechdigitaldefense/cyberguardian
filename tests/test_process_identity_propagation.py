from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = ROOT / "agents" / "linux-ebpf"
DECISION_DIR = ROOT / "control-plane" / "decision-service"
sys.path.insert(0, str(AGENT_DIR))
sys.path.insert(0, str(DECISION_DIR))


def _load_agent():
    spec = importlib.util.spec_from_file_location("cg_agent_process_test", AGENT_DIR / "agent.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_decision():
    spec = importlib.util.spec_from_file_location("cg_decision_process_test", DECISION_DIR / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_agent_inventory_captures_proc_starttime(tmp_path, monkeypatch):
    agent = _load_agent()
    proc = tmp_path / "4321"
    proc.mkdir()
    fields = ["S"] + [str(i) for i in range(1, 19)] + ["987654"]
    (proc / "stat").write_text(f"4321 (worker process) " + " ".join(fields))
    (proc / "cmdline").write_bytes(b"python\x00worker.py\\x00")
    monkeypatch.setattr(agent, "PROC_ROOT", tmp_path)
    found = agent.list_processes()
    assert found == [{
        "pid": "4321",
        "cmd": "python worker.py",
        "start_time": "987654",
    }]


def test_decision_engine_propagates_process_identity_to_kill_action():
    decision = _load_decision()
    detection = decision.Detection(
        asset_id="host-1",
        severity=decision.Severity.HIGH,
        title="suspicious process activity",
        indicators={
            "pid": "4321",
            "cmdline_hint": "python worker.py",
            "expected_starttime": "987654",
        },
    )
    actions = decision.plan_actions(detection)
    kill = next(action for action in actions if action.action == decision.ActionType.KILL_PROCESS)
    assert kill.target == "4321"
    assert kill.parameters["cmdline_hint"] == "python worker.py"
    assert kill.parameters["expected_starttime"] == "987654"
