import importlib
import json

terminal_tool_module = importlib.import_module("tools.terminal_tool")


def test_terminal_returns_guard_event_for_approval_required(monkeypatch):
    monkeypatch.setattr(
        terminal_tool_module,
        "_check_all_guards",
        lambda command, env_type: {
            "approved": False,
            "status": "approval_required",
            "command": command,
            "description": "git push with force",
            "pattern_key": "git push with force",
            "message": "blocked until explicit approval",
        },
    )

    result = json.loads(
        terminal_tool_module.terminal_tool(
            command="git push --force origin main",
            force=False,
            task_id="test-guard-event-approval",
        )
    )

    assert result["status"] == "approval_required"
    assert result["guard_event"]["event"] == "terminal_guard_blocked"
    assert result["guard_event"]["status"] == "approval_required"
    assert result["guard_event"]["command"].startswith("git push")


def test_terminal_returns_guard_event_for_blocked(monkeypatch):
    monkeypatch.setattr(
        terminal_tool_module,
        "_check_all_guards",
        lambda command, env_type: {
            "approved": False,
            "status": "blocked",
            "description": "user denied",
            "message": "BLOCKED: User denied",
        },
    )

    result = json.loads(
        terminal_tool_module.terminal_tool(
            command="rm -rf /tmp/whatever",
            force=False,
            task_id="test-guard-event-blocked",
        )
    )

    assert result["status"] == "blocked"
    assert result["guard_event"]["event"] == "terminal_guard_blocked"
    assert result["guard_event"]["status"] == "blocked"
    assert result["guard_event"]["command"].startswith("rm -rf")
