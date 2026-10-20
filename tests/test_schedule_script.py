"""The Windows scripts cannot run here, so these tests read their text for the settings the
jobs depend on, and (when PowerShell is installed) check that they parse."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
NAMES = [
    "common.ps1",
    "run_collector_once.ps1",
    "schedule_collector.ps1",
    "run_ood_crawl.ps1",
    "render_ood.ps1",
]


def text(name: str) -> str:
    return (SCRIPTS / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", NAMES)
def test_scripts_are_ascii_and_balanced(name):
    src = text(name)
    assert src.isascii()  # Windows PowerShell 5.1 reads BOM-less files as ANSI
    no_comments = re.sub(r"<#.*?#>", "", src, flags=re.S)
    no_comments = re.sub(r"(?m)^\s*#.*$", "", no_comments)
    for open_c, close_c in ("{}", "()", "[]"):
        assert no_comments.count(open_c) == no_comments.count(close_c), (name, open_c)


def test_schedule_registers_the_12_hourly_task_with_the_required_settings():
    s = text("schedule_collector.ps1")
    assert '$TaskName = "PhishDriftCollector"' in s
    assert "[int]$EveryHours = 12" in s and "-RepetitionInterval $every" in s
    assert "New-ScheduledTaskTrigger -AtLogOn" in s  # also at logon
    assert "StartWhenAvailable" in s  # run as soon as possible after a missed start
    assert "[int]$TimeLimitHours = 3" in s and "ExecutionTimeLimit" in s
    assert '"IgnoreNew"' in s  # no overlapping instances
    assert "S4U" in s and "Interactive" in s  # no password stored; fallback is announced
    assert "-Force" in s and "Register-ScheduledTask" in s  # a rerun updates the task
    assert "Unregister-ScheduledTask" in s and "[switch]$Remove" in s
    assert "[switch]$RunNow" in s and "Start-ScheduledTask" in s
    assert "NextRunTime" in s and "Get-ScheduledTaskInfo" in s  # status at the end
    assert "AllowStartIfOnBatteries" in s and "DontStopIfGoingOnBatteries" in s  # a laptop
    assert "run_collector_once.ps1" in s
    assert "Find-PhishDriftPython" in s


def test_task_wrapper_runs_the_collector_and_logs_to_a_dated_file():
    s = text("run_collector_once.ps1")
    assert "-m collector run" in s
    assert "collector_{0}.log" in s and "yyyy-MM-dd" in s and r"data\logs" in s
    assert "Add-Content" in s  # appends
    assert "Find-PhishDriftPython" in s and "exit $code" in s


def test_python_discovery_matches_the_other_scripts():
    s = text("common.ps1")
    assert r".venv\Scripts\python.exe" in s and "py" in s and "-3.11" in s
    assert "Get-Command python" in s


def test_ood_script_checks_disk_runs_the_command_and_prints_the_output():
    s = text("run_ood_crawl.ps1")
    assert '"crawl-ood"' in s and "MinFreeGB" in s and "Get-FreeDiskGB" in s
    assert "ood_urls.csv" in s and "Length" in s  # path and size


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("name", NAMES)
def test_scripts_parse_with_powershell(name):
    cmd = (
        "$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
        f"'{SCRIPTS / name}',[ref]$null,[ref]$e);if($e){{$e|%{{$_.Message}};exit 1}}"
    )
    assert subprocess.run(["pwsh", "-NoProfile", "-Command", cmd]).returncode == 0


def test_render_script_runs_render_ood_then_the_gap_report():
    src = text("render_ood.ps1")
    assert '"collector", "render-ood"' in src and "experiments.render_gap" in src
    assert "Get-FreeDiskGB" in src and "Find-PhishDriftPython" in src
    assert "$code -eq 130" in src  # Ctrl+C tells the user to rerun
