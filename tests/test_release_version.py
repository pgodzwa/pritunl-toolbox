import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release_version.py"
spec = importlib.util.spec_from_file_location("release_version", SCRIPT)
rv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rv)


@pytest.mark.parametrize("tags,messages,expected", [
    ([], ["anything"], ("1.0.0", None, "initial")),
    (["v1.0.0"], ["Fix whois table"], ("1.0.1", "1.0.0", "patch")),
    (["v1.0.0", "v1.0.1"], ["Merge pull request #7\n\nfeat: GeoLite wizard"],
     ("1.1.0", "1.0.1", "minor")),
    (["v1.2.3"], ["feat(tui): tabs"], ("1.3.0", "1.2.3", "minor")),
    (["v1.2.3"], ["Change config\n\nBREAKING CHANGE: profiles renamed"],
     ("2.0.0", "1.2.3", "major")),
    (["v1.2.3"], ["refactor!: drop python 3.10"], ("2.0.0", "1.2.3", "major")),
    (["v1.2.3"], ["Docs only [skip release]"], (None, "1.2.3", "skip")),
    (["v1.9.0", "v1.10.0", "junk", "v1.2.0"], ["fix"], ("1.10.1", "1.10.0", "patch")),
])
def test_next_version(tags, messages, expected):
    assert rv.next_version(tags, messages) == expected


def run_script(repo):
    out = subprocess.run([sys.executable, str(SCRIPT)], cwd=repo, check=True,
                         capture_output=True, text=True).stdout
    return dict(line.split("=", 1) for line in out.splitlines())


def git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                        "HOME": str(repo), "PATH": "/usr/bin:/bin"})


def test_script_against_real_git_repo(tmp_path):
    git(tmp_path, "init", "-q")
    git(tmp_path, "commit", "-q", "--allow-empty", "-m", "initial")
    assert run_script(tmp_path) == {"release": "true", "version": "1.0.0", "previous": "",
                                    "bump": "initial"}
    git(tmp_path, "tag", "v1.0.0")
    assert run_script(tmp_path)["release"] == "false"  # HEAD already released (re-run)
    git(tmp_path, "commit", "-q", "--allow-empty", "-m", "feat: thing; $(rm -rf /)")
    out = run_script(tmp_path)
    assert (out["version"], out["bump"]) == ("1.1.0", "minor")
