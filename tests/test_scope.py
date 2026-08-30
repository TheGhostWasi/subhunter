import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from subhunter.core.scope import Scope


def _write(lines):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(lines))
    f.close()
    return f.name


def test_no_scope_file_means_everything_in_scope():
    scope = Scope()
    assert scope.is_in_scope("anything.example.com") is True


def test_scope_wildcard_match():
    path = _write(["*.example.com", "api.example.net"])
    scope = Scope(scope_file=path)
    assert scope.is_in_scope("dev.example.com") is True
    assert scope.is_in_scope("api.example.net") is True
    assert scope.is_in_scope("other.example.org") is False


def test_exclude_overrides_scope():
    scope_path = _write(["*.example.com"])
    exclude_path = _write(["*.internal.example.com"])
    scope = Scope(scope_file=scope_path, exclude_file=exclude_path)
    in_scope, excluded = scope.evaluate("secret.internal.example.com")
    assert excluded is True
    assert in_scope is False


def test_comments_and_blank_lines_ignored():
    path = _write(["# comment", "", "*.example.com"])
    scope = Scope(scope_file=path)
    assert scope.is_in_scope("dev.example.com") is True
