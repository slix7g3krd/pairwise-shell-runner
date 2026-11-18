import pytest

from security.shell_runner import (
    build_argv,
    validate_command,
    sanitize_env,
    truncate_output,
    validate_timeout
)


def test_argv():
    assert build_argv('echo', ['hello']) == ['echo', 'hello']

def test_metachar_arg():
    assert build_argv('echo', ['a;b']) == ['echo', 'a;b']

def test_newline_arg():
    assert build_argv('echo', ['a' + chr(10) + 'b']) == ['echo', 'a' + chr(10) + 'b']

def test_allowed():
    assert validate_command('ls', {'ls'}) is True

def test_prefix():
    assert validate_command('ls; rm', {'ls'}) is False

def test_env_white():
    assert sanitize_env({'PATH': '/bin', 'LD_PRELOAD': 'x'}, {'PATH'}) == {'PATH': '/bin'}

def test_env_empty():
    assert sanitize_env({'LD_PRELOAD': 'x'}, {'PATH'}) == {}

def test_truncate():
    out = truncate_output('a' * 100, 10)
    assert len(out) <= 10
    assert out.endswith('...')

def test_timeout():
    assert validate_timeout(5) is True

def test_timeout_zero():
    assert validate_timeout(0) is False

def test_sudo():
    assert validate_command('sudo rm', {'rm'}) is False

def test_shell_meta():
    assert validate_command('ls | cat', {'ls'}) is False

def test_empty():
    assert validate_command('', {'ls'}) is False

def test_allowed_rm():
    assert validate_command('rm', {'rm'}) is True

def test_argv_empty():
    assert build_argv('', []) == []
