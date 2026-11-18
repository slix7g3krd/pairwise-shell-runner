"""Hardened shell-command runner helpers.

Security model:
- No shell: commands are built as argv arrays, never concatenated strings,
  so shell metacharacters (; | & $() ` newlines) in arguments are inert data.
- Exact command whitelist: the command must match an allowed entry exactly,
  no prefix matching, no sudo wrappers, no pipelines.
- Environment whitelist: only explicitly allowed variables are passed to the
  child process; PATH / LD_PRELOAD and friends cannot be injected.
- Mandatory timeout: 0 / None / negative timeouts are rejected.
- Output truncation: captured output is bounded to a maximum length.
"""

# Shell metacharacters that must never reach a command line.
SHELL_METACHARS = set(';&|$`<>(){}[]!#~*?\\\n\r')


def build_argv(command, args):
    """Build an argv array from a command and its argument list.

    Arguments are passed through as-is: with shell=False they are literal
    data, so metacharacters and newlines cannot inject extra commands.
    Returns [] for an empty command.
    """
    if not command:
        return []
    return [command] + list(args or [])


def validate_command(command, allowed):
    """Return True only if `command` exactly matches the whitelist.

    Rejects empty commands, prefix matches ('ls; rm' vs 'ls'), sudo
    wrappers, pipelines and anything containing shell metacharacters.
    """
    if not command or not isinstance(command, str):
        return False
    if any(ch in SHELL_METACHARS for ch in command):
        return False
    return command in allowed


def sanitize_env(env, allowed):
    """Keep only whitelisted environment variables."""
    if not env:
        return {}
    return {k: v for k, v in env.items() if k in allowed}


def truncate_output(output, max_len):
    """Bound output to `max_len` characters, appending '...' if truncated."""
    if output is None:
        return ''
    if max_len is None or max_len < 0:
        max_len = 0
    if len(output) <= max_len:
        return output
    if max_len <= 3:
        return output[:max_len]
    return output[:max_len - 3] + '...'


def validate_timeout(timeout):
    """A timeout must be a positive finite number; 0/None means 'no limit'
    and is rejected."""
    if timeout is None or isinstance(timeout, bool):
        return False
    if not isinstance(timeout, (int, float)):
        return False
    return timeout > 0
