"""
Shell tab completion scripts for the PEAT CLI.

The scripts are generated from the argparse parser built by
:func:`peat.cli_args.build_argument_parser`, so they stay in sync with the
CLI automatically. The generated scripts are static: pressing tab runs the
shell's own completion code and never runs PEAT, which avoids PEAT's import
time on every keypress.

Usage: ``peat completion <bash|zsh|fish|powershell>``

.. note::
   This module should only import from the standard library, so that
   generating completions stays cheap and can't break the rest of PEAT.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field

SHELLS = ("bash", "zsh", "fish", "powershell")

# How to complete an argument's value
FILE = "file"  # files and directories
DIR = "dir"  # directories only
NONE = "none"  # takes a value, but there's nothing to complete (e.g. an IP address)

# metavars or dests that indicate a filesystem path
_FILE_HINTS = {"FILE", "PATH", "PCAPS", "SOURCE", "input_source"}
_DIR_HINTS = {"DIR", "ZEEKDIR", "out_dir", "run_dir"}


@dataclass
class _Arg:
    flags: list[str]  # empty for positional arguments
    help: str
    kind: str | None = None  # FILE, DIR, NONE, or None if no value is taken
    choices: list[str] = field(default_factory=list)
    multi: bool = False  # takes more than one value (nargs "+" or "*")
    repeatable: bool = False  # can be given more than once (e.g. "-VV")
    metavar: str = ""


@dataclass
class _Command:
    name: str
    aliases: list[str]
    help: str
    options: list[_Arg]
    positional: _Arg | None

    @property
    def names(self) -> list[str]:
        return [self.name, *self.aliases]

    @property
    def ident(self) -> str:
        """Name that's safe to use in shell function names."""
        return re.sub(r"\W", "_", self.name)

    def value_options(self) -> list[_Arg]:
        return [o for o in self.options if o.kind is not None]


def _clean_help(text: str | None) -> str:
    """First sentence of a help string, on a single line."""
    if not text or text == argparse.SUPPRESS:
        return ""
    text = " ".join(text.split())
    text = text.split(". ")[0].rstrip(".")
    if len(text) > 100:
        text = text[:97].rstrip() + "..."
    return text


def _arg_kind(action: argparse.Action) -> str | None:
    if action.nargs == 0:
        return None

    # Explicit override, e.g. "parser.add_argument(...).complete = 'dir'"
    explicit = getattr(action, "complete", None)
    if explicit:
        return explicit

    hints = {action.metavar, action.dest}
    if hints & _DIR_HINTS:
        return DIR
    if hints & _FILE_HINTS or getattr(action.type, "__name__", "") == "validate_filepath_arg":
        return FILE
    return NONE


def _convert_action(action: argparse.Action) -> _Arg:
    return _Arg(
        flags=list(action.option_strings),
        help=_clean_help(action.help),
        kind=_arg_kind(action),
        choices=[str(c) for c in action.choices] if action.choices else [],
        multi=action.nargs in ("+", "*"),
        repeatable=isinstance(action, argparse._AppendAction | argparse._CountAction),
        metavar=str(action.metavar or action.dest or ""),
    )


def _subparsers_action(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    raise ValueError("parser has no sub-commands")


def _extract(parser: argparse.ArgumentParser) -> tuple[list[_Arg], list[_Command]]:
    """Get the top-level options and the sub-commands from a parser."""
    top_options = [
        _convert_action(a)
        for a in parser._actions
        if a.option_strings and a.help != argparse.SUPPRESS
    ]

    subparsers = _subparsers_action(parser)
    helps = {a.dest: a.help for a in subparsers._choices_actions}

    # Aliases map to the same parser object as the primary name,
    # and the primary name is always added first.
    by_parser: dict[int, _Command] = {}
    commands: list[_Command] = []
    for name, subparser in subparsers.choices.items():
        if id(subparser) in by_parser:
            by_parser[id(subparser)].aliases.append(name)
            continue

        options = []
        positional = None
        for action in subparser._actions:
            if action.help == argparse.SUPPRESS:
                continue
            if action.option_strings:
                options.append(_convert_action(action))
            elif positional is None:
                positional = _convert_action(action)

        cmd = _Command(
            name=name,
            aliases=[],
            help=_clean_help(helps.get(name)),
            options=options,
            positional=positional,
        )
        by_parser[id(subparser)] = cmd
        commands.append(cmd)

    return top_options, commands


def generate_completion(shell: str, parser: argparse.ArgumentParser, version: str = "") -> str:
    """
    Generate a tab completion script for a shell.

    Args:
        shell: bash, zsh, fish, or powershell
        parser: the PEAT argument parser (from ``cli_args.build_argument_parser()``)
        version: PEAT version, noted in the header of the script

    Returns:
        The completion script's contents
    """
    generators = {
        "bash": _bash,
        "zsh": _zsh,
        "fish": _fish,
        "powershell": _powershell,
    }
    if shell not in generators:
        raise ValueError(f"unsupported shell {shell!r}, expected one of {', '.join(SHELLS)}")

    top_options, commands = _extract(parser)
    header = f'Generated by "peat completion {shell}"'
    if version:
        header += f" (PEAT {version})"
    header += ". Do not edit, regenerate it instead."

    return generators[shell](parser.prog, header, top_options, commands)


# ------------------------------ bash ------------------------------


def _bash(prog: str, header: str, top: list[_Arg], commands: list[_Command]) -> str:
    fn = f"_{prog}"
    all_names = [n for c in commands for n in c.names]
    top_flags = [f for o in top for f in o.flags]

    def complete_value(arg: _Arg) -> str:
        if arg.choices:
            return f'_peat_words "{" ".join(arg.choices)}"'
        if arg.kind == FILE:
            return "_peat_files"
        if arg.kind == DIR:
            return "_peat_dirs"
        return ":"  # takes a value, but there's nothing to complete

    def case_block(indent: str, args: list[_Arg]) -> list[str]:
        out = []
        for arg in args:
            out.append(f"{indent}{'|'.join(arg.flags)}) {complete_value(arg)}; return 0 ;;")
        return out

    lines = [
        f"# bash completion for {prog}",
        f"# {header}",
        "#",
        "# To enable, add this to ~/.bashrc:",
        f'#   eval "$({prog} completion bash)"',
        "# Or save the output to a file that bash-completion loads, e.g.:",
        f"#   {prog} completion bash > ~/.local/share/bash-completion/completions/{prog}",
        "",
        "# NOTE: this avoids 'mapfile', which isn't in bash 3.2 (the default on macOS)",
        "_peat_words() {",
        '    COMPREPLY=( $(compgen -W "$1" -- "$cur") )',
        "}",
        "",
        "_peat_files() {",
        "    local IFS=$'\\n'",
        "    compopt -o filenames 2>/dev/null",
        '    COMPREPLY=( $(compgen -f -- "$cur") )',
        "}",
        "",
        "_peat_dirs() {",
        "    local IFS=$'\\n'",
        "    compopt -o filenames 2>/dev/null",
        '    COMPREPLY=( $(compgen -d -- "$cur") )',
        "}",
        "",
        f"{fn}() {{",
        '    local cur="${COMP_WORDS[COMP_CWORD]}"',
        '    local prev="${COMP_WORDS[COMP_CWORD-1]}"',
        '    local cmd="" cmd_idx=0 last_opt="" i',
        "    COMPREPLY=()",
        "",
        '    # Handle "--option=value" (bash splits on "=")',
        '    if [[ "$cur" == "=" ]]; then',
        '        cur=""',
        '    elif [[ "$prev" == "=" ]] && (( COMP_CWORD > 1 )); then',
        '        prev="${COMP_WORDS[COMP_CWORD-2]}"',
        "    fi",
        "",
        "    # Find the sub-command",
        "    for (( i=1; i < COMP_CWORD; i++ )); do",
        '        case "${COMP_WORDS[i]}" in',
        f'            {"|".join(all_names)}) cmd="${{COMP_WORDS[i]}}"; cmd_idx=$i; break ;;',
        "        esac",
        "    done",
        "",
        '    if [[ -z "$cmd" ]]; then',
        '        if [[ "$cur" == -* ]]; then',
        f'            _peat_words "{" ".join(top_flags)}"',
        "        else",
        f'            _peat_words "{" ".join(all_names)}"',
        "        fi",
        "        return 0",
        "    fi",
        "",
        "    # The closest option before the current word, for options taking multiple values",
        "    for (( i=COMP_CWORD-1; i > cmd_idx; i-- )); do",
        '        if [[ "${COMP_WORDS[i]}" == -?* ]]; then',
        '            last_opt="${COMP_WORDS[i]}"',
        "            break",
        "        fi",
        "    done",
        "",
        '    case "$cmd" in',
    ]

    for cmd in commands:
        value_opts = cmd.value_options()
        multi_opts = [o for o in value_opts if o.multi]
        flags = [f for o in cmd.options for f in o.flags]

        lines += [
            f"        {'|'.join(cmd.names)})",
            '            if [[ "$cur" == -* ]]; then',
            f'                _peat_words "{" ".join(flags)}"',
            "                return 0",
            "            fi",
        ]
        if value_opts:
            lines.append('            case "$prev" in')
            lines.extend(case_block("                ", value_opts))
            lines.append("            esac")
        if multi_opts:
            lines.append('            case "$last_opt" in')
            lines.extend(case_block("                ", multi_opts))
            lines.append("            esac")
        if cmd.positional is not None:
            lines.append(f"            {complete_value(cmd.positional)}")
        lines.append("            ;;")

    lines += [
        "    esac",
        "    return 0",
        "}",
        "",
        f"complete -F {fn} {prog}",
        "",
    ]
    return "\n".join(lines)


# ------------------------------ zsh ------------------------------


def _zsh_quote(text: str) -> str:
    """Quote a string for inclusion in a single-quoted _arguments spec."""
    text = text.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")
    text = text.replace(":", "\\:")
    return text.replace("'", "'\\''")


def _zsh_action(arg: _Arg) -> str:
    if arg.choices:
        return "(" + " ".join(arg.choices) + ")"
    if arg.kind == FILE:
        return "_files"
    if arg.kind == DIR:
        return "_files -/"
    return " "  # no completions, just display the message


def _zsh_option_spec(arg: _Arg) -> str:
    desc = f"[{_zsh_quote(arg.help)}]" if arg.help else ""
    value = ""
    if arg.kind is not None:
        metavar = _zsh_quote(arg.metavar)
        # "*-*" means all following words until the next one starting with "-"
        value = f":{'*-*:' if arg.multi else ''}{metavar}:{_zsh_action(arg)}"

    # Options that can be given more than once aren't excluded after use
    if len(arg.flags) == 1:
        prefix = "*" if arg.repeatable else ""
        return f"'{prefix}{arg.flags[0]}{desc}{value}'"

    prefix = "*" if arg.repeatable else "(" + " ".join(arg.flags) + ")"
    return f"'{prefix}'{{{','.join(arg.flags)}}}'{desc}{value}'"


def _zsh(prog: str, header: str, top: list[_Arg], commands: list[_Command]) -> str:
    lines = [
        f"#compdef {prog}",
        f"# zsh completion for {prog}",
        f"# {header}",
        "#",
        "# To enable, save the output to a file named",
        f'# "_{prog}" in a directory in your $fpath, e.g.:',
        f"#   {prog} completion zsh > ~/.zfunc/_{prog}",
        "# and add this to ~/.zshrc (before compinit is called):",
        "#   fpath=(~/.zfunc $fpath)",
        f'# Or, after compinit in ~/.zshrc: eval "$({prog} completion zsh)"',
        "",
        f"_{prog}() {{",
        '    local curcontext="$curcontext" state line ret=1',
        "    typeset -A opt_args",
        "",
        "    _arguments -C \\",
    ]
    for opt in top:
        desc = _zsh_quote(opt.help)
        if len(opt.flags) == 1:
            lines.append(f"        '(- : *){opt.flags[0]}[{desc}]' \\")
        else:
            lines.append(f"        '(- : *)'{{{','.join(opt.flags)}}}'[{desc}]' \\")
    lines += [
        "        '1: :->command' \\",
        "        '*:: :->args' && ret=0",
        "",
        "    case $state in",
        "        command)",
        "            local -a commands",
        "            commands=(",
    ]
    for cmd in commands:
        for name in cmd.names:
            help_text = cmd.help if name == cmd.name else f"Alias for {cmd.name}"
            desc = help_text.replace("\\", "\\\\").replace(":", "\\:").replace("'", "'\\''")
            lines.append(f"                '{name}:{desc}'")
    lines += [
        "            )",
        f"            _describe -t commands '{prog} command' commands && ret=0",
        "            ;;",
        "        args)",
        '            curcontext="${curcontext%:*:*}:' + prog + '-$words[1]:"',
        "            case $words[1] in",
    ]
    for cmd in commands:
        lines.append(f"                {'|'.join(cmd.names)}) _{prog}_{cmd.ident} && ret=0 ;;")
    lines += [
        "            esac",
        "            ;;",
        "    esac",
        "    return ret",
        "}",
        "",
    ]

    for cmd in commands:
        lines.append(f"_{prog}_{cmd.ident}() {{")
        lines.append("    _arguments -s -S \\")
        for opt in cmd.options:
            lines.append(f"        {_zsh_option_spec(opt)} \\")
        if cmd.positional is not None:
            pos = cmd.positional
            lines.append(f"        '*:{_zsh_quote(pos.metavar)}:{_zsh_action(pos)}'")
        else:
            lines[-1] = lines[-1].removesuffix(" \\")
        lines += ["}", ""]

    lines += [
        f'if [[ "$funcstack[1]" == "_{prog}" ]]; then',
        "    # Autoloaded from $fpath",
        f'    _{prog} "$@"',
        "else",
        "    # Sourced or eval'd",
        f"    compdef _{prog} {prog}",
        "fi",
        "",
    ]
    return "\n".join(lines)


# ------------------------------ fish ------------------------------


def _fish_quote(text: str) -> str:
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _fish_flags(arg: _Arg) -> str:
    parts = []
    for flag in arg.flags:
        if flag.startswith("--"):
            parts.append(f"-l {flag[2:]}")
        elif len(flag) == 2:
            parts.append(f"-s {flag[1:]}")
        else:
            parts.append(f"-o {flag[1:]}")
    return " ".join(parts)


def _fish_value(arg: _Arg) -> str:
    if arg.choices:
        return f"-x -a {_fish_quote(' '.join(arg.choices))}"
    if arg.kind == FILE:
        return "-r -F"
    if arg.kind == DIR:
        return "-x -a '(__fish_complete_directories)'"
    if arg.kind == NONE:
        return "-x"
    return ""


def _fish(prog: str, header: str, top: list[_Arg], commands: list[_Command]) -> str:
    base = f"complete -c {prog}"
    no_cmd = "-n __fish_use_subcommand"
    lines = [
        f"# fish completion for {prog}",
        f"# {header}",
        "#",
        "# To enable, save the output to fish's completions directory:",
        f"#   {prog} completion fish > ~/.config/fish/completions/{prog}.fish",
        "",
        f"{base} -e",
        "# Don't complete file names unless an argument expects them",
        f"{base} -f",
        "",
        "# True if the last option on the command line is one of the arguments,",
        "# for completing the 2nd+ values of options that take multiple values",
        "function __fish_peat_last_opt",
        "    set -l tokens (commandline -opc)",
        "    for tok in $tokens[-1..2]",
        "        if string match -qr -- '^-.' $tok",
        "            contains -- $tok $argv",
        "            return",
        "        end",
        "    end",
        "    return 1",
        "end",
        "",
    ]

    for opt in top:
        line = f"{base} {no_cmd} {_fish_flags(opt)}"
        if opt.help:
            line += f" -d {_fish_quote(opt.help)}"
        lines.append(line)

    for cmd in commands:
        for name in cmd.names:
            help_text = cmd.help if name == cmd.name else f"Alias for {cmd.name}"
            lines.append(f"{base} {no_cmd} -a {name} -d {_fish_quote(help_text)}")
    lines.append("")

    for cmd in commands:
        cond = f"-n {_fish_quote('__fish_seen_subcommand_from ' + ' '.join(cmd.names))}"
        lines.append(f"# {cmd.name}")
        for opt in cmd.options:
            line = f"{base} {cond} {_fish_flags(opt)}"
            value = _fish_value(opt)
            if value:
                line += f" {value}"
            if opt.help:
                line += f" -d {_fish_quote(opt.help)}"
            lines.append(line)
            if opt.multi and opt.kind in (FILE, DIR):
                multi_cond = (
                    f"__fish_seen_subcommand_from {' '.join(cmd.names)}; "
                    f"and __fish_peat_last_opt {' '.join(opt.flags)}"
                )
                value = "-F" if opt.kind == FILE else "-a '(__fish_complete_directories)'"
                lines.append(f"{base} -n {_fish_quote(multi_cond)} {value}")
        pos = cmd.positional
        if pos is not None:
            if pos.choices:
                lines.append(f"{base} {cond} -a {_fish_quote(' '.join(pos.choices))}")
            elif pos.kind == FILE:
                lines.append(f"{base} {cond} -F")
            elif pos.kind == DIR:
                lines.append(f"{base} {cond} -a '(__fish_complete_directories)'")
        lines.append("")

    return "\n".join(lines)


# ------------------------------ PowerShell ------------------------------

# Completion logic, inside the Register-ArgumentCompleter script block
# after the data for the sub-commands has been defined.
_PS_COMPLETER = r"""
    # Text of the words before the one being completed
    $words = @($commandAst.CommandElements |
        Where-Object {
            $_.Extent.EndOffset -lt $cursorPosition -or
            ($_.Extent.EndOffset -eq $cursorPosition -and $wordToComplete -eq '')
        } |
        ForEach-Object { $_.Extent.Text })

    function Complete-Words($map, $type) {
        foreach ($key in $map.Keys) {
            if ($key.StartsWith($wordToComplete, [System.StringComparison]::Ordinal)) {
                [System.Management.Automation.CompletionResult]::new(
                    $key, $key, $type, $map[$key])
            }
        }
    }

    function Complete-Value($kind) {
        $completers = [System.Management.Automation.CompletionCompleters]
        if ($kind -is [array]) {
            foreach ($choice in $kind) {
                if ($choice.StartsWith($wordToComplete, [System.StringComparison]::Ordinal)) {
                    [System.Management.Automation.CompletionResult]::new(
                        $choice, $choice, 'ParameterValue', $choice)
                }
            }
        } elseif ($kind -ceq 'file') {
            $completers::CompleteFilename($wordToComplete)
        } elseif ($kind -ceq 'dir') {
            $completers::CompleteFilename($wordToComplete) |
                Where-Object { $_.ResultType -eq 'ProviderContainer' }
        }
        # 'none': nothing to complete (PowerShell falls back to file names)
    }

    # Find the sub-command
    $cmd = $null
    $cmdIdx = 0
    for ($i = 1; $i -lt $words.Count; $i++) {
        if ($commands.ContainsKey($words[$i])) {
            $cmd = $commands[$words[$i]]
            $cmdIdx = $i
            break
        }
    }

    if ($null -eq $cmd) {
        if ($wordToComplete.StartsWith('-')) {
            return Complete-Words $topOptions 'ParameterName'
        }
        return Complete-Words $topCommands 'ParameterValue'
    }

    if ($wordToComplete.StartsWith('-')) {
        return Complete-Words $cmd.Options 'ParameterName'
    }

    $prev = if ($words.Count -gt $cmdIdx + 1) { $words[-1] } else { $null }
    if ($null -ne $prev -and $cmd.Values.ContainsKey($prev)) {
        return Complete-Value $cmd.Values[$prev]
    }

    # Continue completing an option that takes multiple values
    for ($i = $words.Count - 1; $i -gt $cmdIdx; $i--) {
        if ($words[$i] -clike '-?*') {
            if ($cmd.Multi -ccontains $words[$i]) {
                return Complete-Value $cmd.Values[$words[$i]]
            }
            break
        }
    }

    if ($null -ne $cmd.Positional) {
        return Complete-Value $cmd.Positional
    }
}
"""


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _ps_kind(arg: _Arg) -> str:
    if arg.choices:
        return "@(" + ", ".join(_ps_quote(c) for c in arg.choices) + ")"
    return _ps_quote(arg.kind or NONE)


def _powershell(prog: str, header: str, top: list[_Arg], commands: list[_Command]) -> str:
    lines = [
        f"# PowerShell completion for {prog}",
        f"# {header}",
        "#",
        "# To enable for the current session:",
        f"#   {prog} completion powershell | Out-String | Invoke-Expression",
        "# To enable permanently, save the output to a file and dot-source it from $PROFILE:",
        f'#   {prog} completion powershell > "$HOME\\{prog}_completion.ps1"',
        f'#   Add-Content $PROFILE ". `"$HOME\\{prog}_completion.ps1`""',
        "",
        f"Register-ArgumentCompleter -Native -CommandName {_ps_quote(prog)}, "
        f"{_ps_quote(prog + '.exe')} -ScriptBlock {{",
        "    param($wordToComplete, $commandAst, $cursorPosition)",
        "",
        "    # Option names are case-sensitive (e.g. -i and -I), so use ordinal dictionaries",
        "    function New-Map {",
        "        New-Object 'System.Collections.Generic.Dictionary[string,object]' `",
        "            ([System.StringComparer]::Ordinal)",
        "    }",
        "",
        "    # Top-level options and sub-commands: name => description",
        "    $topOptions = New-Map",
        "    $topCommands = New-Map",
    ]
    for opt in top:
        for flag in opt.flags:
            lines.append(f"    $topOptions[{_ps_quote(flag)}] = {_ps_quote(opt.help or flag)}")
    for cmd in commands:
        for name in cmd.names:
            help_text = cmd.help if name == cmd.name else f"Alias for {cmd.name}"
            lines.append(f"    $topCommands[{_ps_quote(name)}] = {_ps_quote(help_text or name)}")

    lines += [
        "",
        "    # For each sub-command:",
        "    #   Options: option => description",
        "    #   Values: option => 'file', 'dir', 'none', or a list of choices",
        "    #   Multi: options that take more than one value",
        "    #   Positional: completion for positional arguments",
        "    #               ('file', 'dir', a list of choices, or $null)",
        "    $commands = New-Map",
    ]
    for cmd in commands:
        var = f"$c_{cmd.ident}"
        lines.append(f"    {var} = @{{ Options = New-Map; Values = New-Map; Multi = @()")
        lines.append("        Positional = $null }")
        for opt in cmd.options:
            for flag in opt.flags:
                lines.append(
                    f"    {var}.Options[{_ps_quote(flag)}] = {_ps_quote(opt.help or flag)}"
                )
                if opt.kind is not None:
                    lines.append(f"    {var}.Values[{_ps_quote(flag)}] = {_ps_kind(opt)}")
        multi = [f for o in cmd.options if o.multi and o.kind is not None for f in o.flags]
        if multi:
            lines.append(f"    {var}.Multi = @({', '.join(_ps_quote(f) for f in multi)})")
        if cmd.positional is not None:
            lines.append(f"    {var}.Positional = {_ps_kind(cmd.positional)}")
        for name in cmd.names:
            lines.append(f"    $commands[{_ps_quote(name)}] = {var}")

    lines.append(_PS_COMPLETER)
    return "\n".join(lines)
