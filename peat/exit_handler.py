"""
Manages functions that should be called when PEAT terminates.
These may include state dumps, file permission fixes, and cleanup
of sockets and connections (e.g. cleanly closing connections with
devices that are sensitive to abrupt/unclean TCP terminations).

This is used instead of using :mod:`atexit` directly to allow mocking
for the purposes of unit tests, and to provide better control of what
is run and in what order.
"""

import atexit
from collections.abc import Callable
from typing import Literal

REGISTRY = {
    "CONNECTION": [],
    "FILE": [],
}  # type: dict[str, list[tuple[Callable, tuple]]]


def register(func: Callable, func_type: Literal["CONNECTION", "FILE"], args: tuple = ()) -> None:
    if func_type not in REGISTRY or not callable(func):
        raise ValueError(f"invalid '{func_type}' function '{func.__name__}'")

    REGISTRY[func_type].append((func, args))


def unregister(func: Callable, func_type: Literal["CONNECTION", "FILE"]) -> None:
    if func_type not in REGISTRY or not callable(func):
        raise ValueError(f"invalid '{func_type}' function '{func.__name__}'")

    for i, func_pair in enumerate(REGISTRY[func_type]):
        if func_pair[0] is func:
            del REGISTRY[func_type][i]
            return


def run_handlers() -> None:
    for func_list in REGISTRY.values():
        for func, args in func_list:
            try:
                func(*args)
            except Exception:
                pass


def run_and_unregister(func_type: Literal["CONNECTION", "FILE"]) -> None:
    """
    Run the handlers of a type now, instead of at exit, and unregister them.

    For example, the CLI closes connections with devices before stopping the
    traffic capture, so the connection teardowns are in the capture.
    """
    if func_type not in REGISTRY:
        raise ValueError(f"invalid handler type '{func_type}'")

    handlers = list(REGISTRY[func_type])
    for func, args in handlers:
        unregister(func, func_type)
        try:
            func(*args)
        except Exception:
            pass


atexit.register(run_handlers)
