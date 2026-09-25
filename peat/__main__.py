#!/usr/bin/env python3

import sys
import timeit

# Sample here to capture how long the imports take
START_TIME = timeit.default_timer()

from peat import __version__, cli_args, cli_main  # noqa: E402


def main():
    """Command line entry point for PEAT."""
    try:
        args = cli_args.parse_peat_arguments(__version__)
        args_dict: dict = vars(args)  # Convert argparse Namespace object to a dict

        # Print shell completion script and exit, without initializing PEAT
        if args_dict.get("func") == "completion":
            from peat.cli_completion import generate_completion

            parser = cli_args.build_argument_parser(version=__version__)
            print(  # noqa: T201
                generate_completion(args.shell, parser, __version__), end="", flush=True
            )
            return

        cli_main.run_peat(args_dict, START_TIME)
    except KeyboardInterrupt:
        print(  # noqa: T201
            "\n** USER TERMINATED EXECUTION **", file=sys.stderr, flush=True
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
