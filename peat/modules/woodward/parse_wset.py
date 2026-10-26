import io
from pathlib import Path
from typing import Any

from .csharp_reader import JSONEncoder, read_stream


def parse_wset(_file: Any) -> dict[int, str]:
    """
    Parse a Woodward ``.wset`` file (.NET Remoting Binary Format, NRBF).

    Args:
        _file: Path of the file, or the contents of the file

    Returns:
        The JSON-encoded root object of each NRBF stream in the file, by index
    """
    # Determine if valid file type
    if isinstance(_file, Path):
        streamfile = open(_file, "rb")
    elif isinstance(_file, bytes):
        # NOTE: BufferedReader for peek()
        streamfile = io.BufferedReader(io.BytesIO(_file))
    else:
        raise Exception("unknown file type for wset parsing")

    # TODO: use netfleece instead since it seems to be better
    # and produces (relatively) reasonabilty sized files
    # https://gitlab.com/malie-library/netfleece

    json_encoder = JSONEncoder(indent=4)
    output_dict = {}
    i = 0

    with streamfile:
        # Omit first 10 bytes due to Woodward-proprietary header
        streamfile.seek(10)

        while True:
            output_dict[i] = json_encoder.encode(read_stream(streamfile))
            i += 1
            if streamfile.peek(1) == b"":
                break

    # NOTE: the results are saved by the caller (e.g. to the device's
    # output directory), not to files in the current working directory.
    return output_dict
