import io
from pathlib import Path
from typing import Any

from .csharp_reader import MAX_JSON_SIZE, JSONEncoder, read_stream


def parse_wset(_file: Any) -> dict[int, str]:
    """
    Parse a Woodward ``.wset`` file (.NET Remoting Binary Format, NRBF).

    Args:
        _file: Path of the file, or the contents of the file

    Returns:
        The JSON-encoded root object of each NRBF stream in the file, by index

    Raises:
        ValueError: The file is invalid, or the JSON would be larger
            than :data:`~peat.modules.woodward.csharp_reader.MAX_JSON_SIZE`
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

    output_dict = {}
    output_size = 0
    i = 0

    with streamfile:
        # Omit first 10 bytes due to Woodward-proprietary header
        streamfile.seek(10)

        while True:
            # NOTE: objects referenced more than once are only expanded once,
            # and the total size of the JSON of all streams is limited
            json_encoder = JSONEncoder(indent=4, max_size=MAX_JSON_SIZE - output_size)
            output_dict[i] = json_encoder.encode(read_stream(streamfile))
            output_size += len(output_dict[i])
            i += 1
            if streamfile.peek(1) == b"":
                break

    # NOTE: the results are saved by the caller (e.g. to the device's
    # output directory), not to files in the current working directory.
    return output_dict
