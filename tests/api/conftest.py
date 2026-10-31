import lzma
import shutil
import struct
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from peat import config

# Layout of the "fat12_mbr" fixture images (see data_files/pillage/make_fixtures.py)
FAT_OFFSET = 64 * 512
FAT_SIZE = 512 * 1024


@pytest.fixture
def pillage_image_path(tmp_path: Path) -> Callable[[str], Path]:
    """Copy a Pillage fixture image to a temporary directory, decompressing ".xz" files."""
    src_dir = Path(__file__).resolve().parent / "data_files" / "pillage"
    dst_dir = tmp_path / "images"
    dst_dir.mkdir(exist_ok=True)

    def _image_path(name: str) -> Path:
        src = src_dir / name
        if name.endswith(".xz"):
            dst = dst_dir / name[:-3]
            dst.write_bytes(lzma.decompress(src.read_bytes()))
        else:
            dst = dst_dir / name
            shutil.copyfile(src, dst)
        return dst

    return _image_path


@pytest.fixture
def fat_partition(pillage_image_path: Callable[[str], Path]) -> bytes:
    """The bytes of the FAT12 filesystem in the "fat12_mbr" images."""
    raw = pillage_image_path("fat12_mbr.img.xz").read_bytes()
    return raw[FAT_OFFSET : FAT_OFFSET + FAT_SIZE]


def mbr_sector(partitions: list[tuple[int, int, int]], boot: int = 0) -> bytes:
    """An MBR (or EBR) sector with (type, start_lba, num_sectors) entries."""
    data = bytearray(512)
    for i, (ptype, start, count) in enumerate(partitions):
        data[446 + i * 16 : 446 + (i + 1) * 16] = struct.pack(
            "<B3sB3sII", boot, b"\xff\xff\xff", ptype, b"\xff\xff\xff", start, count
        )
    data[510:512] = b"\x55\xaa"
    return bytes(data)


def gpt_disk(
    partitions: list[tuple[bytes, int, bytes, str]],
    sector_size: int = 512,
    num_sectors: int = 2048,
    corrupt_header: bool = False,
) -> bytearray:
    """
    A disk with a GUID Partition Table (GPT).

    Args:
        partitions: (type_guid_le, first_lba, data, name) of each partition
    """
    disk = bytearray(num_sectors * sector_size)
    disk[0:512] = mbr_sector([(0xEE, 1, num_sectors - 1)])

    num_entries, entry_size, entries_lba = 128, 128, 2
    table = bytearray(num_entries * entry_size)
    for i, (type_guid, first_lba, data, name) in enumerate(partitions):
        last_lba = first_lba + len(data) // sector_size - 1
        entry = struct.pack("<16s16sQQQ", type_guid, bytes(range(16)), first_lba, last_lba, 0)
        entry += name.encode("utf-16-le").ljust(72, b"\x00")
        table[i * entry_size : (i + 1) * entry_size] = entry
        disk[first_lba * sector_size : first_lba * sector_size + len(data)] = data
    disk[entries_lba * sector_size : entries_lba * sector_size + len(table)] = table

    header = bytearray(
        struct.pack(
            "<8sIIIIQQQQ16sQIII",
            b"EFI PART",
            0x00010000,
            92,
            0,
            0,
            1,
            num_sectors - 1,
            34,
            num_sectors - 34,
            bytes(16),
            entries_lba,
            num_entries,
            entry_size,
            zlib.crc32(table),
        )
    )
    struct.pack_into("<I", header, 16, zlib.crc32(header) ^ (1 if corrupt_header else 0))
    disk[sector_size : sector_size + len(header)] = header
    return disk


@pytest.fixture
def pillage_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, examples_path) -> dict:
    """Pillage configuration from the example config, with a temporary working directory."""
    pillage_conf = yaml.safe_load(examples_path("peat-config.yaml").read_text())["pillage"]
    runtime = config["runtime_configs"]
    monkeypatch.setitem(runtime, "PILLAGE", pillage_conf)
    monkeypatch.setitem(runtime, "PILLAGE_BACKEND", "auto")
    monkeypatch.setitem(runtime, "SUMMARIES_DIR", tmp_path / "summaries")

    work_dir = tmp_path / "work"
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)

    return pillage_conf
