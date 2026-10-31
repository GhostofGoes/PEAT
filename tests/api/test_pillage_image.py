import hashlib
import os
import sys
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest
import pyvmdk

from peat.api import pillage_image
from peat.api.pillage_image import (
    DiskImage,
    PillageImageError,
    RangeReader,
    UnsupportedImageError,
    VolumeInfo,
    check_library_support,
    detect_image_format,
    find_volumes,
)

from .conftest import FAT_OFFSET, FAT_SIZE, gpt_disk, mbr_sector

# Files in the "fat12_mbr" images, excluding /WINDOWS (see make_fixtures.py)
FAT_FILES = {
    "p1:/project.L5X": b"<RSLogix5000Content/>\r\n",
    "p1:/readme.txt": b"not a device file\r\n",
    "p1:/SEL/SET_ALL.TXT": b"synthetic SEL settings\r\n",
    "p1:/SEL/sub/relay.rdb": b"synthetic SEL RDB\r\n",
    "p1:/Other/set_all.txt": b"second synthetic SEL settings\r\n",
}

BASIC_DATA_GUID = bytes.fromhex("a2a0d0ebe5b9334487c068b6b72699c7")  # EBD0A0A2-...


def read_files(img: DiskImage, **kwargs) -> dict[str, bytes]:
    return {
        str(f): b"".join(f.chunks())
        for f in img.iter_files(excluded_root_dirs=("Windows",), **kwargs)
    }


def media_of(data: bytes) -> pillage_image._Media:
    def _read_at(offset: int, size: int) -> bytes:
        return bytes(data[offset : offset + size])

    return pillage_image._Media(_read_at, len(data), lambda: None)


# --- Format detection ---


@pytest.mark.parametrize(
    ("head", "name", "requested", "expected"),
    [
        (b"EVF\x09\x0d\x0a\xff\x00", "disk.bin", "auto", "ewf"),
        (b"EVF2\r\n\x81\x00", "disk.Ex01", None, "ewf"),
        (b"KDMV", "disk.img", "auto", "vmdk"),
        (b"vhdxfile", "disk", "auto", "vhdx"),
        (pillage_image.VHD_COOKIE, "disk.img", "auto", "vhd"),
        (b"QFI\xfb", "disk.img", "", "qcow2"),  # magic beats the extension
        (b"\x00" * 16, "disk.vmdk", "auto", "vmdk"),  # text descriptors: extension only
        (b"\x00" * 16, "disk.E01", "auto", "ewf"),
        (b"\x00" * 16, "disk.001", "auto", "split_raw"),
        (b"\x00" * 16, "disk.VHDX", "auto", "vhdx"),
        (b"\x00" * 16, "disk.vdi", "auto", "vdi"),
        (b"\x00" * 16, "disk.xyz", "auto", "raw"),
        (b"\x00" * 16, "disk", "auto", "raw"),
        (b"QFI\xfb", "disk.img", "raw", "raw"),  # explicit format wins
        (b"\x00" * 16, "disk.img", "VPC", "vhd"),
        (b"\x00" * 16, "disk.img", "E01", "ewf"),
    ],
)
def test_detect_image_format(tmp_path, head, name, requested, expected):
    pth = tmp_path / name
    pth.write_bytes(head + b"\x00" * 2048)
    assert detect_image_format(pth, requested) == expected


def test_detect_image_format_fixed_vhd_footer(tmp_path):
    pth = tmp_path / "disk.img"
    pth.write_bytes(b"\x00" * 4096 + pillage_image.VHD_COOKIE + b"\x00" * 504)
    assert detect_image_format(pth) == "vhd"


@pytest.mark.parametrize("magic", [b"LVF\x09\x0d\x0a\xff\x00", b"LEF2\r\n\x81\x00"])
def test_detect_image_format_logical_evidence(tmp_path, magic):
    pth = tmp_path / "files.L01"
    pth.write_bytes(magic + b"\x00" * 100)
    with pytest.raises(UnsupportedImageError, match="logical evidence"):
        detect_image_format(pth)


def test_detect_image_format_invalid(tmp_path):
    pth = tmp_path / "disk.img"
    pth.write_bytes(b"\x00" * 512)
    with pytest.raises(UnsupportedImageError, match="unknown image format 'foo'"):
        detect_image_format(pth, "foo")
    with pytest.raises(PillageImageError, match="can't read"):
        detect_image_format(tmp_path / "missing.img")


def test_check_library_support(monkeypatch):
    check_library_support("raw")
    check_library_support("ewf")
    with pytest.raises(UnsupportedImageError, match="without mounting"):
        check_library_support("vdi")

    monkeypatch.setitem(sys.modules, "pyewf", None)
    with pytest.raises(UnsupportedImageError, match="pip install libewf-python"):
        check_library_support("ewf")
    check_library_support("raw")

    for module in pillage_image.FS_MODULES.values():
        monkeypatch.setitem(sys.modules, module, None)
    with pytest.raises(UnsupportedImageError, match="no filesystem modules"):
        check_library_support("raw")


# --- Partitions ---


def test_find_volumes_mbr(pillage_image_path):
    data = pillage_image_path("fat12_mbr.img.xz").read_bytes()
    assert find_volumes(media_of(data)) == [VolumeInfo(1, "mbr", FAT_OFFSET, FAT_SIZE, "0x01")]


def test_find_volumes_mbr_clipped_and_out_of_bounds():
    disk = bytearray(64 * 1024)
    disk[:512] = mbr_sector([(0x83, 8, 1000), (0x07, 10000, 10), (0x00, 2, 4), (0x0C, 9, 0)])
    vols = find_volumes(media_of(disk))
    # Partition 1 is clipped to the end of the disk, 2 starts after the end of the disk
    assert vols == [VolumeInfo(1, "mbr", 8 * 512, len(disk) - 8 * 512, "0x83")]


def test_find_volumes_extended_mbr():
    disk = bytearray(1024 * 512)
    # Primary partition 1, and an extended partition at LBA 100 with 2 logical partitions
    disk[:512] = mbr_sector([(0x0C, 10, 50), (0x05, 100, 900)])
    # EBR 1 at LBA 100: logical partition at LBA 110, next EBR at 100 + 200
    disk[100 * 512 : 101 * 512] = mbr_sector([(0x07, 10, 80), (0x05, 200, 300)])
    # EBR 2 at LBA 300: logical partition at LBA 320, no next EBR
    disk[300 * 512 : 301 * 512] = mbr_sector([(0x83, 20, 100)])
    vols = find_volumes(media_of(disk))
    assert [(v.index, v.offset // 512, v.size // 512, v.type_id) for v in vols] == [
        (1, 10, 50, "0x0c"),
        (5, 110, 80, "0x07"),
        (6, 320, 100, "0x83"),
    ]


def test_find_volumes_ebr_loop_terminates():
    disk = bytearray(512 * 512)
    disk[:512] = mbr_sector([(0x0F, 100, 400)])
    # EBR at LBA 100: logical partition, next EBR at 100 + 200
    disk[100 * 512 : 101 * 512] = mbr_sector([(0x07, 10, 20), (0x05, 200, 50)])
    # EBR at LBA 300: logical partition, next EBR is itself (100 + 200)
    disk[300 * 512 : 301 * 512] = mbr_sector([(0x83, 10, 20), (0x05, 200, 50)])
    assert [v.index for v in find_volumes(media_of(disk))] == [5, 6]


def test_find_volumes_ebr_chain_limit():
    disk = bytearray(1024 * 512)
    disk[:512] = mbr_sector([(0x05, 100, 900)])
    for i in range(300):
        lba = 100 + i * 2
        disk[lba * 512 : (lba + 1) * 512] = mbr_sector([(0x07, 1, 1), (0x05, (i + 1) * 2, 2)])
    vols = find_volumes(media_of(disk))
    assert len(vols) == 128
    assert vols[-1].index == 132


@pytest.mark.parametrize("sector_size", [512, 4096])
def test_find_volumes_gpt(fat_partition, sector_size):
    first_lba = 2048 * 512 // sector_size
    disk = gpt_disk(
        [(BASIC_DATA_GUID, first_lba, fat_partition, "PEAT data")],
        sector_size=sector_size,
        num_sectors=first_lba + len(fat_partition) // sector_size + 64,
    )
    vols = find_volumes(media_of(disk))
    assert vols == [
        VolumeInfo(
            index=1,
            scheme="gpt",
            offset=first_lba * sector_size,
            size=len(fat_partition),
            type_id="ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
            name="PEAT data",
        )
    ]


def test_find_volumes_gpt_bad_crc(fat_partition):
    disk = gpt_disk(
        [(BASIC_DATA_GUID, 2048, fat_partition, "x")], num_sectors=4096, corrupt_header=True
    )
    # Falls back to the protective MBR, which has no usable partitions
    assert find_volumes(media_of(disk)) == []


def test_find_volumes_bare_filesystems(fat_partition, pillage_image_path):
    # A FAT boot sector ends with 55 AA, it must not be parsed as an MBR
    assert find_volumes(media_of(fat_partition)) == [VolumeInfo(0, "none", 0, FAT_SIZE)]
    ext = pillage_image_path("ext4.img.xz").read_bytes()
    assert find_volumes(media_of(ext)) == [VolumeInfo(0, "none", 0, len(ext))]
    ntfs = pillage_image_path("ntfs.img.xz").read_bytes()
    assert find_volumes(media_of(ntfs)) == [VolumeInfo(0, "none", 0, len(ntfs))]


def test_range_reader():
    media = media_of(bytes(range(256)) * 4)
    view = RangeReader(media, 100, 50)
    assert view.get_size() == 50
    assert view.read(10) == bytes(range(100, 110))
    assert view.tell() == 10
    assert view.seek(-5, os.SEEK_END) == 45
    assert view.read() == bytes(range(145, 150))
    assert view.read(10) == b""
    view.seek(2, os.SEEK_SET)
    view.seek(3, os.SEEK_CUR)
    assert view.read(1) == bytes([105])
    with pytest.raises(OSError, match="invalid seek"):
        view.seek(-1)
    # Clipped to the end of the media
    assert RangeReader(media, 1000, 100).get_size() == 24


# --- Reading images ---


def test_raw_fat_mbr(pillage_image_path):
    with DiskImage(pillage_image_path("fat12_mbr.img.xz")) as img:
        assert img.format == "raw"
        assert read_files(img) == FAT_FILES
        assert img.volumes[0].filesystem == "fat"
        summary = img.summary()
    assert summary["media_size"] == FAT_OFFSET + FAT_SIZE
    assert summary["volumes"][0]["type_id"] == "0x01"


def test_excluded_root_dirs_case_insensitive(pillage_image_path):
    with DiskImage(pillage_image_path("fat12_mbr.img.xz")) as img:
        everything = {str(f) for f in img.iter_files()}
        assert "p1:/WINDOWS/skip.rdb" in everything
        # "Windows" in the exclude list matches "WINDOWS" in the image
        assert "p1:/WINDOWS/skip.rdb" not in read_files(img)
        # Only excluded at the root
        no_sel = {str(f) for f in img.iter_files(excluded_root_dirs=["sub", "sel"])}
        assert no_sel == set(FAT_FILES) - {"p1:/SEL/SET_ALL.TXT", "p1:/SEL/sub/relay.rdb"} | {
            "p1:/WINDOWS/skip.rdb"
        }


def test_not_recursive(pillage_image_path):
    with DiskImage(pillage_image_path("fat12_mbr.img.xz")) as img:
        assert set(read_files(img, recursive=False)) == {"p1:/project.L5X", "p1:/readme.txt"}


def test_ewf_matches_raw(pillage_image_path):
    raw = pillage_image_path("fat12_mbr.img.xz")
    with DiskImage(pillage_image_path("fat12_mbr.E01")) as img:
        assert img.format == "ewf"
        assert read_files(img) == FAT_FILES
        assert img.media_size == raw.stat().st_size
        info = img.info
    assert info["segments"] == ["fat12_mbr.E01"]
    assert info["hashes"]["MD5"] == hashlib.md5(raw.read_bytes()).hexdigest()
    assert info["headers"]["case_number"] == "PEAT-CASE-1"


def test_ewf_multiple_segments(pillage_image_path, monkeypatch):
    # Only one segment open at a time: images can have more segments than
    # the open file limit (e.g. 256 on macOS)
    monkeypatch.setattr(pillage_image, "MAX_OPEN_FILES", 1)
    for ext in ("E02", "E03"):
        pillage_image_path(f"fat12_mbr_segments.{ext}.xz")
    with DiskImage(pillage_image_path("fat12_mbr_segments.E01.xz")) as img:
        assert img.info["segments"] == [f"fat12_mbr_segments.E0{i}" for i in (1, 2, 3)]
        assert img.info["headers"]["case_number"] == "PEAT-CASE-2"
        assert img.media_size == 5 * 512 * 1024
        assert read_files(img) == FAT_FILES
        assert img._media.read_at(img.media_size - 512, 1024) == bytes(512)


def test_ewf_missing_segment(pillage_image_path):
    pillage_image_path("fat12_mbr_segments.E03.xz")
    first = pillage_image_path("fat12_mbr_segments.E01.xz")
    with pytest.raises(PillageImageError, match="missing or corrupt segment"):
        DiskImage(first).open()


def test_ewf_truncated(pillage_image_path, tmp_path):
    good = pillage_image_path("fat12_mbr.E01").read_bytes()
    bad = tmp_path / "bad.E01"
    bad.write_bytes(good[: len(good) // 2])
    with pytest.raises(PillageImageError, match=r"EWF|failed to read"):
        DiskImage(bad).open()


@pytest.mark.parametrize(
    ("ext", "fmt"), [("vmdk", "vmdk"), ("vhd", "vhd"), ("vhdx", "vhdx"), ("qcow2", "qcow2")]
)
def test_vm_formats(pillage_image_path, ext, fmt):
    with DiskImage(pillage_image_path(f"fat12_mbr.{ext}.xz")) as img:
        assert img.format == fmt
        assert read_files(img) == FAT_FILES


def test_vm_format_from_magic_with_other_extension(pillage_image_path, tmp_path):
    src = pillage_image_path("fat12_mbr.qcow2.xz")
    renamed = tmp_path / "disk.img"
    src.rename(renamed)
    with DiskImage(renamed) as img:
        assert img.format == "qcow2"
        assert read_files(img) == FAT_FILES


def test_file_pool_limits_open_files(pillage_image_path, monkeypatch):
    monkeypatch.setattr(pillage_image, "MAX_OPEN_FILES", 2)
    raw = pillage_image_path("fat12_mbr.img.xz")
    data = raw.read_bytes()
    directory = raw.parent
    size = len(data) // 64
    paths = []
    for i in range(64):
        pth = directory / f"many.{i + 1:03d}"
        pth.write_bytes(data[i * size : (i + 1) * size])
        paths.append(pth)
    reader = pillage_image._FileReader(paths)
    assert reader.size == len(data)
    assert reader.read_at(0, len(data)) == data
    assert reader.read_at(size - 3, 7) == data[size - 3 : size + 4]
    assert reader._pool.num_open <= 2
    reader.close()
    assert reader._pool.num_open == 0

    with DiskImage(paths[0]) as img:
        assert img.format == "split_raw"
        assert len(img.info["parts"]) == 64
        assert read_files(img) == FAT_FILES


def test_pooled_file_replaced(tmp_path):
    pth = tmp_path / "disk.001"
    pth.write_bytes(b"a" * 100)
    (tmp_path / "disk.002").write_bytes(b"c" * 100)
    pool = pillage_image._FilePool(max_open=1)
    pooled = pillage_image._PooledFile(pool, pth)
    other = pillage_image._PooledFile(pool, tmp_path / "disk.002")
    assert pooled.read(4) == b"aaaa"
    assert other.read(1) == b"c"  # Closes pooled's file, only 1 can be open

    # A file can only be replaced while it's closed (open files can't be replaced on Windows)
    assert pooled not in pool._open
    replacement = tmp_path / "new"
    replacement.write_bytes(b"b" * 100)
    os.replace(replacement, pth)
    with pytest.raises(OSError, match="replaced"):
        pooled.read(4)
    assert pool.num_open == 0  # The replacement isn't left open
    with pytest.raises(OSError, match="not a regular file"):
        pillage_image._PooledFile(pool, tmp_path)


def test_pooled_file_changed(tmp_path):
    # Same device and inode, but a different size. On some filesystems st_ino doesn't
    # identify the file (it's 0, or a reused FAT file ID on Windows), the size still does.
    pth = tmp_path / "disk.001"
    pth.write_bytes(b"a" * 100)
    pool = pillage_image._FilePool(max_open=1)
    pooled = pillage_image._PooledFile(pool, pth)
    assert pooled.read(4) == b"aaaa"
    pool.close()
    with pth.open("ab") as fp:
        fp.write(b"b")
    with pytest.raises(OSError, match="changed"):
        pooled.read(4)
    assert pool.num_open == 0


def test_pooled_file_identity_from_open_file(tmp_path, monkeypatch):
    # On Windows, os.stat() doesn't always get st_dev and st_ino the same way as
    # os.fstat() (e.g. they're 0 if it can only read the file's directory entry)
    pth = tmp_path / "disk.001"
    pth.write_bytes(b"a" * 100)
    real_stat = os.stat

    def _stat(path, *args, **kwargs):
        st = real_stat(path, *args, **kwargs)
        if os.fspath(path) != os.fspath(pth):
            return st
        values = list(st)
        values[1] = values[2] = 0  # st_ino, st_dev
        return os.stat_result(values)

    monkeypatch.setattr(os, "stat", _stat)
    pool = pillage_image._FilePool(max_open=1)
    pooled = pillage_image._PooledFile(pool, pth)
    assert pooled.read(4) == b"aaaa"
    pool.close()
    assert pooled.read(4) == b"aaaa"


def test_split_raw_parts(tmp_path):
    for name in ("disk.000", "disk.001", "disk.002", "other.001"):
        (tmp_path / name).write_bytes(b"x")
    assert pillage_image.split_raw_parts(tmp_path / "disk.000") == [
        tmp_path / f"disk.00{i}" for i in range(3)
    ]
    assert pillage_image.split_raw_parts(tmp_path / "other.001") == [tmp_path / "other.001"]
    for name in ("disk", "disk.img", "disk.\u0661"):
        with pytest.raises(UnsupportedImageError, match="numeric extension"):
            pillage_image.split_raw_parts(tmp_path / name)

    (tmp_path / "disk").write_bytes(bytes(4096))
    with pytest.raises(UnsupportedImageError, match="numeric extension"):
        DiskImage(tmp_path / "disk", "split_raw").open()

    (tmp_path / "dir.001").write_bytes(b"x")
    (tmp_path / "dir.002").mkdir()
    with pytest.raises(PillageImageError, match="not a regular file"):
        pillage_image.split_raw_parts(tmp_path / "dir.001")


def test_split_raw(pillage_image_path):
    raw = pillage_image_path("fat12_mbr.img.xz")
    data = raw.read_bytes()
    third = len(data) // 3
    for i, chunk in enumerate([data[:third], data[third : 2 * third], data[2 * third :]]):
        (raw.parent / f"disk.{i + 1:03d}").write_bytes(chunk)
    with DiskImage(raw.parent / "disk.001") as img:
        assert img.format == "split_raw"
        assert img.info["parts"] == ["disk.001", "disk.002", "disk.003"]
        assert img.media_size == len(data)
        assert read_files(img) == FAT_FILES


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_image_path_can_be_a_symlink(pillage_image_path, tmp_path):
    link = tmp_path / "evidence.E01"
    link.symlink_to(pillage_image_path("fat12_mbr.E01"))
    with DiskImage(link) as img:
        assert img.info["segments"] == ["evidence.E01"]
        assert read_files(img) == FAT_FILES


def test_bare_ext4_symlink_not_followed(pillage_image_path):
    with DiskImage(pillage_image_path("ext4.img.xz")) as img:
        files = read_files(img)
    assert files == {
        "p0:/etc/cfg.txt": b"synthetic SEL cfg\n",
        "p0:/home/user/Projects/plant.L5X": b"<RSLogix5000Content/>\n",
    }
    # /etc/evil.rdb is a symbolic link to /etc/shadow


def test_bare_ntfs(pillage_image_path):
    with DiskImage(pillage_image_path("ntfs.img.xz")) as img:
        files = {str(f): f for f in img.iter_files()}
        data = {name: b"".join(f.chunks()) for name, f in files.items()}
        assert img.volumes[0].filesystem == "ntfs"
    # NTFS metadata files ($MFT, etc.) are skipped. The OneDrive folder has a
    # (cloud files) reparse point, its files are still found. "/Junction" is
    # a junction to C:\Windows, it's never followed (its own index is empty).
    assert data == {
        "p0:/Project.RDB": b"synthetic SEL RDB\r\n",
        "p0:/set_all.txt": b"synthetic SEL settings\r\n",
        "p0:/SEL/hardlink.rdb": b"synthetic SEL RDB\r\n",
        "p0:/SEL/sub/cser.txt": b"synthetic SEL CSER\r\n",
        "p0:/Users/eng/OneDrive/Projects/plant.L5X": b"synthetic L5X in OneDrive\r\n",
    }
    # Hard links have the same data ID (MFT entry), other files don't
    assert files["p0:/SEL/hardlink.rdb"].data_id == files["p0:/Project.RDB"].data_id
    assert len({f.data_id for f in files.values()}) == 4


def test_fat_data_ids(pillage_image_path):
    with DiskImage(pillage_image_path("fat12_mbr.img.xz")) as img:
        data_ids = [f.data_id for f in img.iter_files()]
    assert None not in data_ids
    assert len(set(data_ids)) == len(data_ids)


def test_gpt_image(fat_partition, tmp_path):
    pth = tmp_path / "gpt.img"
    pth.write_bytes(gpt_disk([(BASIC_DATA_GUID, 2048, fat_partition, "data")], num_sectors=4096))
    with DiskImage(pth) as img:
        assert read_files(img) == FAT_FILES
        assert img.volumes[0].scheme == "gpt"


def test_unreadable_partitions_skipped(fat_partition, tmp_path):
    bitlocker = bytearray(64 * 1024)
    bitlocker[3:11] = b"-FVE-FS-"
    bitlocker[510:512] = b"\x55\xaa"
    xfs = b"XFSB" + bytes(64 * 1024 - 4)
    disk = bytearray(mbr_sector([(0x07, 64, 128), (0x83, 192, 128), (0x01, 320, 1024)]))
    disk += bytes(63 * 512) + bitlocker + xfs + fat_partition
    pth = tmp_path / "disk.img"
    pth.write_bytes(disk)
    with DiskImage(pth) as img:
        files = {k.replace("p3:", "p1:") for k in read_files(img)}
        assert "BitLocker" in img.volumes[0].error
        assert "XFS" in img.volumes[1].error
        assert img.volumes[2].filesystem == "fat"
    assert files == set(FAT_FILES)


def test_no_supported_filesystem(tmp_path):
    pth = tmp_path / "zeros.img"
    pth.write_bytes(bytes(1024 * 1024))
    with pytest.raises(UnsupportedImageError, match="no supported filesystems found"):
        DiskImage(pth).open()


# --- Refusals ---


def write_vmdk_descriptor(
    directory: Path,
    extents: list[tuple[int, str]],
    create_type: str = "twoGbMaxExtentFlat",
    extent_type: str = "FLAT",
    parent_cid: str = "ffffffff",
) -> Path:
    offset = " 0" if extent_type == "FLAT" else ""
    lines = "".join(f'RW {sectors} {extent_type} "{name}"{offset}\n' for sectors, name in extents)
    desc = (
        f"# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID={parent_cid}\n"
        f'createType="{create_type}"\n\n# Extent description\n'
        f"{lines}\n# The Disk Data Base\n#DDB\n\n"
        'ddb.virtualHWVersion = "4"\n'
    )
    pth = directory / "disk.vmdk"
    pth.write_text(desc)
    return pth


def test_vmdk_flat_extents(pillage_image_path):
    raw = pillage_image_path("fat12_mbr.img.xz")
    data = raw.read_bytes()
    half = len(data) // 2
    (raw.parent / "disk-f001.vmdk").write_bytes(data[:half])
    (raw.parent / "disk-f002.vmdk").write_bytes(data[half:])
    desc = write_vmdk_descriptor(
        raw.parent, [(half // 512, "disk-f001.vmdk"), (half // 512, "disk-f002.vmdk")]
    )
    with DiskImage(desc) as img:
        assert img.info["extents"] == ["disk-f001.vmdk", "disk-f002.vmdk"]
        assert read_files(img) == FAT_FILES


def test_vmdk_esxi_vmfs_extent(pillage_image_path):
    # VMware ESXi: createType "vmfs", with a "VMFS" extent (disk-flat.vmdk)
    raw = pillage_image_path("fat12_mbr.img.xz")
    raw.rename(raw.parent / "disk-flat.vmdk")
    desc = write_vmdk_descriptor(
        raw.parent,
        [(len((raw.parent / "disk-flat.vmdk").read_bytes()) // 512, "disk-flat.vmdk")],
        create_type="vmfs",
        extent_type="VMFS",
    )
    with DiskImage(desc) as img:
        assert img.info["extents"] == ["disk-flat.vmdk"]
        assert read_files(img) == FAT_FILES


@pytest.mark.parametrize("decoy", [False, True])
def test_vmdk_renamed_sparse(pillage_image_path, decoy):
    # A monolithicSparse VMDK (made by qemu-img) names itself "fat12_mbr.vmdk"
    # in its embedded descriptor, which is wrong after it's renamed
    original = pillage_image_path("fat12_mbr.vmdk.xz")
    renamed = original.rename(original.parent / "case42_EWS.vmdk")
    if decoy:
        # Another file with the original name must not be read instead
        original.write_bytes(pillage_image_path("ntfs.img.xz").read_bytes())
    with DiskImage(renamed) as img:
        assert img.info["extents"] == ["case42_EWS.vmdk"]
        assert read_files(img) == FAT_FILES


@pytest.mark.parametrize(
    ("create_type", "extent", "match"),
    [
        ("fullDevice", 'FLAT "/dev/sda" 0', "physical device"),
        ("partitionedDevice", 'FLAT "/dev/sda" 0', "physical device"),
        ("vmfsRawDeviceMap", 'VMFSRDM "disk-rdm.vmdk"', "physical device"),
        ("vmfsPassthroughRawDeviceMap", 'VMFSRDM "disk-rdm.vmdk"', "physical device"),
        ("monolithicFlat", "ZERO", "unsupported extent type"),
        ("custom", 'VMFSRAW "disk-raw.vmdk"', "unsupported extent type"),
    ],
)
def test_vmdk_raw_devices_refused(tmp_path, create_type, extent, match):
    pth = tmp_path / "disk.vmdk"
    pth.write_text(
        "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n"
        f'createType="{create_type}"\n\n# Extent description\nRW 1088 {extent}\n\n'
        '# The Disk Data Base\n#DDB\n\nddb.virtualHWVersion = "4"\n'
    )
    (tmp_path / "disk-rdm.vmdk").write_bytes(bytes(1088 * 512))
    with pytest.raises(UnsupportedImageError, match=match):
        DiskImage(pth).open()


def test_vmdk_snapshot_refused(pillage_image_path):
    raw = pillage_image_path("fat12_mbr.img.xz")
    desc = write_vmdk_descriptor(
        raw.parent, [(len(raw.read_bytes()) // 512, raw.name)], parent_cid="12345678"
    )
    with pytest.raises(UnsupportedImageError, match="snapshot"):
        DiskImage(desc).open()


@pytest.mark.parametrize(
    ("name", "head"),
    [
        ("bad.vhdx", b"vhdxfile"),
        ("bad.vhd", pillage_image.VHD_COOKIE),
        ("bad.qcow2", b"QFI\xfb"),
        ("bad.vmdk", b"KDMV"),
        ("bad2.vmdk", b"# Disk DescriptorFile\ngarbage\n\x00\xff"),
        ("bad.E01", b"EVF\x09\x0d\x0a\xff\x00"),
    ],
)
def test_corrupt_containers(tmp_path, name, head):
    # The real error is reported, not an error from closing the image
    pth = tmp_path / name
    pth.write_bytes(head + bytes(range(256)) * 64)
    with pytest.raises(PillageImageError, match="failed to open") as exc_info:
        DiskImage(pth).open()
    assert not isinstance(exc_info.value, UnsupportedImageError)


@pytest.mark.parametrize("extent", ["../outside.img", "/etc/passwd", "sub/x.img", "C:x.img"])
def test_vmdk_extent_outside_directory_refused(tmp_path, extent):
    images = tmp_path / "images"
    images.mkdir()
    (tmp_path / "outside.img").write_bytes(bytes(4096))
    desc = write_vmdk_descriptor(images, [(8, extent)])
    with pytest.raises(PillageImageError, match="refusing VMDK extent"):
        DiskImage(desc).open()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_vmdk_extent_symlink_refused(tmp_path):
    (tmp_path / "target.img").write_bytes(bytes(4096))
    (tmp_path / "link.img").symlink_to(tmp_path / "target.img")
    desc = write_vmdk_descriptor(tmp_path, [(8, "link.img")])
    with pytest.raises(PillageImageError, match="not a regular file"):
        DiskImage(desc).open()


class FakeImage:
    """Stand-in for libyal image objects (pyvhdi.file, pyqcow.file, pyvmdk.handle)."""

    def __init__(self, **attrs) -> None:
        self.closed = False
        self.__dict__.update(attrs)

    def open(self, _path: str) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    def is_locked(self) -> bool:
        return self.__dict__.get("locked", False)


def fake_import(monkeypatch, name: str, module: object) -> None:
    real_import = pillage_image._import

    def _import(mod_name: str):
        return module if mod_name == name else real_import(mod_name)

    monkeypatch.setattr(pillage_image, "_import", _import)


@pytest.mark.parametrize(
    ("attrs", "match"),
    [
        ({"backing_filename": "/etc/base.qcow2"}, "backing file"),
        ({"backing_filename": None, "locked": True}, "encrypted"),
    ],
)
def test_qcow2_refused(monkeypatch, tmp_path, attrs, match):
    fake = FakeImage(**attrs)
    fake_import(monkeypatch, "pyqcow", SimpleNamespace(file=lambda: fake))
    pth = tmp_path / "disk.qcow2"
    pth.write_bytes(b"QFI\xfb" + bytes(1024))
    with pytest.raises(UnsupportedImageError, match=match):
        DiskImage(pth).open()
    assert fake.closed


def test_image_metadata_escaped_in_messages(monkeypatch, tmp_path):
    # e.g. a terminal escape sequence that sets the window title and clears the screen
    fake = FakeImage(backing_filename="x\x1b]0;PWNED\x07\x1b[2Jbase.img\x9b")
    fake_import(monkeypatch, "pyqcow", SimpleNamespace(file=lambda: fake))
    pth = tmp_path / "disk.qcow2"
    pth.write_bytes(b"QFI\xfb" + bytes(1024))
    with pytest.raises(UnsupportedImageError) as exc_info:
        DiskImage(pth).open()
    msg = str(exc_info.value)
    assert "x\\x1b]0;PWNED\\x07\\x1b[2Jbase.img\\x9b" in msg
    assert not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in msg)

    with pytest.raises(PillageImageError) as exc_info:
        pillage_image._regular_sibling(pth, "a\x1b[31m/b", "VMDK extent")
    assert "\x1b" not in str(exc_info.value)
    assert pillage_image._err(OSError("bad\x1b[2J\n  name")) == "bad\\x1b[2J name"
    assert pillage_image._safe_text("a" * 500, max_len=10) == "aaaaaaa..."


def test_vhd_differential_refused(monkeypatch, tmp_path):
    disk_types = SimpleNamespace(FIXED=2, DYNAMIC=3, DIFFERENTIAL=4)
    fake = FakeImage(disk_type=4, parent_filename="parent.vhdx")
    fake_import(monkeypatch, "pyvhdi", SimpleNamespace(file=lambda: fake, disk_types=disk_types))
    pth = tmp_path / "child.avhdx"
    pth.write_bytes(b"vhdxfile" + bytes(1024))
    with pytest.raises(UnsupportedImageError, match="differencing disk"):
        DiskImage(pth).open()
    assert fake.closed


@pytest.mark.parametrize(
    ("attrs", "match"),
    [
        (
            {"disk_type": pyvmdk.disk_types.MONOLITHIC_SPARSE, "parent_content_identifier": 1},
            "snapshot",
        ),
        (
            {"disk_type": pyvmdk.disk_types.DEVICE, "parent_content_identifier": None},
            "physical device",
        ),
    ],
)
def test_vmdk_refused(monkeypatch, tmp_path, attrs, match):
    fake = FakeImage(parent_filename="parent.vmdk", **attrs)
    fake_import(
        monkeypatch, "pyvmdk", SimpleNamespace(handle=lambda: fake, disk_types=pyvmdk.disk_types)
    )
    pth = tmp_path / "disk.vmdk"
    pth.write_bytes(b"KDMV" + bytes(1024))
    with pytest.raises(UnsupportedImageError, match=match):
        DiskImage(pth).open()
    assert fake.closed


def test_regular_sibling(tmp_path):
    image = tmp_path / "disk.E01"
    image.write_bytes(b"")
    (tmp_path / "disk.E02").write_bytes(b"")
    (tmp_path / "subdir").mkdir()
    assert pillage_image._regular_sibling(image, "disk.E02", "EWF segment") == (
        tmp_path / "disk.E02"
    )
    for bad in ["", ".", "..", "../disk.E02", "a\\b", "a/b", "x\x00"]:
        with pytest.raises(PillageImageError, match="refusing"):
            pillage_image._regular_sibling(image, bad, "EWF segment")
    with pytest.raises(PillageImageError, match="not a regular file"):
        pillage_image._regular_sibling(image, "subdir", "EWF segment")
    with pytest.raises(PillageImageError, match="missing"):
        pillage_image._regular_sibling(image, "disk.E03", "EWF segment")


# --- Walking ---


class FakeEntry:
    def __init__(self, name, ident, children=None, size=0, data=b"") -> None:
        self.name = name
        self.identifier = ident
        self.size = size or len(data)
        self.data = data
        self.children = children
        self.file_attribute_flags = 0x10 if children is not None else 0x20
        self.number_of_extents = 0

    @property
    def sub_file_entries(self):
        return iter(self.children or [])

    def read_buffer_at_offset(self, size, offset):
        return self.data[offset : offset + size]


def test_walk_directory_loop_guard():
    loop = FakeEntry("loop", 1, [])
    root = FakeEntry("", 1, [loop, FakeEntry("a.txt", 2, data=b"abc")])
    loop.children = [root]  # Points back at the root (same identifier)
    fs = SimpleNamespace(get_root_directory=lambda: root)
    files = list(pillage_image.walk_filesystem(pillage_image._FatAdapter(), fs, 1))
    assert [(str(f), b"".join(f.chunks())) for f in files] == [("p1:/a.txt", b"abc")]


def test_walk_unsafe_names_and_listing_errors():
    class BrokenDir(FakeEntry):
        @property
        def sub_file_entries(self):
            raise OSError("corrupt directory")

    root = FakeEntry(
        "",
        1,
        [
            FakeEntry("..", 2, data=b"x"),
            FakeEntry("a/../b.txt", 3, data=b"x"),
            FakeEntry("evil\x1b[31m.txt", 4, data=b"x"),
            BrokenDir("broken", 5, []),
        ],
    )
    fs = SimpleNamespace(get_root_directory=lambda: root)
    paths = [f.path for f in pillage_image.walk_filesystem(pillage_image._FatAdapter(), fs, 1)]
    assert paths == [PurePosixPath("/a_.._b.txt"), PurePosixPath("/evil_[31m.txt")]


def test_image_file_chunks_stops_on_short_read():
    entry = FakeEntry("f", 1, size=100, data=b"abc")
    img_file = pillage_image.ImageFile(1, PurePosixPath("/f"), 100, entry)
    assert b"".join(img_file.chunks(chunk_size=2)) == b"abc"
