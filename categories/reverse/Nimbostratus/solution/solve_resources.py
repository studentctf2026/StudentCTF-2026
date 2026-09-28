import argparse
import itertools
import pathlib
import subprocess

import pefile

def extract_rcdata(executable: pathlib.Path, output: pathlib.Path):
    pe = pefile.PE(str(executable), fast_load=False)
    resources = {}
    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_id = type_entry.struct.Id
        if type_id != 10:
            continue
        for name_entry in type_entry.directory.entries:
            resource_id = name_entry.struct.Id
            language_entry = name_entry.directory.entries[0]
            data_rva = language_entry.data.struct.OffsetToData
            data_size = language_entry.data.struct.Size
            data = pe.get_memory_mapped_image()[data_rva:data_rva + data_size]
            resources[resource_id] = bytes(data)
            (output / f"rcdata_{resource_id}.bin").write_bytes(data)
    return resources

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("task", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--upx", type=pathlib.Path)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    resources = extract_rcdata(args.task, args.output)
    print("RCDATA:")
    for resource_id, data in sorted(resources.items()):
        print(f"  id={resource_id:4d} size={len(data):7d}")

    dll_ids = (3179, 4597, 6211)
    for tail in itertools.permutations(dll_ids[1:]):
        order = (dll_ids[0],) + tail
        candidate = bytearray().join(resources[item] for item in order)
        marker = candidate.find(b"UPY!")
        if marker < 0:
            raise RuntimeError("damaged UPX marker was not found")
        candidate[marker + 2] = ord("X")
        candidate_path = args.output / (
            "nimbus_" + "_".join(str(item) for item in order) + ".dll")
        candidate_path.write_bytes(candidate)
        status = "not tested"
        if args.upx:
            result = subprocess.run(
                [str(args.upx), "-t", str(candidate_path)],
                capture_output=True,
                text=True,
            )
            status = "UPX OK" if result.returncode == 0 else "UPX FAIL"
        print(f"DLL order {order}: repaired marker at 0x{marker:X}, {status}")

    parameters = resources[8461]
    (args.output / "Nimbus_parameters_public.txt").write_bytes(parameters)
    print("Parameters written: Nimbus_parameters_public.txt")

if __name__ == "__main__":
    main()
