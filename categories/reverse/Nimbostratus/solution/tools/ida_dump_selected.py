import json
import os

import ida_auto
import ida_funcs
import ida_name
import idc

WINDOWS = {
    "resource_loader": (0x14000193C, 26),
    "tigress_dispatch": (0x1400035D0, 42),
    "dll_loader": (0x140003B84, 34),
    "password_gate": (0x140002350, 58),
    "archive_unpack": (0x1400025D0, 46),
}

def dump(start, count):
    rows = []
    ea = start
    for _ in range(count):
        rows.append({
            "ea": f"0x{ea:016X}",
            "function": ida_name.get_name(ida_funcs.get_func(ea).start_ea)
            if ida_funcs.get_func(ea) else "",
            "text": idc.generate_disasm_line(ea, 0) or "",
        })
        ea = idc.next_head(ea)
    return rows

ida_auto.auto_wait()
output = os.path.abspath(idc.ARGV[1])
with open(output, "w", encoding="utf-8") as handle:
    json.dump(
        {name: dump(start, count) for name, (start, count) in WINDOWS.items()},
        handle,
        ensure_ascii=False,
        indent=2,
    )
idc.qexit(0)
