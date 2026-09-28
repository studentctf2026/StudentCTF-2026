import json
import os

import ida_auto
import ida_entry
import ida_funcs
import ida_hexrays
import ida_loader
import ida_name
import idautils
import idc

def main():
    ida_auto.auto_wait()
    output_json = os.path.abspath(idc.ARGV[1])
    output_text = os.path.abspath(idc.ARGV[2])

    entries = []
    for index in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(index)
        ea = ida_entry.get_entry(ordinal)
        entries.append((ordinal, ea, ida_name.get_name(ea)))

    export = next((item for item in entries if item[0] == 1), entries[0])
    ordinal, export_ea, original_name = export
    ida_name.set_name(export_ea, "NimbusVerify", ida_name.SN_FORCE)
    function = ida_funcs.get_func(export_ea)
    instructions = []
    calls = []
    if function:
        for ea in idautils.Heads(function.start_ea, function.end_ea):
            text = idc.generate_disasm_line(ea, 0) or ""
            instructions.append((ea, text))
            if idc.print_insn_mnem(ea).lower() == "call":
                target = idc.get_operand_value(ea, 0)
                calls.append((ea, target, ida_name.get_name(target), text))

    pseudocode = "Hex-Rays decompilation unavailable"
    try:
        pseudocode = str(ida_hexrays.decompile(export_ea))
    except Exception as error:
        pseudocode = f"Hex-Rays error: {error}"

    result = {
        "export": {
            "ordinal": ordinal,
            "ea": f"0x{export_ea:016X}",
            "original_name": original_name,
            "name": "NimbusVerify",
        },
        "entries": [
            {"ordinal": item[0], "ea": f"0x{item[1]:016X}", "name": item[2]}
            for item in entries
        ],
        "calls": [
            {
                "call_ea": f"0x{item[0]:016X}",
                "target_ea": f"0x{item[1]:016X}",
                "target_name": item[2],
                "text": item[3],
            }
            for item in calls
        ],
        "pseudocode": pseudocode,
    }

    os.makedirs(os.path.dirname(output_json), exist_ok=True)
    with open(output_json, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    with open(output_text, "w", encoding="utf-8") as handle:
        handle.write(f"Export ordinal {ordinal}: 0x{export_ea:016X} NimbusVerify\n\n")
        for ea, text in instructions:
            handle.write(f"0x{ea:016X}  {text}\n")
        handle.write("\n--- Hex-Rays ---\n")
        handle.write(pseudocode)
        handle.write("\n")

    ida_loader.save_database(idc.get_idb_path(), 0)
    idc.qexit(0)

main()
