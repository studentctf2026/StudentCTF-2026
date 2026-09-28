import json
import os

import ida_auto
import ida_entry
import ida_funcs
import ida_name
import ida_nalt
import ida_loader
import idaapi
import idautils
import idc

TARGET_IMPORTS = {
    "FindResourceW",
    "LoadResource",
    "SizeofResource",
    "LoadLibraryW",
    "GetProcAddress",
    "BCryptHashData",
    "BCryptFinishHash",
    "MessageBoxW",
}

def collect_imports():
    imports = {}

    def callback(ea, name, ordinal):
        if name:
            imports[name] = ea
        return True

    for module_index in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(module_index, callback)
    return imports

def instruction_window(ea, before=10, after=24):
    start = ea
    for _ in range(before):
        previous = idc.prev_head(start)
        if previous == idc.BADADDR:
            break
        start = previous
    rows = []
    current = start
    for _ in range(before + after + 1):
        if current == idc.BADADDR:
            break
        rows.append({
            "ea": current,
            "address": f"0x{current:016X}",
            "text": idc.generate_disasm_line(current, 0) or "",
            "focus": current == ea,
        })
        current = idc.next_head(current)
    return rows

def main():
    ida_auto.auto_wait()
    output_json = os.path.abspath(idc.ARGV[1])
    output_asm = os.path.abspath(idc.ARGV[2])
    imports = collect_imports()

    entries = []
    for index in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(index)
        ea = ida_entry.get_entry(ordinal)
        entries.append({
            "ordinal": ordinal,
            "ea": ea,
            "address": f"0x{ea:016X}",
            "name": ida_name.get_name(ea),
        })

    targets = []
    seen = set()
    for import_name in sorted(TARGET_IMPORTS):
        import_ea = imports.get(import_name)
        if import_ea is None:
            continue
        for xref in idautils.XrefsTo(import_ea):
            function = ida_funcs.get_func(xref.frm)
            function_start = function.start_ea if function else idc.BADADDR
            key = (import_name, xref.frm)
            if key in seen:
                continue
            seen.add(key)
            targets.append({
                "import": import_name,
                "import_ea": f"0x{import_ea:016X}",
                "xref_ea": f"0x{xref.frm:016X}",
                "function_ea": f"0x{function_start:016X}" if function else None,
                "function_name": ida_name.get_name(function_start) if function else None,
                "instructions": instruction_window(xref.frm),
            })

    semantic_names = {
        0x140001910: "load_rcdata",
        0x1400021D0: "submit_password_gui",
        0x1400024D0: "unpack_archive",
        0x140003550: "verify_password_obfuscated",
    }
    for ea, name in semantic_names.items():
        ida_name.set_name(ea, name, ida_name.SN_FORCE)

    call_graph = {}
    for function_ea, function_name in semantic_names.items():
        function = ida_funcs.get_func(function_ea)
        calls = []
        if function:
            for head in idautils.Heads(function.start_ea, function.end_ea):
                if idc.print_insn_mnem(head).lower() != "call":
                    continue
                target = idc.get_operand_value(head, 0)
                calls.append({
                    "call_ea": f"0x{head:016X}",
                    "target_ea": f"0x{target:016X}",
                    "target_name": ida_name.get_name(target),
                    "text": idc.generate_disasm_line(head, 0) or "",
                })
        call_graph[function_name] = calls

    result = {
        "input": idaapi.get_input_file_path(),
        "imagebase": f"0x{idaapi.get_imagebase():016X}",
        "entries": entries,
        "imports": {
            name: f"0x{ea:016X}"
            for name, ea in sorted(imports.items())
            if name in TARGET_IMPORTS
        },
        "targets": targets,
        "call_graph": call_graph,
    }

    os.makedirs(os.path.dirname(output_json), exist_ok=True)
    with open(output_json, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)

    with open(output_asm, "w", encoding="utf-8") as handle:
        handle.write(f"Input: {result['input']}\n")
        handle.write(f"Image base: {result['imagebase']}\n\n")
        for target in targets:
            handle.write(
                f"[{target['import']}] xref={target['xref_ea']} "
                f"function={target['function_name']} ({target['function_ea']})\n"
            )
            for row in target["instructions"]:
                marker = "=>" if row["focus"] else "  "
                handle.write(f"{marker} {row['address']}  {row['text']}\n")
            handle.write("\n")

    ida_loader.save_database(idc.get_idb_path(), 0)
    idc.qexit(0)

main()
