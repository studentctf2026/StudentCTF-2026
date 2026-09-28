import json
import pathlib
import textwrap

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "writeup" / "images"
FINAL_OUTPUT = ROOT / "Итого" / "images"
SELECTED = json.loads((ROOT / "writeup" / "ida" / "selected.json").read_text(encoding="utf-8"))
ANALYSIS = json.loads((ROOT / "writeup" / "ida" / "analysis.json").read_text(encoding="utf-8"))
NIMBUS = json.loads((ROOT / "writeup" / "ida" / "nimbus_analysis.json").read_text(encoding="utf-8"))
MANIFEST = json.loads((ROOT / "build" / "generated" / "resource_manifest.json").read_text(encoding="utf-8-sig"))

FONT_UI = "C:/Windows/Fonts/segoeui.ttf"
FONT_BOLD = "C:/Windows/Fonts/seguisb.ttf"
FONT_MONO = "C:/Windows/Fonts/CascadiaMono.ttf"

BG = "#0d1117"
PANEL = "#161b22"
PANEL_2 = "#1f2630"
TEXT = "#e6edf3"
MUTED = "#8b949e"
BLUE = "#58a6ff"
CYAN = "#39c5cf"
GREEN = "#3fb950"
YELLOW = "#d29922"
ORANGE = "#f0883e"
RED = "#f85149"
PURPLE = "#bc8cff"
BORDER = "#30363d"

def font(size, bold=False, mono=False):
    path = FONT_MONO if mono else (FONT_BOLD if bold else FONT_UI)
    return ImageFont.truetype(path, size)

def canvas(title, subtitle, width=1800, height=1050):
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, width, 84), fill="#101820")
    draw.text((42, 18), title, font=font(29, bold=True), fill=TEXT)
    draw.text((44, 55), subtitle, font=font(17), fill=MUTED)
    return image, draw

def round_box(draw, xy, fill=PANEL, outline=BORDER, radius=16, width=2):
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)

def wrapped(draw, text, xy, max_chars, size=21, fill=TEXT, bold=False, spacing=7):
    lines = []
    for paragraph in text.split("\n"):
        lines.extend(textwrap.wrap(paragraph, width=max_chars) or [""])
    draw.multiline_text(xy, "\n".join(lines), font=font(size, bold=bold), fill=fill, spacing=spacing)
    return len(lines)

def arrow(draw, start, end, color=BLUE, width=5):
    draw.line((start, end), fill=color, width=width)
    x, y = end
    draw.polygon([(x, y), (x - 16, y - 9), (x - 16, y + 9)], fill=color)

def ida_frame(draw, xy, function_name, rows, highlights=None, compact=False):
    highlights = highlights or {}
    x1, y1, x2, y2 = xy
    round_box(draw, xy, fill="#11161d", outline="#414a56", radius=10)
    draw.rectangle((x1, y1, x2, y1 + 38), fill="#2b313a")
    draw.text((x1 + 14, y1 + 7), "IDA View-A", font=font(17, bold=True), fill=TEXT)
    draw.rectangle((x1, y1 + 38, x2, y1 + 72), fill="#191f27")
    draw.text((x1 + 15, y1 + 45), function_name, font=font(16, mono=True), fill=CYAN)
    line_height = 28 if compact else 31
    code_font = font(16 if compact else 17, mono=True)
    y = y1 + 82
    for row in rows:
        if y + line_height > y2 - 8:
            break
        address = row["ea"].replace("0x00000001", "")
        instruction = row["text"]
        line_color = highlights.get(row["ea"])
        if line_color:
            draw.rounded_rectangle((x1 + 8, y - 2, x2 - 8, y + line_height - 3), radius=5, fill=line_color)
        draw.text((x1 + 16, y), address, font=code_font, fill=MUTED)
        mnemonic, _, operands = instruction.partition(" ")
        max_operand_chars = max(18, int((x2 - (x1 + 292)) / (9.8 if compact else 10.4)))
        operands = operands.strip()
        if len(operands) > max_operand_chars:
            operands = operands[:max_operand_chars - 1] + "…"
        draw.text((x1 + 205, y), mnemonic, font=code_font, fill=CYAN)
        draw.text((x1 + 280, y), operands, font=code_font, fill=TEXT)
        y += line_height

def save(image, name):
    OUTPUT.mkdir(parents=True, exist_ok=True)
    FINAL_OUTPUT.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT / name, "PNG", optimize=True)
    image.save(FINAL_OUTPUT / name, "PNG", optimize=True)

def architecture():
    image, draw = canvas(
        "Устройство CTF SFX",
        "PE-ресурсы, проверка Nimbus и независимая криптографическая защита архива",
    )
    round_box(draw, (55, 125, 420, 900), fill="#111821", outline=BLUE)
    draw.text((82, 150), "task.exe / .rsrc", font=font(28, bold=True), fill=BLUE)
    resources = [
        ("3179", "DLL: часть 1", CYAN),
        ("4597", "DLL: часть ?", CYAN),
        ("6211", "DLL: часть ?", CYAN),
        ("8461", "Nimbus params", PURPLE),
        ("7331 · 2843", "архив: части 1–2", GREEN),
        ("9157 · 5629", "архив: части 3–4", GREEN),
    ]
    y = 218
    for resource_id, label, color in resources:
        round_box(draw, (82, y, 392, y + 82), fill=PANEL_2, outline=color, radius=10)
        draw.text((100, y + 12), resource_id, font=font(21, bold=True, mono=True), fill=color)
        draw.text((100, y + 45), label, font=font(18), fill=TEXT)
        y += 100

    arrow(draw, (430, 360), (520, 360), BLUE)
    round_box(draw, (530, 125, 1115, 515), fill=PANEL, outline=BORDER)
    draw.text((560, 150), "Путь выполнения", font=font(27, bold=True), fill=TEXT)
    runtime = [
        ("1", "Собрать DLL: 3179 + две перестановки"),
        ("2", "SHA-256 выбирает правильный порядок"),
        ("3", "LoadLibraryW → ordinal 1 NimbusVerify"),
        ("4", "verified == 1 и тот же пароль → unpack"),
        ("5", "SHA-256 архива + хеш каждого файла"),
    ]
    y = 205
    for number, label in runtime:
        draw.ellipse((558, y, 594, y + 36), fill=BLUE)
        draw.text((570, y + 4), number, font=font(17, bold=True), fill=BG, anchor="mm")
        wrapped(draw, label, (610, y - 1), 43, size=20)
        y += 58

    round_box(draw, (530, 550, 1115, 900), fill=PANEL, outline=ORANGE)
    draw.text((560, 575), "Путь решения", font=font(27, bold=True), fill=ORANGE)
    solver = [
        "Извлечь RCDATA по ID из таблицы ресурсов",
        "Попробовать 2 порядка частей DLL",
        "UPY! → UPX! (маркер начинается с 0x205)",
        "upx -t / upx -d, открыть DLL в IDA",
        "Запустить готовую differential-атаку Nimbus",
    ]
    y = 628
    for index, label in enumerate(solver, 1):
        draw.text((565, y), f"{index}.", font=font(20, bold=True), fill=ORANGE)
        wrapped(draw, label, (600, y), 44, size=19)
        y += 51

    arrow(draw, (1125, 360), (1215, 360), GREEN)
    round_box(draw, (1225, 190, 1745, 485), fill="#102019", outline=GREEN)
    draw.text((1260, 220), "Успешная распаковка", font=font(28, bold=True), fill=GREEN)
    draw.text((1260, 285), "Flags_extracted/", font=font(25, mono=True), fill=TEXT)
    draw.text((1290, 335), "├── Flag.txt", font=font(21, mono=True), fill=TEXT)
    draw.text((1290, 375), "└── Flag_countries_1950/", font=font(21, mono=True), fill=TEXT)
    draw.text((1320, 415), "└── 51 PNG", font=font(21, mono=True), fill=MUTED)
    round_box(draw, (1225, 550, 1745, 900), fill="#20140f", outline=RED)
    draw.text((1260, 580), "Почему патч единицы не помогает", font=font(25, bold=True), fill=RED)
    wrapped(
        draw,
        "Даже если заменить результат NimbusVerify на 1, введённая строка всё равно участвует в получении ключа архива. Неверный пароль ломает SHA-256 первого же расшифрованного файла.",
        (1260, 650),
        39,
        size=21,
        spacing=10,
    )
    draw.text((60, 970), f"Архив: {MANIFEST['archive_size']} байт · DLL: {MANIFEST['dll_size']} байт", font=font(18), fill=MUTED)
    save(image, "01_architecture.png")

def resource_loader():
    image, draw = canvas(
        "IDA Pro: загрузка PE-ресурса",
        "task.exe · функция load_rcdata · точные адреса из базы IDA Pro 9.0",
    )
    rows = SELECTED["resource_loader"][:22]
    highlights = {
        "0x000000014000193E": "#27354a",
        "0x000000014000194A": "#3b2c16",
        "0x000000014000195E": "#253622",
        "0x000000014000196C": "#253622",
        "0x000000014000197E": "#3b2c16",
    }
    ida_frame(draw, (55, 120, 1220, 950), "load_rcdata (0x140001910)", rows, highlights)
    round_box(draw, (1260, 145, 1740, 410), fill=PANEL, outline=BLUE)
    draw.text((1290, 175), "Что видно", font=font(25, bold=True), fill=BLUE)
    wrapped(draw, "r8d = 0x0A — стандартный тип RT_RCDATA. ID ресурса приходит в EDX, после чего код получает размер и указатель на данные.", (1290, 230), 36, size=21)
    round_box(draw, (1260, 450, 1740, 735), fill=PANEL, outline=GREEN)
    draw.text((1290, 480), "Как найти в IDA", font=font(25, bold=True), fill=GREEN)
    wrapped(draw, "Imports → FindResourceW → Xrefs. Короткая функция с цепочкой FindResourceW / SizeofResource / LoadResource / LockResource — универсальный загрузчик частей.", (1290, 535), 36, size=21)
    round_box(draw, (1260, 775, 1740, 950), fill="#20140f", outline=ORANGE)
    wrapped(draw, "Переименуйте sub_140001910 в load_rcdata — остальные вызовы становятся намного понятнее.", (1290, 815), 36, size=21, fill=ORANGE, bold=True)
    save(image, "02_ida_resource_loader.png")

def tigress_and_dll():
    image, draw = canvas(
        "IDA Pro: Tigress flattening и загрузка Nimbus DLL",
        "verify_password_obfuscated · диспетчер на 68 состояний и динамический вызов ordinal 1",
    )
    dispatch = SELECTED["tigress_dispatch"][:19]
    ida_frame(
        draw,
        (45, 120, 1130, 730),
        "verify_password_obfuscated (dispatcher)",
        dispatch,
        {"0x00000001400035D0": "#27354a", "0x00000001400035EF": "#4a2020"},
        compact=True,
    )
    dll_rows = SELECTED["dll_loader"][:8]
    ida_frame(
        draw,
        (45, 760, 1130, 1015),
        "verify_password_obfuscated (case 44)",
        dll_rows,
        {"0x0000000140003B9D": "#3b2c16"},
        compact=True,
    )
    round_box(draw, (1170, 135, 1755, 425), fill=PANEL, outline=RED)
    draw.text((1200, 165), "Признак Tigress", font=font(27, bold=True), fill=RED)
    wrapped(draw, "Один большой switch на 68 состояний, непрямой jmp rcx и десятки переходов назад к dispatcher. Это flattening, а не бизнес-логика Nimbus.", (1200, 225), 42, size=21)
    round_box(draw, (1170, 465, 1755, 730), fill=PANEL, outline=ORANGE)
    draw.text((1200, 495), "Полезный якорь", font=font(27, bold=True), fill=ORANGE)
    wrapped(draw, "Не распутывайте весь граф. Идите от импортов LoadLibraryW и GetProcAddress: обе ссылки принадлежат sub_140003550.", (1200, 555), 42, size=21)
    round_box(draw, (1170, 770, 1755, 1015), fill="#102019", outline=GREEN)
    draw.text((1200, 800), "Вывод", font=font(27, bold=True), fill=GREEN)
    wrapped(draw, "DLL пишется во временный файл, загружается, затем вызывается экспорт ordinal 1. Имя экспорта специально отсутствует.", (1200, 860), 42, size=21)
    save(image, "03_ida_tigress_dll.png")

def password_and_archive():
    image, draw = canvas(
        "IDA Pro: gate пароля и сборка архива",
        "Патч verified==1 недостаточен: пароль остаётся аргументом unpack_archive",
    )
    password = SELECTED["password_gate"][16:31]
    ida_frame(
        draw,
        (45, 125, 1160, 650),
        "submit_password_gui (0x1400021D0)",
        password,
        {
            "0x000000014000238B": "#27354a",
            "0x0000000140002390": "#4a2020",
            "0x000000014000239F": "#253622",
        },
        compact=True,
    )
    archive = SELECTED["archive_unpack"][:23]
    ida_frame(
        draw,
        (45, 685, 1160, 1015),
        "unpack_archive (0x1400024D0)",
        archive,
        {"0x00000001400025DF": "#27354a", "0x0000000140002614": "#3b2c16", "0x0000000140002624": "#253622"},
        compact=True,
    )
    round_box(draw, (1200, 145, 1755, 430), fill=PANEL, outline=RED)
    draw.text((1230, 175), "Два аргумента", font=font(27, bold=True), fill=RED)
    wrapped(draw, "EDX получает результат проверки (1), а RCX всё ещё указывает на введённый пароль. Поэтому патч JNZ открывает только следующий слой.", (1230, 235), 40, size=21)
    round_box(draw, (1200, 470, 1755, 725), fill=PANEL, outline=BLUE)
    draw.text((1230, 500), "Четыре части", font=font(27, bold=True), fill=BLUE)
    wrapped(draw, "Цикл вызывает load_rcdata четыре раза, суммирует размеры, выделяет общий буфер и делает четыре memcpy.", (1230, 560), 40, size=21)
    round_box(draw, (1200, 765, 1755, 1015), fill="#102019", outline=GREEN)
    draw.text((1230, 795), "Криптопроверка", font=font(27, bold=True), fill=GREEN)
    wrapped(draw, "После склейки проверяется SHA-256 архива, затем пароль расшифровывает данные. Для каждого файла хранится отдельный SHA-256.", (1230, 855), 40, size=21)
    save(image, "04_ida_password_archive.png")

def upx_repair():
    image, draw = canvas(
        "Восстановление DLL из RCDATA",
        "Две перестановки, один повреждённый байт UPX и проверка через upx -t",
    )
    round_box(draw, (60, 125, 1030, 900), fill="#090d12", outline=BORDER)
    draw.text((90, 155), "PowerShell / solve_resources.py", font=font(21, bold=True, mono=True), fill=GREEN)
    terminal = [
        "RCDATA:",
        "  id=3179 size=  90284   # fixed first part",
        "  id=4597 size=  90282   # unknown tail A",
        "  id=6211 size=  90282   # unknown tail B",
        "  id=8461 size=   9943   # Nimbus params",
        "",
        "DLL order (3179, 4597, 6211):",
        "  repaired marker at 0x205, UPX OK",
        "",
        "DLL order (3179, 6211, 4597):",
        "  repaired marker at 0x205, UPX FAIL",
        "",
        "> upx -d Nimbus_3179_4597_6211.dll",
        "1075712 <- 270848   25.18%   win64/pe",
        "Unpacked 1 file.",
    ]
    y = 210
    mono = font(20, mono=True)
    for line in terminal:
        color = GREEN if "UPX OK" in line or "Unpacked" in line else (RED if "FAIL" in line else TEXT)
        draw.text((90, y), line, font=mono, fill=color)
        y += 40
    round_box(draw, (1080, 125, 1740, 490), fill=PANEL, outline=ORANGE)
    draw.text((1110, 155), "Повреждённый маркер", font=font(27, bold=True), fill=ORANGE)
    draw.text((1120, 245), "offset  00 01 02 03", font=font(22, mono=True), fill=MUTED)
    draw.text((1120, 295), "0x0205  55 50 59 21", font=font(29, mono=True), fill=TEXT)
    draw.rounded_rectangle((1340, 286, 1390, 333), radius=6, outline=RED, width=4)
    draw.text((1120, 365), "          U  P  Y  !", font=font(24, mono=True), fill=RED)
    draw.text((1120, 420), "0x207: Y (0x59) → X (0x58)", font=font(23, bold=True, mono=True), fill=GREEN)
    round_box(draw, (1080, 540, 1740, 900), fill=PANEL, outline=BLUE)
    draw.text((1110, 570), "Почему всего 2 варианта", font=font(27, bold=True), fill=BLUE)
    wrapped(draw, "Первая часть фиксирована и содержит DOS/PE-заголовки. Две оставшиеся части имеют одинаковый размер и намеренно не подписаны — остаётся переставить только их.", (1110, 635), 48, size=22)
    wrapped(draw, "Правильность порядка подтверждает не расширение файла, а внутренний тест UPX.", (1110, 790), 48, size=22, fill=YELLOW, bold=True)
    save(image, "05_upx_repair.png")

def nimbus_attack():
    image, draw = canvas(
        "IDA Pro: NimbusVerify и differential-атака",
        f"Восстановленная DLL · export ordinal {NIMBUS['export']['ordinal']} · {NIMBUS['export']['ea']}",
    )
    round_box(draw, (50, 125, 1110, 875), fill="#11161d", outline="#414a56", radius=10)
    draw.rectangle((50, 125, 1110, 165), fill="#2b313a")
    draw.text((65, 133), "Pseudocode-A · NimbusVerify", font=font(18, bold=True), fill=TEXT)
    pseudo_lines = [
        "_BOOL8 __fastcall NimbusVerify(",
        "    const char *password, BYTE *params, size_t size)",
        "{",
        "    if (size == 0 || params == 0 || !password)",
        "        return 0;",
        "",
        "    password_length = strlen(password);",
        "    parse_verify_records(params, size);",
        "",
        "    // Проверяются опубликованные VERIFY-векторы",
        "    // шифра Nimbus под введённым 128-битным ключом.",
        "    for (record : verify_records)",
        "        ok &= NimbusEncrypt(record.pt, password) == record.ct;",
        "",
        "    return ok;",
        "}",
    ]
    y = 195
    code_font = font(21, mono=True)
    for line in pseudo_lines:
        color = GREEN if "return ok" in line else (RED if "return 0" in line else (MUTED if line.strip().startswith("//") else TEXT))
        draw.text((80, y), line, font=code_font, fill=color)
        y += 39
    round_box(draw, (1150, 125, 1750, 480), fill=PANEL, outline=PURPLE)
    draw.text((1180, 155), "Атака из проекта", font=font(28, bold=True), fill=PURPLE)
    wrapped(draw, "Nimbus_attack.cpp использует пары с выбранной разностью. Публичные PAIR-записи позволяют восстановить 128-битный master key без перебора.", (1180, 220), 43, size=22)
    round_box(draw, (1150, 525, 1750, 875), fill="#090d12", outline=GREEN)
    draw.text((1180, 555), "> Nimbus_attack.exe params.txt", font=font(20, mono=True), fill=MUTED)
    key = "6DA4AEBBADB2B66E0B31F1A8083CA400"
    draw.text((1180, 635), key[:16], font=font(30, bold=True, mono=True), fill=GREEN)
    draw.text((1180, 685), key[16:], font=font(30, bold=True, mono=True), fill=GREEN)
    draw.text((1180, 770), "Ключ одновременно является", font=font(21), fill=TEXT)
    draw.text((1180, 808), "паролем окна SFX.", font=font(23, bold=True), fill=YELLOW)
    draw.text((62, 940), "Иллюстрация собрана из выгрузки IDA Pro 9.0 и фактического вывода готовой атаки.", font=font(18), fill=MUTED)
    save(image, "06_nimbus_attack.png")

if __name__ == "__main__":
    architecture()
    resource_loader()
    tigress_and_dll()
    password_and_archive()
    upx_repair()
    nimbus_attack()
    print(f"Generated 6 images in {OUTPUT} and {FINAL_OUTPUT}")
