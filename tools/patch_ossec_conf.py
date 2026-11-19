#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_ossec_conf.py: безопасное добавление и удаление строк проекта Wazuh TI DNS в ossec.conf.

Файл ossec.conf целиком НЕ заменяется. Скрипт только добавляет недостающие строки в существующий
блок <ruleset> (или удаляет временный localfile интеграционного теста), перед записью проверяет, что
результат остаётся корректным XML, и делает копию рядом с файлом (если не указан --no-backup).
Запись выполняется в тот же файл (inode сохраняется), поэтому скрипт безопасен и для файла,
подключённого в контейнер как bind mount.

Команды:
  check                   показать, какие строки TI есть в файле; код 0 - всё на месте и временного
                          localfile нет, 1 - не хватает строк TI, 2 - строки TI на месте, но остался
                          временный localfile теста
  apply                   добавить недостающие строки TI в <ruleset> (повторный запуск ничего не меняет)
  add-test-localfile      добавить ВРЕМЕННЫЙ <localfile> для интеграционного теста
                          (/tmp/wazuh-ti-dashboard-test.log), обрамлённый комментариями-маркерами
  remove-test-localfile   удалить временный localfile теста (по маркерам или по пути в <location>)

Строки TI (добавляются в конец <ruleset>):
  <decoder_exclude>0155-named_decoders.xml</decoder_exclude>
  <list>etc/lists/ti-domains</list>  ... (всего пять списков)

Примеры:
  python3 patch_ossec_conf.py check --file /var/ossec/etc/ossec.conf
  python3 patch_ossec_conf.py apply --file /var/ossec/etc/ossec.conf --dry-run
  python3 patch_ossec_conf.py apply --file /var/ossec/etc/ossec.conf

Коды возврата: 0 успех, 1 не хватает строк TI (для check), 2 остался временный localfile (для check),
3 ошибка (файл не найден, нет единственного блока <ruleset>, результат не является корректным XML).
Скрипту нужен только Python 3.8+ со стандартной библиотекой.
"""
from __future__ import annotations

import argparse
import datetime
import difflib
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

DECODER_EXCLUDE = "0155-named_decoders.xml"
TI_LISTS = ["ti-domains", "ti-urlhaus", "ti-threatfox", "ti-phishingarmy", "ti-multi"]
TI_COMMENT = "<!-- Threat Intelligence DNS -->"

TEST_LOG = "/tmp/wazuh-ti-dashboard-test.log"
TEST_BEGIN = "<!-- wazuh-ti-integration-test:begin (временный источник, удалить после проверки) -->"
TEST_END = "<!-- wazuh-ti-integration-test:end -->"

EXIT_OK, EXIT_MISSING, EXIT_TEST_LEFT, EXIT_ERROR = 0, 1, 2, 3

COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
RULESET_OPEN_RE = re.compile(r"<ruleset\s*>")
RULESET_CLOSE_RE = re.compile(r"</ruleset\s*>")
OSSEC_CLOSE_RE = re.compile(r"</ossec_config\s*>")
TEST_MARKERS_RE = re.compile(
    r"[ \t]*<!--\s*wazuh-ti-integration-test:begin.*?-->.*?<!--\s*wazuh-ti-integration-test:end\s*-->[ \t]*\r?\n?",
    re.S,
)
TEST_ELEMENT_RE = re.compile(
    r"[ \t]*<localfile>(?:(?!</localfile>).)*?<location>\s*"
    + re.escape(TEST_LOG)
    + r"\s*</location>(?:(?!</localfile>).)*?</localfile>[ \t]*\r?\n?",
    re.S,
)


class PatchError(Exception):
    pass


def required_patterns() -> List[Tuple[str, re.Pattern]]:
    items = [
        (
            "<decoder_exclude>%s</decoder_exclude>" % DECODER_EXCLUDE,
            re.compile(r"<decoder_exclude>\s*" + re.escape(DECODER_EXCLUDE) + r"\s*</decoder_exclude>"),
        )
    ]
    for name in TI_LISTS:
        line = "<list>etc/lists/%s</list>" % name
        items.append((line, re.compile(r"<list>\s*etc/lists/" + re.escape(name) + r"\s*</list>")))
    return items


def comment_spans(text: str) -> List[Tuple[int, int]]:
    return [(m.start(), m.end()) for m in COMMENT_RE.finditer(text)]


def inside(pos: int, spans: List[Tuple[int, int]]) -> bool:
    return any(a <= pos < b for a, b in spans)


def find_outside(text: str, regex: re.Pattern) -> List[re.Match]:
    spans = comment_spans(text)
    return [m for m in regex.finditer(text) if not inside(m.start(), spans)]


def newline_of(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def ruleset_block(text: str) -> Tuple[int, int]:
    """Возвращает (конец открывающего тега, начало закрывающего) единственного блока <ruleset>."""
    opens = find_outside(text, RULESET_OPEN_RE)
    closes = find_outside(text, RULESET_CLOSE_RE)
    if len(opens) != 1 or len(closes) != 1:
        raise PatchError(
            "ожидался ровно один блок <ruleset>...</ruleset>, найдено открывающих: %d, закрывающих: %d"
            % (len(opens), len(closes))
        )
    if opens[0].end() > closes[0].start():
        raise PatchError("закрывающий тег </ruleset> стоит раньше открывающего")
    return opens[0].end(), closes[0].start()


def missing_ti_lines(text: str) -> List[str]:
    start, end = ruleset_block(text)
    block = COMMENT_RE.sub("", text[start:end])
    return [line for line, pat in required_patterns() if not pat.search(block)]


def line_indent_before(text: str, pos: int) -> Tuple[int, str]:
    """Начало строки, в которой находится pos, и её отступ, если до pos только пробелы."""
    line_start = text.rfind("\n", 0, pos) + 1
    prefix = text[line_start:pos]
    return line_start, (prefix if prefix.strip() == "" else "")


def insert_before_closing(text: str, close_pos: int, lines: List[str], extra_indent: str = "  ") -> str:
    nl = newline_of(text)
    line_start, closing_indent = line_indent_before(text, close_pos)
    own_line = text[line_start:close_pos].strip() == ""
    child = closing_indent + extra_indent
    payload = "".join(child + line + nl for line in lines)
    if own_line:
        return text[:line_start] + payload + text[line_start:]
    return text[:close_pos] + nl + payload + text[close_pos:]


def apply_ti(text: str) -> Tuple[str, List[str]]:
    missing = missing_ti_lines(text)
    if not missing:
        return text, []
    start, end = ruleset_block(text)
    lines = list(missing)
    if TI_COMMENT not in text[start:end]:
        lines.insert(0, TI_COMMENT)
    return insert_before_closing(text, end, lines), missing


def has_test_localfile(text: str) -> bool:
    return bool(find_outside(text, TEST_ELEMENT_RE)) or bool(find_outside(text, TEST_MARKERS_RE))


def add_test_localfile(text: str) -> Tuple[str, bool]:
    if has_test_localfile(text):
        return text, False
    closes = find_outside(text, OSSEC_CLOSE_RE)
    if not closes:
        raise PatchError("в файле нет закрывающего тега </ossec_config>")
    block = [
        TEST_BEGIN,
        "<localfile>",
        "  <log_format>syslog</log_format>",
        "  <location>%s</location>" % TEST_LOG,
        "</localfile>",
        TEST_END,
    ]
    return insert_before_closing(text, closes[0].start(), block), True


def remove_test_localfile(text: str) -> Tuple[str, bool]:
    changed = False
    for regex in (TEST_MARKERS_RE, TEST_ELEMENT_RE):
        while True:
            found = find_outside(text, regex)
            if not found:
                break
            m = found[0]
            text = text[: m.start()] + text[m.end():]
            changed = True
    return text, changed


def validate_xml(text: str) -> None:
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    try:
        ET.fromstring("<root>" + body + "</root>")
    except ET.ParseError as exc:
        raise PatchError("результат не является корректным XML: %s" % exc)


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", newline="") as fh:
            return fh.read()
    except OSError as exc:
        raise PatchError("не удалось прочитать %s: %s" % (path, exc))


def write_in_place(path: str, new_text: str, backup: bool) -> Optional[str]:
    backup_path = None
    try:
        if backup:
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            backup_path = "%s.bak-ti-%s" % (path, stamp)
            shutil.copy2(path, backup_path)
        with open(path, "r+", encoding="utf-8", newline="") as fh:
            fh.seek(0)
            fh.write(new_text)
            fh.truncate()
    except OSError as exc:
        raise PatchError("не удалось записать %s: %s" % (path, exc))
    return backup_path


def show_diff(path: str, old: str, new: str) -> None:
    diff = difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True), "%s (до)" % path, "%s (после)" % path
    )
    sys.stdout.writelines(diff)


def cmd_check(text: str) -> int:
    missing = missing_ti_lines(text)
    test_left = has_test_localfile(text)
    for line, pat in required_patterns():
        state = "ОТСУТСТВУЕТ" if line in missing else "есть"
        print("  %-12s %s" % (state, line))
    print("  %-12s временный localfile интеграционного теста (%s)" % ("ОСТАЛСЯ" if test_left else "нет", TEST_LOG))
    if missing:
        print("Не хватает строк TI: %d. Выполните команду apply." % len(missing))
        return EXIT_MISSING
    if test_left:
        print("Строки TI на месте, но остался временный localfile. Выполните команду remove-test-localfile.")
        return EXIT_TEST_LEFT
    print("Конфигурация в порядке.")
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Безопасная правка ossec.conf для проекта Wazuh TI DNS")
    ap.add_argument("command", choices=["check", "apply", "add-test-localfile", "remove-test-localfile"])
    ap.add_argument("--file", required=True, help="путь к ossec.conf")
    ap.add_argument("--dry-run", action="store_true", help="не записывать файл, показать diff")
    ap.add_argument("--no-backup", action="store_true", help="не создавать копию ossec.conf.bak-ti-<время>")
    args = ap.parse_args(argv)

    try:
        text = read_text(args.file)
        if args.command == "check":
            ruleset_block(text)
            return cmd_check(text)

        if args.command == "apply":
            new_text, added = apply_ti(text)
            summary = (
                "добавлено строк TI: %d" % len(added) if added else "изменений не требуется, все строки TI уже есть"
            )
        elif args.command == "add-test-localfile":
            new_text, changed = add_test_localfile(text)
            added = [TEST_LOG] if changed else []
            summary = (
                "добавлен временный localfile %s" % TEST_LOG if changed else "временный localfile уже есть"
            )
        else:
            new_text, changed = remove_test_localfile(text)
            added = [TEST_LOG] if changed else []
            summary = (
                "временный localfile удалён" if changed else "временного localfile нет, изменений не требуется"
            )

        if new_text == text:
            print(summary)
            return EXIT_OK

        validate_xml(new_text)
        if args.dry_run:
            show_diff(args.file, text, new_text)
            print("\n[dry-run] " + summary + "; файл не изменён")
            return EXIT_OK
        backup = write_in_place(args.file, new_text, backup=not args.no_backup)
        print(summary)
        if backup:
            print("копия до изменения: %s" % backup)
        print("Дальше: проверьте конфигурацию (wazuh-analysisd -t) и перезапустите Manager по README.")
        return EXIT_OK
    except PatchError as exc:
        print("ОШИБКА: %s" % exc, file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
