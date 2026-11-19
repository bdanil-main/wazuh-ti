#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
show_alerts.py: алерты TI DNS из /var/ossec/logs/alerts/alerts.json в виде таблицы.

Показывает алерты правил 100201-100204, 100210, 100211 за последние N минут: время, rule.id, уровень,
имя декодера, data.query, data.query_d2, data.query_d3, data.srcip, имя агента. С параметром --expect
сверяет результат с файлом, который создал tests/make-live-events.py, и печатает PASS или FAIL.

Читается только хвост файла (--tail-mb), поэтому скрипт безопасен для большого alerts.json.

Запуск внутри контейнера (скрипт передаётся через stdin):
  podman exec -i single-node_wazuh.manager_1 /var/ossec/framework/python/bin/python3 - \\
      --minutes 30 --expect /tmp/wazuh-ti-expected.tsv < tests/show_alerts.py

Параметры:
  --file PATH       путь к alerts.json (по умолчанию /var/ossec/logs/alerts/alerts.json)
  --minutes N       окно по времени, по умолчанию 60
  --tail-mb N       сколько мегабайт с конца файла читать, по умолчанию 20
  --expect FILE     файл ожиданий (домен, rule id, уровень через табуляцию); rule id '-' означает,
                    что TI-алерта по этому домену быть не должно
Код возврата: 0 успех (или нет --expect), 1 хотя бы одна проверка FAIL, 2 файл не прочитан.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from typing import Dict, List, Optional

TI_RULES = {"100201", "100202", "100203", "100204", "100210", "100211"}


def parse_ts(value: str) -> Optional[datetime.datetime]:
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")
    except (ValueError, TypeError):
        return None


def read_tail(path: str, tail_mb: int) -> List[str]:
    size = os.path.getsize(path)
    start = max(0, size - tail_mb * 1024 * 1024)
    with open(path, "rb") as fh:
        fh.seek(start)
        data = fh.read()
    lines = data.decode("utf-8", errors="replace").splitlines()
    if start > 0 and lines:
        lines = lines[1:]
    return lines


def collect(lines: List[str], minutes: int) -> List[Dict[str, str]]:
    border = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes)
    rows: List[Dict[str, str]] = []
    for raw in lines:
        if '"rule"' not in raw:
            continue
        try:
            alert = json.loads(raw)
        except ValueError:
            continue
        rule = alert.get("rule", {})
        if str(rule.get("id")) not in TI_RULES:
            continue
        moment = parse_ts(alert.get("timestamp", ""))
        if moment is not None and moment < border:
            continue
        data = alert.get("data", {})
        rows.append(
            {
                "time": alert.get("timestamp", ""),
                "rule": str(rule.get("id")),
                "level": str(rule.get("level")),
                "decoder": alert.get("decoder", {}).get("name", ""),
                "query": data.get("query", ""),
                "d2": data.get("query_d2", ""),
                "d3": data.get("query_d3", ""),
                "srcip": data.get("srcip", ""),
                "agent": alert.get("agent", {}).get("name", ""),
            }
        )
    return rows


def print_table(rows: List[Dict[str, str]]) -> None:
    head = ("время", "rule", "ур.", "декодер", "data.query", "query_d2", "query_d3", "srcip", "агент")
    keys = ("time", "rule", "level", "decoder", "query", "d2", "d3", "srcip", "agent")
    table = [head] + [tuple(r[k] or "-" for k in keys) for r in rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(head))]
    for row in table:
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())


def check_expect(rows: List[Dict[str, str]], path: str) -> int:
    failed = 0
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            parts = raw.rstrip("\n").split("\t")
            if len(parts) != 3:
                continue
            query, rule, level = parts
            found = [r for r in rows if r["query"] == query]
            if rule == "-":
                ok = not found
                verdict = "нет TI-алерта" if ok else "найден алерт %s" % found[-1]["rule"]
            else:
                last = found[-1] if found else None
                ok = bool(last) and last["rule"] == rule and last["level"] == level
                verdict = (
                    "rule %s, уровень %s" % (last["rule"], last["level"]) if last else "алерт не найден"
                )
            print("%s  %-45s ожидалось %-7s ур.%-2s: %s" % ("PASS" if ok else "FAIL", query, rule, level, verdict))
            failed += 0 if ok else 1
    print("Итог: %s" % ("все проверки пройдены" if not failed else "не пройдено проверок: %d" % failed))
    return 1 if failed else 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="show_alerts.py", description="Алерты TI DNS из alerts.json")
    ap.add_argument("--file", default="/var/ossec/logs/alerts/alerts.json")
    ap.add_argument("--minutes", type=int, default=60)
    ap.add_argument("--tail-mb", type=int, default=20)
    ap.add_argument("--expect", help="файл ожиданий от make-live-events.py")
    args = ap.parse_args(argv)

    try:
        rows = collect(read_tail(args.file, args.tail_mb), args.minutes)
    except OSError as exc:
        print("ОШИБКА: не удалось прочитать %s: %s" % (args.file, exc), file=sys.stderr)
        return 2
    if rows:
        print_table(rows)
    else:
        print("TI-алертов за последние %d минут не найдено" % args.minutes)
    if args.expect:
        print()
        try:
            return check_expect(rows, args.expect)
        except OSError as exc:
            print("ОШИБКА: не удалось прочитать %s: %s" % (args.expect, exc), file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
