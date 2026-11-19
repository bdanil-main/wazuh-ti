#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make-live-events.py: синтетические события BIND по РЕАЛЬНЫМ доменам из ваших CDB-списков.

Скрипт читает рабочие списки Wazuh (ti-domains, ti-urlhaus, ti-threatfox, ti-phishingarmy, ti-multi),
выбирает по одному подходящему домену на каждое правило и формирует строки лога BIND в том формате,
который ожидает декодер. Домены берутся из ТЕКУЩИХ списков, поэтому тест не зависит от того,
какие IOC были в фидах в день первой установки. Реальные DNS-запросы никуда не отправляются.

Выбор доменов (детерминированный: первый подходящий в алфавитном порядке):
  100201  домен есть в ti-multi (минимум два источника)
  100202  домен есть в ti-threatfox, но нет в ti-multi
  100203  домен есть в ti-urlhaus, но нет в ti-multi и ti-threatfox
  100204  домен есть в ti-phishingarmy, но нет в ti-multi, ti-threatfox, ti-urlhaus
  100210  запрос test.<домен из двух меток из ti-domains>: родитель из двух меток есть в списке
  100211  запрос test.<домен из трёх меток из ti-domains>, у которого родитель из двух меток
          в списке отсутствует: совпадает по трём последним меткам
  100200  контрольные запросы www.example.org и localhost: декодируются, алерта быть не должно

Если для какого-то правила в списках нет подходящего домена, оно пропускается с пояснением.

Запуск внутри контейнера Manager (скрипт передаётся через stdin, копировать его в контейнер не нужно):
  podman exec -i single-node_wazuh.manager_1 /var/ossec/framework/python/bin/python3 - \\
      --append /tmp/wazuh-ti-dashboard-test.log \\
      --expect /tmp/wazuh-ti-expected.tsv < tests/make-live-events.py

Параметры:
  --lists-dir DIR   каталог списков (по умолчанию /var/ossec/etc/lists)
  --append FILE     дописать события в файл (для интеграционного теста через <localfile>);
                    без параметра события печатаются в stdout (для wazuh-logtest), таблица - в stderr
  --expect FILE     записать ожидаемый результат (домен, rule id, уровень) для tests/show_alerts.py
Код возврата: 0 успех, 2 списки не найдены или пусты, 3 не удалось подобрать ни одного домена.
"""
from __future__ import annotations

import argparse
import datetime
import os
import sys
from typing import Dict, List, Optional, Set, Tuple

LIST_NAMES = ["ti-domains", "ti-urlhaus", "ti-threatfox", "ti-phishingarmy", "ti-multi"]
HOST = "dc-02"
DNS_SERVER = "10.16.18.13"
CONTROL_DOMAINS = ["www.example.org", "localhost"]


def load_list(path: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition(":")
            if key:
                result[key] = value
    return result


def labels(name: str) -> int:
    return len(name.split("."))


def first(candidates: List[str]) -> Optional[str]:
    return sorted(candidates)[0] if candidates else None


def pick_cases(lists: Dict[str, Dict[str, str]]) -> Tuple[List[Dict[str, str]], List[str]]:
    domains = lists["ti-domains"]
    multi: Set[str] = set(lists["ti-multi"])
    fox: Set[str] = set(lists["ti-threatfox"])
    haus: Set[str] = set(lists["ti-urlhaus"])
    phish: Set[str] = set(lists["ti-phishingarmy"])
    exact = multi | fox | haus | phish

    cases: List[Dict[str, str]] = []
    skipped: List[str] = []

    def add(rule: str, level: str, query: str, note: str, qtype: str = "A") -> None:
        cases.append(dict(rule=rule, level=level, query=query, note=note, qtype=qtype))

    d = first([k for k in multi])
    if d:
        add("100201", "14", d, "точное совпадение, домен найден минимум в двух источниках (%s)" % domains.get(d, "?"))
    else:
        skipped.append("100201: в ti-multi нет доменов")

    d = first([k for k in fox if k not in multi])
    if d:
        add("100202", "13", d, "точное совпадение, только ThreatFox", "TXT")
    else:
        skipped.append("100202: нет домена только из ThreatFox")

    d = first([k for k in haus if k not in multi and k not in fox])
    if d:
        add("100203", "12", d, "точное совпадение, только URLhaus")
    else:
        skipped.append("100203: нет домена только из URLhaus")

    d = first([k for k in phish if k not in multi and k not in fox and k not in haus])
    if d:
        add("100204", "10", d, "точное совпадение, только Phishing Army", "AAAA")
    else:
        skipped.append("100204: нет домена только из Phishing Army")

    d = first([k for k in domains if labels(k) == 2 and ("test." + k) not in exact])
    if d:
        add("100210", "8", "test." + d, "поддомен: родитель %s (две метки) есть в ti-domains" % d)
    else:
        skipped.append("100210: в ti-domains нет домена из двух меток")

    d = first(
        [
            k
            for k in domains
            if labels(k) == 3
            and ".".join(k.split(".")[-2:]) not in domains
            and ("test." + k) not in exact
        ]
    )
    if d:
        add("100211", "8", "test." + d, "поддомен: родитель %s (три метки) есть в ti-domains" % d)
    else:
        skipped.append("100211: в ti-domains нет домена из трёх меток без родителя из двух меток")

    for control in CONTROL_DOMAINS:
        if control in domains:
            skipped.append("контроль %s пропущен: домен присутствует в ti-domains" % control)
        else:
            add("-", "0", control, "контроль: декодируется, алерта быть не должно")
    return cases, skipped


def build_line(ts: str, index: int, query: str, qtype: str) -> str:
    client = "10.16.18.%d" % (117 + index)
    port = 54328 + index
    return "%s %s named[641085]: queries: client @0x78c719d8bd88 %s#%d (%s): query: %s IN %s +E(0) (%s)" % (
        ts, HOST, client, port, query, query, qtype, DNS_SERVER
    )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="make-live-events.py", description="События BIND по реальным доменам из списков TI")
    ap.add_argument("--lists-dir", default="/var/ossec/etc/lists")
    ap.add_argument("--append", help="дописать события в этот файл вместо печати в stdout")
    ap.add_argument("--expect", help="записать ожидаемый результат в этот файл (для show_alerts.py)")
    args = ap.parse_args(argv)

    lists: Dict[str, Dict[str, str]] = {}
    for name in LIST_NAMES:
        path = os.path.join(args.lists_dir, name)
        try:
            lists[name] = load_list(path)
        except OSError as exc:
            print("ОШИБКА: не удалось прочитать список %s: %s" % (path, exc), file=sys.stderr)
            return 2
    if not lists["ti-domains"]:
        print("ОШИБКА: список ti-domains пуст, сначала выполните обновление (run-updater.sh)", file=sys.stderr)
        return 2

    cases, skipped = pick_cases(lists)
    if not [c for c in cases if c["rule"] != "-"]:
        print("ОШИБКА: не удалось подобрать ни одного домена из списков", file=sys.stderr)
        return 3

    now = datetime.datetime.now().astimezone()
    lines = []
    for i, case in enumerate(cases):
        ts = (now + datetime.timedelta(milliseconds=100 * i)).isoformat(timespec="microseconds")
        lines.append(build_line(ts, i, case["query"], case["qtype"]))

    table = ["Ожидаемый результат (rule id; '-' означает, что алерта быть не должно):"]
    for i, case in enumerate(cases, 1):
        table.append("  %2d  %-8s уровень %-2s  %-45s %s" % (i, case["rule"], case["level"], case["query"], case["note"]))
    for text in skipped:
        table.append("  пропущено: " + text)
    table.append("Событий: %d" % len(cases))

    if args.expect:
        with open(args.expect, "w", encoding="utf-8") as fh:
            for case in cases:
                fh.write("%s\t%s\t%s\n" % (case["query"], case["rule"], case["level"]))

    if args.append:
        with open(args.append, "a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
        print("\n".join(table))
        print("Дописано в %s: %d событий" % (args.append, len(lines)))
    else:
        for line in lines:
            print(line)
        print("\n".join(table), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
