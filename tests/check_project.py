#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_project.py: автономная проверка согласованности проекта Wazuh TI DNS (без Wazuh и без сети).

Запуск из любого каталога:
  python3 -I tests/check_project.py

Что проверяется:
  1. Состав архива: нет лишних файлов, секретов, резервных копий и временных логов.
  2. Корректность XML (декодеры, правила, фрагменты ossec.conf, образец ossec.conf), отсутствие
     двойного дефиса в комментариях.
  3. Декодеры: один родитель named, декодер named-dns-query-3plus стоит раньше named-query, prematch
     не подходит к событиям, которые regex разобрать не может (фаззинг), стандартные декодеры сохранены.
  4. Правила: уникальные ID, порядок (точные совпадения раньше поддоменов), поля, списки, уровни, MITRE.
  5. Согласованность имён списков в config.ini, правилах, фрагменте ossec.conf и tools/patch_ossec_conf.py.
  6. Постоянные пути: config.ini, юниты, обёртка и скрипты не используют /usr/local/sbin, /etc/wazuh-ti,
     /var/lib/wazuh-ti. Временный localfile отсутствует в постоянной конфигурации.
  7. Эмуляция декодера и правил на тестовых событиях и образцах списков, сверка с ожиданиями,
     составленными вручную (tests/fixtures/dns-events.expected.tsv).
  8. Генератор событий по реальным спискам и сверка алертов (make-live-events.py, show_alerts.py).
  9. tools/patch_ossec_conf.py: добавление, повторный запуск, комментарии, удаление временного localfile.
 10. Самотест updater (все прежние проверки плюс проверки защиты Auth-Key).
 11. README и CHANGELOG: обязательные разделы, существование упомянутых файлов, нет опасных команд.

Эмуляция не заменяет wazuh-logtest на живом Manager: стандартные правила Wazuh в ней не моделируются.
Код возврата: 0 все проверки пройдены, 1 есть ошибки.
"""
from __future__ import annotations

import configparser
import importlib.util
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable

EXPECTED_FILES = sorted(
    [
        "README.md",
        "CHANGELOG.md",
        "wazuh-ti-updater.py",
        "config.ini",
        "allowlist.txt",
        "run-updater.sh",
        "wazuh-ti-updater.service",
        "wazuh-ti-updater.timer",
        "wazuh-ti-updater.cron",
        "bind_named_dns_decoders.xml",
        "local_ti_dns_rules.xml",
        "ossec.conf.snippet.xml",
        "tools/patch_ossec_conf.py",
        "tests/check_project.py",
        "tests/logtest.sh",
        "tests/send-events.sh",
        "tests/make-live-events.py",
        "tests/show_alerts.py",
        "tests/fixtures/dns-events.log",
        "tests/fixtures/dns-events.expected.tsv",
        "tests/fixtures/ossec.conf.before",
        "tests/fixtures/lists/ti-domains",
        "tests/fixtures/lists/ti-urlhaus",
        "tests/fixtures/lists/ti-threatfox",
        "tests/fixtures/lists/ti-phishingarmy",
        "tests/fixtures/lists/ti-multi",
        "contrib/baremetal/README.txt",
        "contrib/baremetal/wazuh-ti-updater.service",
        "contrib/baremetal/wazuh-ti-updater.timer",
        "contrib/baremetal/wazuh-ti-updater.cron",
    ]
)
EXECUTABLE = [
    "wazuh-ti-updater.py",
    "run-updater.sh",
    "tools/patch_ossec_conf.py",
    "tests/check_project.py",
    "tests/logtest.sh",
    "tests/send-events.sh",
    "tests/make-live-events.py",
    "tests/show_alerts.py",
]
TI_LISTS = ["ti-domains", "ti-urlhaus", "ti-threatfox", "ti-phishingarmy", "ti-multi"]
RULE_ORDER = ["100201", "100202", "100203", "100204", "100210", "100211"]
RULE_LEVEL = {"100200": 0, "100201": 14, "100202": 13, "100203": 12, "100204": 10, "100210": 8, "100211": 8}
RULE_ID_RE = re.compile(r"\b1002(?:00|01|02|03|04|10|11)\b")
TEST_LOG = "/tmp/wazuh-ti-dashboard-test.log"
FORBIDDEN_PATHS = ["/usr/local/sbin", "/etc/wazuh-ti", "/var/lib/wazuh-ti"]
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"

failures: List[str] = []
counter = {"ok": 0}


def check(cond: bool, msg: str) -> bool:
    print(("  OK    " if cond else "  FAIL  ") + msg)
    if cond:
        counter["ok"] += 1
    else:
        failures.append(msg)
    return cond


def section(title: str) -> None:
    print("\n== %s ==" % title)


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def parse_wrapped(text: str) -> ET.Element:
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    return ET.fromstring("<root>" + body + "</root>")


def load_module(rel: str, name: str):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / rel))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
def check_tree() -> None:
    section("состав архива")
    actual = sorted(
        str(p.relative_to(ROOT)).replace(os.sep, "/") for p in ROOT.rglob("*") if p.is_file()
    )
    actual = [a for a in actual if "__pycache__" not in a and not a.endswith(".pyc")]
    extra = sorted(set(actual) - set(EXPECTED_FILES))
    missing = sorted(set(EXPECTED_FILES) - set(actual))
    check(not missing, "все ожидаемые файлы на месте%s" % (": нет " + ", ".join(missing) if missing else ""))
    check(not extra, "нет лишних файлов%s" % (": " + ", ".join(extra) if extra else ""))
    check(not any(p.name == "__pycache__" for p in ROOT.rglob("*")), "нет каталогов __pycache__")
    for rel in EXECUTABLE:
        check(os.access(str(ROOT / rel), os.X_OK), "%s имеет бит исполнения" % rel)

    section("секреты и временные файлы")
    hex_re = re.compile(r"\b[0-9a-fA-F]{32,}\b")
    token_re = re.compile(r"\b[A-Za-z0-9_\-]{40,}\b")
    key_assign_re = re.compile(r"auth[-_ ]?key\s*[:=]\s*[A-Za-z0-9_\-+/=]{16,}", re.I)
    leaks: List[str] = []
    for rel in actual:
        if rel.endswith(".pyc"):
            continue
        try:
            text = read(rel)
        except UnicodeDecodeError:
            leaks.append("%s: двоичный файл" % rel)
            continue
        for rx, what in ((hex_re, "hex-строка"), (token_re, "длинный токен"), (key_assign_re, "присвоение Auth-Key")):
            for m in rx.finditer(text):
                if m.group(0) == EMPTY_MD5:  # контрольная сумма пустых данных, а не секрет
                    continue
                leaks.append("%s: %s %s" % (rel, what, m.group(0)[:20]))
    check(not leaks, "в проекте нет ключей и длинных токенов%s" % ("; ".join(leaks[:5]) if leaks else ""))
    check(not [a for a in actual if a.endswith((".key", ".bak", ".orig", ".swp"))] and
          not [a for a in actual if ".bak" in a], "нет файлов ключей и резервных копий")
    allowed_test_log = {
        "README.md", "CHANGELOG.md", "tools/patch_ossec_conf.py", "tests/check_project.py",
        "tests/send-events.sh", "tests/make-live-events.py", "tests/show_alerts.py",
    }
    bad = [rel for rel in actual if TEST_LOG in read(rel) and rel not in allowed_test_log]
    check(not bad, "временный localfile теста не попал в постоянную конфигурацию%s" % (": " + ", ".join(bad) if bad else ""))
    snippet = read("ossec.conf.snippet.xml")
    check("wazuh-ti-dashboard-test" not in snippet and "wazuh-ti-integration-test" not in snippet,
          "ossec.conf.snippet.xml не содержит временного localfile")


# --------------------------------------------------------------------------- #
def check_xml() -> None:
    section("XML")
    for rel in ("bind_named_dns_decoders.xml", "local_ti_dns_rules.xml", "ossec.conf.snippet.xml",
                "tests/fixtures/ossec.conf.before"):
        text = read(rel)
        try:
            parse_wrapped(text)
            valid = True
        except ET.ParseError as exc:
            valid = False
            print("        " + str(exc))
        check(valid, "%s: корректный XML" % rel)
        dash = [c for c in re.findall(r"<!--(.*?)-->", text, re.S) if "--" in c]
        check(not dash, "%s: нет двойного дефиса внутри комментариев" % rel)


# --------------------------------------------------------------------------- #
def load_decoders() -> List[Dict]:
    root = parse_wrapped(read("bind_named_dns_decoders.xml"))
    decs = []
    for d in root.findall("decoder"):
        pm, rx, od, par = d.find("prematch"), d.find("regex"), d.find("order"), d.find("parent")
        decs.append(
            dict(
                name=d.get("name"),
                parent=None if par is None else par.text,
                pre=None if pm is None else pm.text,
                pre_t=None if pm is None else pm.get("type"),
                rx=None if rx is None else rx.text,
                rx_t=None if rx is None else rx.get("type"),
                order=None if od is None else od.text.split(","),
            )
        )
    return decs


def decode_event(decs: List[Dict], line: str) -> Tuple[str, Dict[str, str]]:
    """Эмуляция: предекодер снимает заголовок, дочерние декодеры named перебираются по порядку,
    выбирается первый, чей prematch подошёл; при неудаче regex поля не извлекаются и перебор останавливается."""
    m = re.match(r"^\S+\s+\S+\s+(named)(?:\[\d+\])?:\s+(.*)$", line)
    if not m:
        return "", {}
    msg = m.group(2)
    for d in [d for d in decs if d["parent"] == "named"]:
        if d["pre"] and d["pre_t"] == "pcre2":
            if not re.search(d["pre"], msg):
                continue
        elif d["pre"]:
            continue  # osregex-декодеры не эмулируются
        if d["rx"] and d["rx_t"] == "pcre2":
            rm = re.search(d["rx"], msg)
            if not rm:
                return d["name"], {}
            return d["name"], dict(zip(d["order"], rm.groups()))
        return d["name"], {}
    return "named", {}


def check_decoders() -> List[Dict]:
    section("декодеры")
    decs = load_decoders()
    names = [d["name"] for d in decs]
    check(names.count("named") == 1, "декодер-родитель named определён ровно один раз")
    check(len(names) == len(set(names)), "имена декодеров уникальны: %s" % ", ".join(names))
    for stock in ("named-query", "named_client", "named-master", "named_from"):
        check(stock in names, "стандартный декодер %s сохранён" % stock)
    check("named-dns-query-3plus" in names and names.index("named-dns-query-3plus") < names.index("named-query"),
          "named-dns-query-3plus стоит раньше named-query")
    stock_q = next(d for d in decs if d["name"] == "named-query")
    check(stock_q["order"] == ["srcip", "query", "query_type", "dns_server"], "порядок полей named-query стандартный")
    three = next(d for d in decs if d["name"] == "named-dns-query-3plus")
    check(three["order"] == ["srcip", "query_d2", "query_d3", "query", "query_type", "dns_server"],
          "порядок полей named-dns-query-3plus: srcip, query_d2, query_d3, query, query_type, dns_server")
    check(re.compile(three["rx"]).groups == 6, "regex named-dns-query-3plus содержит 6 групп захвата")

    pre, rx = re.compile(three["pre"]), re.compile(three["rx"])
    random.seed(7)
    labels = ["a", "b1", "xn--e1aybc", "UPPER", "c-d", "z", ""]
    bad = hits = 0
    for _ in range(30000):
        name = ".".join(random.choice(labels) for _ in range(random.randint(1, 6)))
        if random.random() < 0.15:
            name += "."
        msg = "queries: client @0x1 10.0.0.1#5 (%s): query: %s IN A +E(0) (10.0.0.2)" % (name, name)
        p, r = bool(pre.search(msg)), bool(rx.search(msg))
        hits += p
        bad += 1 if p and not r else 0
    check(bad == 0, "фаззинг: prematch не подходит к событиям, которые regex не разберёт (совпадений %d)" % hits)

    header = read("bind_named_dns_decoders.xml")
    check("<decoder_exclude>0155-named_decoders.xml</decoder_exclude>" in header,
          "в заголовке декодера описано исключение 0155-named_decoders.xml")
    return decs


# --------------------------------------------------------------------------- #
def load_rules() -> List[Dict]:
    root = parse_wrapped(read("local_ti_dns_rules.xml"))
    group = root.find("group")
    out = []
    for r in group.findall("rule"):
        lst = r.find("list")
        field = r.find("field")
        out.append(
            dict(
                id=r.get("id"),
                level=int(r.get("level")),
                if_sid=(r.find("if_sid").text if r.find("if_sid") is not None else None),
                if_group=(r.find("if_group").text if r.find("if_group") is not None else None),
                list_field=None if lst is None else lst.get("field"),
                list_lookup=None if lst is None else lst.get("lookup"),
                list_path=None if lst is None else lst.text.strip(),
                field_name=None if field is None else field.get("name"),
                mitre=[i.text for i in r.findall("mitre/id")],
                description=(r.find("description").text or ""),
                group_attr=group.get("name"),
            )
        )
    return out


def check_rules() -> List[Dict]:
    section("правила")
    rules = load_rules()
    ids = [r["id"] for r in rules]
    check(len(ids) == len(set(ids)), "ID правил уникальны: %s" % ", ".join(ids))
    check(ids == ["100200"] + RULE_ORDER, "порядок правил в файле: 100200, затем %s" % ", ".join(RULE_ORDER))
    base = rules[0]
    check(base["if_group"] == "named" and base["field_name"] == "query" and base["level"] == 0,
          "100200: уровень 0, if_group=named, поле query")
    check("named" not in rules[0]["group_attr"].split(","), "группа named не указана в <group> файла правил")
    for r in rules[1:]:
        check(r["if_sid"] == "100200", "%s: дочернее правило 100200" % r["id"])
        check(r["level"] == RULE_LEVEL[r["id"]], "%s: уровень %d" % (r["id"], r["level"]))
        check(r["list_lookup"] == "match_key", "%s: lookup=match_key" % r["id"])
        check(r["mitre"] and all(m in ("T1071.004", "T1105", "T1566") for m in r["mitre"]),
              "%s: MITRE %s из допустимого набора" % (r["id"], ",".join(r["mitre"])))
        check("$(query)" in r["description"] and "$(srcip)" in r["description"], "%s: описание содержит query и srcip" % r["id"])
    exact = {"100201": ("query", "ti-multi"), "100202": ("query", "ti-threatfox"), "100203": ("query", "ti-urlhaus"),
             "100204": ("query", "ti-phishingarmy"), "100210": ("query_d2", "ti-domains"), "100211": ("query_d3", "ti-domains")}
    by_id = {r["id"]: r for r in rules}
    for rid, (fld, lst) in exact.items():
        r = by_id[rid]
        check(r["list_field"] == fld and r["list_path"] == "etc/lists/" + lst, "%s: поле %s, список etc/lists/%s" % (rid, fld, lst))
    return rules


# --------------------------------------------------------------------------- #
def check_consistency(rules: List[Dict]) -> None:
    section("согласованность имён списков и конфигурации")
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#",))
    cp.read(str(ROOT / "config.ini"), encoding="utf-8")
    cfg_lists = {cp["general"]["merged_list"], cp["general"]["multi_list"]}
    for sec in cp.sections():
        if sec.startswith("source:"):
            cfg_lists.add(cp[sec]["list"])
    check(cfg_lists == set(TI_LISTS), "config.ini определяет ровно пять списков: %s" % ", ".join(sorted(cfg_lists)))
    snippet = parse_wrapped(read("ossec.conf.snippet.xml"))
    snip_lists = [e.text for e in snippet.iter("list")]
    check(snip_lists[-5:] == ["etc/lists/" + n for n in TI_LISTS][-5:] or
          set(snip_lists[-5:]) == {"etc/lists/" + n for n in TI_LISTS},
          "фрагмент ossec.conf регистрирует все пять списков")
    rule_lists = {r["list_path"] for r in rules if r["list_path"]}
    check(rule_lists <= {"etc/lists/" + n for n in TI_LISTS}, "правила используют только зарегистрированные списки")
    check([e.text for e in snippet.iter("decoder_exclude")] == ["0155-named_decoders.xml"],
          "фрагмент ossec.conf содержит decoder_exclude для 0155-named_decoders.xml")
    ruleset = next(snippet.iter("ruleset"))
    children = [(c.tag, (c.text or "").strip()) for c in ruleset]
    expected_tail = [("decoder_exclude", "0155-named_decoders.xml")] + [("list", "etc/lists/" + n) for n in TI_LISTS]
    check(children[-6:] == expected_tail, "эталонный <ruleset>: блок TI стоит последним и содержит 6 строк")
    check(children.count(("decoder_dir", "etc/decoders")) == 1 and children.count(("rule_dir", "etc/rules")) == 1,
          "эталонный <ruleset>: каталоги etc/decoders и etc/rules не дублируются")
    check(children.count(("decoder_dir", "ruleset/decoders")) == 1 and children.count(("rule_dir", "ruleset/rules")) == 1,
          "эталонный <ruleset>: стандартные каталоги ruleset/decoders и ruleset/rules на месте")
    check(("rule_exclude", "0215-policy_rules.xml") in children, "эталонный <ruleset>: rule_exclude 0215-policy_rules.xml сохранён")

    tool = load_module("tools/patch_ossec_conf.py", "patch_tool")
    check(tool.TI_LISTS == TI_LISTS and tool.DECODER_EXCLUDE == "0155-named_decoders.xml",
          "tools/patch_ossec_conf.py добавляет те же пять списков и то же исключение")
    check(tool.TEST_LOG == TEST_LOG, "путь временного localfile в скрипте совпадает с документацией")

    remotes = list(snippet.iter("remote"))
    localfiles = list(snippet.iter("localfile"))
    check(len(remotes) == 1 and remotes[0].findtext("connection") == "syslog", "вариант Б: один блок remote с connection=syslog")
    check(len(localfiles) == 1 and localfiles[0].findtext("log_format") == "syslog", "вариант А: один блок localfile с log_format=syslog")

    section("постоянные пути (Podman)")
    for opt in ("lists_dir", "state_dir", "log_file", "auth_key_file", "allowlist_file"):
        value = cp["general"][opt]
        check(value.startswith("/var/ossec/"), "config.ini: %s = %s внутри /var/ossec (постоянные тома)" % (opt, value))
    for opt in ("state_dir", "auth_key_file", "allowlist_file"):
        check(cp["general"][opt].startswith("/var/ossec/wodles/wazuh-ti"), "config.ini: %s в /var/ossec/wodles/wazuh-ti" % opt)
    check(cp["general"]["log_file"].startswith("/var/ossec/logs/"), "config.ini: журнал в постоянном томе /var/ossec/logs")
    check(cp["general"]["validate_command"] == "/var/ossec/bin/wazuh-analysisd -t", "validate_command: wazuh-analysisd -t")
    for rel in ("config.ini", "wazuh-ti-updater.service", "wazuh-ti-updater.timer", "wazuh-ti-updater.cron",
                "run-updater.sh", "allowlist.txt", "tools/patch_ossec_conf.py", "tests/logtest.sh",
                "tests/send-events.sh", "tests/make-live-events.py", "tests/show_alerts.py"):
        text = read(rel)
        # config.ini упоминает запрещённые пути только в предупреждающем комментарии
        body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#")) if rel == "config.ini" else text
        found = [p for p in FORBIDDEN_PATHS if p in body]
        check(not found, "%s не использует непостоянные пути %s" % (rel, ", ".join(found) if found else ""))
    service = read("wazuh-ti-updater.service")
    check("podman exec" in service and "/var/ossec/wodles/wazuh-ti/run-updater.sh" in service and "systemctl" not in service,
          "юнит запускает обновление через podman exec, без systemctl внутри контейнера")
    check("run-updater.sh" in read("wazuh-ti-updater.cron") and "XDG_RUNTIME_DIR" in read("wazuh-ti-updater.cron"),
          "cron-вариант запускает run-updater.sh и задаёт XDG_RUNTIME_DIR")
    timer = read("wazuh-ti-updater.timer")
    check("OnCalendar=*-*-* 03:20:00" in timer and "Persistent=true" in timer and "WantedBy=timers.target" in timer,
          "таймер: ежедневно 03:20, Persistent, WantedBy=timers.target")
    updater = read("wazuh-ti-updater.py")
    for path in ("/var/ossec/wodles/wazuh-ti/state", "/var/ossec/logs/wazuh-ti-updater.log",
                 "/var/ossec/wodles/wazuh-ti/abusech.key", "/var/ossec/wodles/wazuh-ti/allowlist.txt",
                 "/var/ossec/wodles/wazuh-ti/config.ini"):
        check(path in updater, "updater: значение по умолчанию %s" % path)
    check(not [p for p in FORBIDDEN_PATHS if p in updater], "updater не содержит непостоянных путей по умолчанию")
    check(read("contrib/baremetal/README.txt").count("/etc/wazuh-ti") >= 1, "contrib/baremetal описывает классические пути отдельно")


# --------------------------------------------------------------------------- #
class Emulator:
    """Упрощённая модель: декодер BIND и дочерние правила 100200 с проверкой CDB-списков."""

    def __init__(self, decs: List[Dict], rules: List[Dict], lists_dir: Path):
        self.decs, self.rules = decs, rules
        self.lists: Dict[str, Set[str]] = {}
        for name in TI_LISTS:
            keys: Set[str] = set()
            for line in (lists_dir / name).read_text(encoding="utf-8").splitlines():
                if line.strip() and not line.startswith("#"):
                    keys.add(line.split(":", 1)[0])
            self.lists[name] = keys

    def run(self, line: str) -> Tuple[str, str, int, Dict[str, str]]:
        dec, fields = decode_event(self.decs, line)
        if not fields.get("query"):
            return dec, "-", 0, fields
        for r in self.rules[1:]:
            value = fields.get(r["list_field"])
            if value is not None and value in self.lists[os.path.basename(r["list_path"])]:
                return dec, r["id"], r["level"], fields
        return dec, "100200", 0, fields


def check_emulation(decs: List[Dict], rules: List[Dict]) -> None:
    section("эмуляция декодера и правил на тестовых событиях")
    emu = Emulator(decs, rules, ROOT / "tests/fixtures/lists")
    events = [l for l in read("tests/fixtures/dns-events.log").splitlines() if l.strip()]
    expected = [l.split("\t") for l in read("tests/fixtures/dns-events.expected.tsv").splitlines()
                if l.strip() and not l.startswith("#")]
    check(len(events) == len(expected), "событий %d, ожиданий %d" % (len(events), len(expected)))
    for line, exp in zip(events, expected):
        n, dec_exp, rule_exp, level_exp = exp[0], exp[1], exp[2], int(exp[3])
        dec, rule, level, fields = emu.run(line)
        ok = dec == dec_exp and rule == rule_exp and level == level_exp
        check(ok, "событие %s: декодер %s, правило %s, уровень %d (ожидалось %s, %s, %d)" % (
            n, dec, rule, level, dec_exp, rule_exp, level_exp))
        if fields:
            check(fields.get("srcip") and fields.get("query_type") and fields.get("dns_server") == "10.16.18.13",
                  "событие %s: извлечены srcip, query_type, dns_server" % n)
    dec, rule, level, f = emu.run(events[5])
    check(f.get("query_d2") == "phish-army-login.test" and f.get("query_d3") == "login.phish-army-login.test",
          "query_d2 и query_d3 для login.phish-army-login.test вычислены верно")
    # поддомены обрабатываются правилом 100210 раньше 100211
    check([r["id"] for r in rules[1:]].index("100210") < [r["id"] for r in rules[1:]].index("100211"),
          "правило 100210 проверяется раньше 100211")
    # точное совпадение приоритетнее поддомена
    line = events[1]
    check(emu.run(line)[1] == "100203", "точное совпадение 100203 не перекрывается правилами поддоменов")


def check_generator(decs: List[Dict], rules: List[Dict]) -> None:
    section("генератор событий по спискам и сверка алертов")
    emu = Emulator(decs, rules, ROOT / "tests/fixtures/lists")
    with tempfile.TemporaryDirectory(prefix="ti-check-") as tmp:
        tmpd = Path(tmp)
        exp_file = tmpd / "expected.tsv"
        out = subprocess.run(
            [PY, "-I", str(ROOT / "tests/make-live-events.py"), "--lists-dir", str(ROOT / "tests/fixtures/lists"),
             "--expect", str(exp_file)],
            capture_output=True, text=True,
        )
        check(out.returncode == 0, "make-live-events.py завершился с кодом 0")
        events = [l for l in out.stdout.splitlines() if l.strip()]
        expected = [l.split("\t") for l in exp_file.read_text(encoding="utf-8").splitlines()]
        check(len(events) == len(expected) >= 6, "сформировано событий: %d" % len(events))
        alerts = []
        for line, (query, rule_exp, level_exp) in zip(events, expected):
            dec, rule, level, fields = emu.run(line)
            if rule_exp == "-":
                check(rule == "100200", "контрольный запрос %s: декодируется, алерта нет" % query)
            else:
                check(rule == rule_exp and str(level) == level_exp,
                      "запрос %s: эмуляция даёт %s/%s, генератор ожидает %s/%s" % (query, rule, level, rule_exp, level_exp))
                alerts.append((query, rule, level, dec, fields))
        used = {e[1] for e in expected}
        check({"100201", "100202", "100203", "100204", "100210", "100211"} <= used, "генератор покрыл все шесть правил TI")

        # alerts.json: правильные алерты, затем потерянный алерт и лишний алерт по контрольному домену
        import datetime
        now = datetime.datetime.now().astimezone()
        ts = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + now.strftime("%z")
        alert_file = tmpd / "alerts.json"

        def write_alerts(items, extra=()):
            with alert_file.open("w", encoding="utf-8") as fh:
                fh.write(json.dumps({"timestamp": "2020-01-01T00:00:00.000+0000", "rule": {"id": "100203", "level": 12},
                                     "data": {"query": "old.test"}}) + "\n")
                for q, r, l, d, f in items:
                    fh.write(json.dumps({"timestamp": ts, "rule": {"id": r, "level": l}, "agent": {"name": "wazuh.manager"},
                                         "decoder": {"name": d}, "data": f}) + "\n")
                for e in extra:
                    fh.write(json.dumps(e) + "\n")

        def run_show():
            return subprocess.run([PY, "-I", str(ROOT / "tests/show_alerts.py"), "--file", str(alert_file),
                                   "--minutes", "10", "--expect", str(exp_file)], capture_output=True, text=True)

        write_alerts(alerts)
        res = run_show()
        check(res.returncode == 0 and "FAIL" not in res.stdout, "show_alerts: полный набор алертов даёт PASS по всем строкам")
        write_alerts(alerts[1:])
        res = run_show()
        check(res.returncode == 1 and res.stdout.count("FAIL") == 1, "show_alerts: пропавший алерт даёт ровно один FAIL")
        write_alerts(alerts, extra=[{"timestamp": ts, "rule": {"id": "100203", "level": 12}, "data": {"query": "www.example.org"}}])
        res = run_show()
        check(res.returncode == 1 and "FAIL  www.example.org" in res.stdout, "show_alerts: алерт на контрольный домен даёт FAIL")
        write_alerts([(q, r, 99, d, f) for q, r, l, d, f in alerts])
        res = run_show()
        check(res.returncode == 1, "show_alerts: неверный уровень даёт FAIL")


# --------------------------------------------------------------------------- #
def check_patch_tool() -> None:
    section("tools/patch_ossec_conf.py")
    tool = load_module("tools/patch_ossec_conf.py", "patch_tool2")
    before = read("tests/fixtures/ossec.conf.before")
    check(len(tool.missing_ti_lines(before)) == 6, "в исходном образце не хватает всех 6 строк TI")
    after, added = tool.apply_ti(before)
    check(len(added) == 6 and tool.missing_ti_lines(after) == [], "apply добавляет 6 строк, после этого недостающих нет")
    again, added2 = tool.apply_ti(after)
    check(again == after and added2 == [], "повторный apply ничего не меняет (идемпотентность)")
    tool.validate_xml(after)
    check(True, "результат apply является корректным XML")
    check(after.count("<decoder_dir>etc/decoders</decoder_dir>") == 1 and after.count("<rule_dir>etc/rules</rule_dir>") == 1,
          "каталоги etc/decoders и etc/rules не продублированы")
    stripped = after.replace("    <!-- Threat Intelligence DNS -->\n", "")
    for line in ["<decoder_exclude>0155-named_decoders.xml</decoder_exclude>"] + ["<list>etc/lists/%s</list>" % n for n in TI_LISTS]:
        stripped = stripped.replace("    " + line + "\n", "")
    check(stripped == before, "кроме 6 строк TI и комментария, файл не изменился ни в одном символе")
    with_test, changed = tool.add_test_localfile(after)
    check(changed and tool.has_test_localfile(with_test), "add-test-localfile добавляет временный localfile")
    check(tool.add_test_localfile(with_test)[1] is False, "повторное добавление временного localfile ничего не меняет")
    removed, changed = tool.remove_test_localfile(with_test)
    check(changed and removed == after, "remove-test-localfile возвращает файл к состоянию до теста")
    commented = before.replace("  </ruleset>", "    <!-- <list>etc/lists/ti-domains</list> -->\n  </ruleset>", 1)
    check("<list>etc/lists/ti-domains</list>" in tool.missing_ti_lines(commented),
          "закомментированная строка не считается установленной")
    for bad in ("<ossec_config></ossec_config>", "<ruleset></ruleset><ruleset></ruleset>"):
        try:
            tool.apply_ti(bad)
            raised = False
        except tool.PatchError:
            raised = True
        check(raised, "ошибка при некорректном числе блоков <ruleset>: %r" % bad[:30])

    with tempfile.TemporaryDirectory(prefix="ti-patch-") as tmp:
        target = Path(tmp) / "ossec.conf"
        target.write_text(before, encoding="utf-8")
        inode = target.stat().st_ino
        res = subprocess.run([PY, "-I", str(ROOT / "tools/patch_ossec_conf.py"), "check", "--file", str(target)],
                             capture_output=True, text=True)
        check(res.returncode == 1, "check до установки возвращает 1")
        res = subprocess.run([PY, "-I", str(ROOT / "tools/patch_ossec_conf.py"), "apply", "--file", str(target)],
                             capture_output=True, text=True)
        backups = [p.name for p in Path(tmp).iterdir() if ".bak-ti-" in p.name]
        check(res.returncode == 0 and len(backups) == 1, "apply создаёт одну резервную копию рядом с файлом")
        check(target.stat().st_ino == inode, "файл изменён на месте (inode сохранён, безопасно для bind mount)")
        res = subprocess.run([PY, "-I", str(ROOT / "tools/patch_ossec_conf.py"), "check", "--file", str(target)],
                             capture_output=True, text=True)
        check(res.returncode == 0, "check после установки возвращает 0")
        res = subprocess.run([PY, "-I", str(ROOT / "tools/patch_ossec_conf.py"), "apply", "--file", str(target), "--dry-run"],
                             capture_output=True, text=True)
        check(res.returncode == 0 and "изменений не требуется" in res.stdout, "dry-run на настроенном файле: изменений не требуется")


# --------------------------------------------------------------------------- #
def check_selftest() -> None:
    section("самотест updater")
    res = subprocess.run([PY, "-I", str(ROOT / "wazuh-ti-updater.py"), "--selftest"], capture_output=True, text=True)
    out = res.stdout
    ok_count = len(re.findall(r"^  OK ", out, re.M))
    fail_count = len(re.findall(r"^  FAIL ", out, re.M))
    check(res.returncode == 0 and "САМОТЕСТ ПРОЙДЕН" in out, "самотест завершился успешно")
    check(ok_count >= 47 and fail_count == 0, "проверок пройдено: %d (было 47, добавлены проверки защиты ключа), ошибок: %d" % (ok_count, fail_count))
    check("ключ в URL-кодировке маскируется" in out and "ключ читается из файла" in out, "проверки защиты Auth-Key выполняются")
    for name in TI_LISTS:
        check(("%s: корректный CDB" % name) in out, "самотест собрал и проверил список %s" % name)
    res = subprocess.run([PY, "-I", "-m", "py_compile", str(ROOT / "wazuh-ti-updater.py")], capture_output=True, text=True)
    check(res.returncode == 0, "py_compile: wazuh-ti-updater.py без синтаксических ошибок")
    for rel in ("tools/patch_ossec_conf.py", "tests/make-live-events.py", "tests/show_alerts.py", "tests/check_project.py"):
        res = subprocess.run([PY, "-I", "-c", "import ast,sys; ast.parse(open(sys.argv[1], encoding='utf-8').read())", str(ROOT / rel)],
                             capture_output=True, text=True)
        check(res.returncode == 0, "синтаксис Python: %s" % rel)
    for rel in ("run-updater.sh", "tests/logtest.sh", "tests/send-events.sh"):
        res = subprocess.run(["bash", "-n", str(ROOT / rel)], capture_output=True, text=True)
        check(res.returncode == 0, "синтаксис bash: %s" % rel)


# --------------------------------------------------------------------------- #
def check_docs() -> None:
    section("README и CHANGELOG")
    readme = read("README.md")
    changelog = read("CHANGELOG.md")
    required = [
        "Wazuh 4.14.10", "Podman", "Fish", "decoder_exclude", "0155-named_decoders.xml", "Вариант А", "Вариант Б",
        "wazuh-logtest", "alerts.json", "Dashboard", "Проверка применения списков", "Интеграционная проверка",
        "Очистка", "Результаты интеграционного тестирования", "Ограничения", "run-updater.sh", "patch_ossec_conf.py",
        "/var/ossec/wodles/wazuh-ti", "read -s", "0600", "wazuh-ti-updater.timer",
    ]
    for word in required:
        check(word in readme, "README содержит «%s»" % word)
    for rid in ("100200", "100201", "100202", "100203", "100204", "100210", "100211"):
        check(rid in readme, "README описывает правило %s" % rid)
    for name in TI_LISTS:
        check(name in readme, "README упоминает список %s" % name)
    for line in readme.splitlines():
        if "100210" in line and "подтвержд" in line:
            check("не подтвержд" in line or "ожидает" in line,
                  "правило 100210 нигде не заявлено проверенным: %s" % line.strip()[:70])
    check(re.search(r"100210[^\n]*не подтвержд", readme) is not None, "README явно указывает, что 100210 не подтверждено на живом Wazuh")
    snippet = parse_wrapped(read("ossec.conf.snippet.xml"))
    ti_block = ["<decoder_exclude>0155-named_decoders.xml</decoder_exclude>"] + ["<list>etc/lists/%s</list>" % n for n in TI_LISTS]
    check(all(l in readme for l in ti_block), "README содержит полный блок TI для <ruleset> (decoder_exclude и пять списков)")
    check("<ruleset>" in readme and "<!-- Threat Intelligence DNS -->" in readme, "README содержит полную секцию <ruleset> с блоком TI")

    refs = set(re.findall(r"`((?:tests|tools|contrib)/[A-Za-z0-9_./-]+)`", readme))
    missing = sorted(r for r in refs if not (ROOT / r).exists() and "*" not in r)
    check(not missing, "все упомянутые в README файлы существуют%s" % (": нет " + ", ".join(missing) if missing else ""))
    top = set(re.findall(r"`([A-Za-z0-9_.-]+\.(?:py|sh|ini|txt|xml|service|timer|cron|md))`", readme))
    unknown = sorted(t for t in top if t not in {os.path.basename(e) for e in EXPECTED_FILES}
                     and t not in {"ossec.conf", "agent.conf", "named.conf", "queries.log", "alerts.json", "config.ini",
                                   "0155-named_decoders.xml", "0215-policy_rules.xml", "local_decoder.xml",
                                   "wazuh_manager.conf", "ossec.conf.bak-ti-ВРЕМЯ", "hostfile.txt"})
    check(not unknown, "README не ссылается на несуществующие файлы проекта%s" % (": " + ", ".join(unknown) if unknown else ""))

    for line in readme.splitlines():
        if "systemctl" in line:
            check("--user" in line or "baremetal" in line or "contrib" in line or "не " in line.lower(),
                  "systemctl в README только для пользовательских юнитов хоста: %s" % line.strip()[:70])
    danger = ["down -v", "--volumes", "volume rm", "volume prune", "system prune", "rm -rf /var/ossec", "podman rm -v",
              "podman-compose down -v", "reset"]
    for line in readme.splitlines():
        for d in danger[:-1]:
            if d in line:
                check("не " in line.lower() or "никогда" in line.lower(),
                      "опасная команда «%s» упомянута только как запрет: %s" % (d, line.strip()[:60]))
    check(not re.search(r"\bcp\b[^\n]*fixtures/lists[^\n]*/var/ossec/etc/lists", readme),
          "README не предлагает копировать тестовые списки в рабочие")

    for rel in EXPECTED_FILES:
        if rel == "CHANGELOG.md":
            continue
        check(rel in changelog or rel.replace("tests/fixtures/lists/", "tests/fixtures/lists/") in changelog,
              "CHANGELOG упоминает %s" % rel)


def main() -> int:
    check_tree()
    check_xml()
    decs = check_decoders()
    rules = check_rules()
    check_consistency(rules)
    check_emulation(decs, rules)
    check_generator(decs, rules)
    check_patch_tool()
    check_selftest()
    if (ROOT / "README.md").exists() and (ROOT / "CHANGELOG.md").exists():
        check_docs()
    print()
    if failures:
        print("ПРОВЕРКА НЕ ПРОЙДЕНА: %d ошибок из %d" % (len(failures), len(failures) + counter["ok"]))
        for f in failures:
            print("  - " + f)
        return 1
    print("ПРОВЕРКА ПРОЙДЕНА: %d проверок" % counter["ok"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
