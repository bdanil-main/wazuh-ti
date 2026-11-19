#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wazuh-ti-updater: ежедневное обновление Threat Intelligence CDB-списков для Wazuh 4.x.

Источники (бесплатные):
  * URLhaus (abuse.ch)   - домены из hostfile и хосты из URL (CSV-дамп);
  * ThreatFox (abuse.ch) - домены C2/payload из hostfile и из полного CSV-дампа;
  * Phishing Army        - агрегированный список phishing-доменов.

Что делает скрипт:
  1. Скачивает фиды (HTTPS, повторы, лимит размера, проверка на HTML/JSON-ошибки).
  2. Извлекает домены, нормализует (lowercase, без конечной точки, проверка формата),
     удаляет дубликаты, отбрасывает IP-адреса и мусор.
  3. Хранит историю "last seen" по каждому источнику (retention), поэтому при сбое
     источника список не теряет его IOC сразу.
  4. Формирует CDB-списки: общий (domain:Источник1,Источник2), по одному на источник
     и список доменов, найденных минимум в двух источниках.
  5. Пишет во временные файлы, проверяет целостность, делает бэкап, атомарно заменяет
     рабочие списки, валидирует конфигурацию Wazuh (wazuh-analysisd -t) и применяет
     изменения без полного рестарта (wazuh-control reload).
  6. При ошибке валидации автоматически восстанавливает предыдущие списки.

Коды возврата:
  0 - успех (в т.ч. "изменений нет")
  1 - внутренняя ошибка / ошибка конфигурации
  2 - источник недоступен и резервных данных нет (рабочие списки НЕ тронуты)
  3 - не прошла проверка списков или конфигурации Wazuh (выполнен откат)
  4 - списки обновлены, но reload Wazuh завершился ошибкой (повтор при следующем запуске)
  5 - уже запущен другой экземпляр
  6 - списки обновлены, но часть источников работала в деградированном режиме
"""
from __future__ import annotations

import argparse
import configparser
import csv
import fcntl
import grp
import hashlib
import http.client
import io
import json
import logging
import logging.handlers
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

VERSION = "1.1.0"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_SOURCE = 2
EXIT_VALIDATE = 3
EXIT_RELOAD = 4
EXIT_LOCKED = 5
EXIT_DEGRADED = 6

LOG = logging.getLogger("wazuh-ti")

DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$"
)
CDB_LINE_RE = re.compile(r"^[a-z0-9.-]+:[A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+)*$")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
HTML_RE = re.compile(r"^\s*<(?:!doctype|html|head|body)", re.IGNORECASE)

SENTINEL_LINE = "empty-list-sentinel.invalid:none"

PARSERS = ("hostfile", "plain", "csv_url", "csv_ioc")
COMPRESSIONS = ("none", "zip")
AUTH_MODES = ("none", "abusech")


class ConfigError(Exception):
    pass


class FeedError(Exception):
    pass


class ShrinkError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Конфигурация
# --------------------------------------------------------------------------- #
@dataclass
class Feed:
    name: str
    source_id: str
    url: str
    parser: str
    auth: str = "none"
    required: bool = True
    compression: str = "none"
    min_entries: int = 1


@dataclass
class Source:
    id: str
    label: str
    list_name: str
    retention_days: int
    min_entries: int
    order: int
    feeds: List[Feed] = field(default_factory=list)


@dataclass
class Config:
    lists_dir: Path
    state_dir: Path
    log_file: str
    auth_key_file: str
    allowlist_file: str
    owner_group: str
    file_mode: int
    merged_list: str
    multi_list: str
    keep_backups: int
    http_timeout: int
    http_retries: int
    max_download_bytes: int
    fallback_days: int
    max_shrink_percent: int
    min_shrink_base: int
    allow_partial: bool
    validate_command: str
    reload_command: str
    command_timeout: int
    user_agent: str
    sources: List[Source]


def load_config(path: str) -> Config:
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#",))
    if not cp.read(path, encoding="utf-8"):
        raise ConfigError("не удалось прочитать конфигурацию: %s" % path)
    if "general" not in cp:
        raise ConfigError("в конфигурации нет секции [general]")
    g = cp["general"]

    try:
        cfg_general = dict(
            lists_dir=Path(g.get("lists_dir", "/var/ossec/etc/lists")),
            state_dir=Path(g.get("state_dir", "/var/ossec/wodles/wazuh-ti/state")),
            log_file=g.get("log_file", "/var/ossec/logs/wazuh-ti-updater.log").strip(),
            auth_key_file=g.get("auth_key_file", "/var/ossec/wodles/wazuh-ti/abusech.key").strip(),
            allowlist_file=g.get("allowlist_file", "/var/ossec/wodles/wazuh-ti/allowlist.txt").strip(),
            owner_group=g.get("owner_group", "wazuh").strip(),
            file_mode=int(g.get("file_mode", "0660"), 8),
            merged_list=g.get("merged_list", "ti-domains").strip(),
            multi_list=g.get("multi_list", "ti-multi").strip(),
            keep_backups=g.getint("keep_backups", 7),
            http_timeout=g.getint("http_timeout", 60),
            http_retries=g.getint("http_retries", 3),
            max_download_bytes=g.getint("max_download_mb", 300) * 1024 * 1024,
            fallback_days=g.getint("fallback_days", 3),
            max_shrink_percent=g.getint("max_shrink_percent", 60),
            min_shrink_base=g.getint("min_shrink_base", 500),
            allow_partial=g.getboolean("allow_partial", False),
            validate_command=g.get("validate_command", "").strip(),
            reload_command=g.get("reload_command", "").strip(),
            command_timeout=g.getint("command_timeout", 300),
            user_agent=g.get("user_agent", "wazuh-ti-updater/%s" % VERSION).strip(),
        )
    except ValueError as exc:
        raise ConfigError("некорректное значение в [general]: %s" % exc)

    for key in ("merged_list", "multi_list"):
        if not NAME_RE.match(cfg_general[key]):
            raise ConfigError("%s: допустимы только буквы, цифры, '_' и '-'" % key)

    sources: Dict[str, Source] = {}
    for sec in cp.sections():
        if not sec.startswith("source:"):
            continue
        sid = sec.split(":", 1)[1].strip()
        s = cp[sec]
        if not NAME_RE.match(sid):
            raise ConfigError("[%s]: недопустимый идентификатор источника" % sec)
        if not s.getboolean("enabled", True):
            continue
        label = s.get("label", sid).strip()
        list_name = s.get("list", "ti-%s" % sid).strip()
        if not NAME_RE.match(label):
            raise ConfigError("[%s] label: допустимы только буквы, цифры, '_' и '-'" % sec)
        if not NAME_RE.match(list_name):
            raise ConfigError("[%s] list: допустимы только буквы, цифры, '_' и '-'" % sec)
        sources[sid] = Source(
            id=sid,
            label=label,
            list_name=list_name,
            retention_days=s.getint("retention_days", 0),
            min_entries=s.getint("min_entries", 1),
            order=s.getint("order", 100),
        )

    for sec in cp.sections():
        if not sec.startswith("feed:"):
            continue
        fname = sec.split(":", 1)[1].strip()
        f = cp[sec]
        if not f.getboolean("enabled", True):
            continue
        sid = f.get("source", "").strip()
        if sid not in sources:
            # источник выключен или не существует - фид пропускаем
            continue
        parser = f.get("parser", "").strip()
        compression = f.get("compression", "none").strip()
        auth = f.get("auth", "none").strip()
        if parser not in PARSERS:
            raise ConfigError("[%s] parser должен быть одним из %s" % (sec, ", ".join(PARSERS)))
        if compression not in COMPRESSIONS:
            raise ConfigError("[%s] compression должен быть одним из %s" % (sec, ", ".join(COMPRESSIONS)))
        if auth not in AUTH_MODES:
            raise ConfigError("[%s] auth должен быть одним из %s" % (sec, ", ".join(AUTH_MODES)))
        url = f.get("url", "").strip()
        if not url.lower().startswith("https://"):
            raise ConfigError("[%s] url должен начинаться с https://" % sec)
        sources[sid].feeds.append(
            Feed(
                name=fname,
                source_id=sid,
                url=url,
                parser=parser,
                auth=auth,
                required=f.getboolean("required", True),
                compression=compression,
                min_entries=f.getint("min_entries", 1),
            )
        )

    ordered = sorted(sources.values(), key=lambda x: (x.order, x.id))
    if not ordered:
        raise ConfigError("не включено ни одного источника")
    names = [cfg_general["merged_list"], cfg_general["multi_list"]] + [s.list_name for s in ordered]
    if len(set(names)) != len(names):
        raise ConfigError("имена CDB-списков должны быть уникальными: %s" % ", ".join(names))
    labels = [s.label for s in ordered]
    if len(set(labels)) != len(labels):
        raise ConfigError("метки источников (label) должны быть уникальными")
    for s in ordered:
        if not s.feeds:
            raise ConfigError("у источника %s нет ни одного включённого фида" % s.id)

    return Config(sources=ordered, **cfg_general)


# --------------------------------------------------------------------------- #
# Нормализация доменов и парсеры
# --------------------------------------------------------------------------- #
def normalize_domain(raw: Optional[str]) -> Optional[str]:
    """Приводит значение к нормализованному домену или возвращает None."""
    if raw is None:
        return None
    value = raw.strip().strip("\"'").strip().lower()
    if not value:
        return None
    if value.startswith("*."):
        value = value[2:]
    value = value.rstrip(".")
    if not value:
        return None
    if any(ch in value for ch in ":/@?#\\ \t[]"):
        return None
    if not value.isascii():
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if not DOMAIN_RE.match(value):
        return None
    return value


def host_from_url(url: Optional[str]) -> Optional[str]:
    """Извлекает и нормализует хост из URL. IP-адреса отбрасываются."""
    if url is None:
        return None
    u = url.strip().strip("\"'").strip()
    if not u:
        return None
    if "://" not in u:
        u = "http://" + u
    try:
        host = urllib.parse.urlsplit(u).hostname
    except ValueError:
        return None
    if not host:
        return None
    return normalize_domain(host)


@dataclass
class ParseResult:
    domains: Set[str] = field(default_factory=set)
    total: int = 0
    rejected: int = 0
    ignored: int = 0

    def add_domain(self, raw: str) -> None:
        self.total += 1
        d = normalize_domain(raw)
        if d:
            self.domains.add(d)
        else:
            self.rejected += 1

    def add_url(self, url: str) -> None:
        self.total += 1
        d = host_from_url(url)
        if d:
            self.domains.add(d)
        else:
            self.rejected += 1


def parse_hostfile(text: str, res: ParseResult) -> None:
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        hosts = parts[1:] if len(parts) > 1 else parts
        for host in hosts:
            res.add_domain(host)


def parse_plain(text: str, res: ParseResult) -> None:
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;!":
            continue
        res.add_domain(line.split()[0])


def _find_csv_header(text: str, wanted: str) -> Tuple[Optional[List[str]], List[str]]:
    """Возвращает (колонки из комментария-заголовка, строки данных)."""
    header: Optional[List[str]] = None
    data_lines: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            body = stripped.lstrip("#").strip()
            if header is None and "," in body:
                try:
                    cols = [c.strip().lower() for c in next(csv.reader([body], skipinitialspace=True))]
                except (csv.Error, StopIteration):
                    continue
                if wanted in cols:
                    header = cols
            continue
        data_lines.append(line)
    return header, data_lines


def parse_csv(text: str, kind: str, res: ParseResult) -> None:
    wanted = "url" if kind == "url" else "ioc_value"
    header, data_lines = _find_csv_header(text, wanted)
    try:
        rows = list(csv.reader(data_lines, skipinitialspace=True))
    except csv.Error as exc:
        raise FeedError("повреждённый CSV: %s" % exc)
    if header is None and rows:
        first = [c.strip().lower() for c in rows[0]]
        if wanted in first:
            header = first
            rows = rows[1:]
    if kind == "url":
        idx = header.index("url") if header else 2
        for row in rows:
            if len(row) <= idx:
                res.total += 1
                res.rejected += 1
                continue
            res.add_url(row[idx])
    else:
        vidx = header.index("ioc_value") if header else 2
        tidx = header.index("ioc_type") if header and "ioc_type" in header else 3
        for row in rows:
            if len(row) <= max(vidx, tidx):
                res.total += 1
                res.rejected += 1
                continue
            ioc_type = row[tidx].strip().lower()
            if ioc_type == "domain":
                res.add_domain(row[vidx])
            elif ioc_type == "url":
                res.add_url(row[vidx])
            else:
                res.ignored += 1


def parse_feed_text(parser: str, text: str) -> ParseResult:
    res = ParseResult()
    if parser == "hostfile":
        parse_hostfile(text, res)
    elif parser == "plain":
        parse_plain(text, res)
    elif parser == "csv_url":
        parse_csv(text, "url", res)
    elif parser == "csv_ioc":
        parse_csv(text, "ioc", res)
    else:
        raise FeedError("неизвестный парсер: %s" % parser)
    return res


# --------------------------------------------------------------------------- #
# Загрузка
# --------------------------------------------------------------------------- #
_FIXTURES: Dict[str, bytes] = {}  # используется только в --selftest


def redact(text: str, secret: Optional[str]) -> str:
    if secret:
        text = text.replace(secret, "***")
        text = text.replace(urllib.parse.quote(secret, safe=""), "***")
    return text


def http_get(url: str, cfg: Config, secret: Optional[str]) -> bytes:
    last = "неизвестная ошибка"
    for attempt in range(1, cfg.http_retries + 1):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": cfg.user_agent, "Accept": "*/*"}
            )
            with urllib.request.urlopen(req, timeout=cfg.http_timeout) as resp:
                length_hdr = resp.headers.get("Content-Length")
                length = int(length_hdr) if length_hdr and length_hdr.isdigit() else None
                if length is not None and length > cfg.max_download_bytes:
                    raise FeedError("ответ слишком большой: %d байт" % length)
                buf = bytearray()
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    if len(buf) > cfg.max_download_bytes:
                        raise FeedError("ответ превысил лимит %d байт" % cfg.max_download_bytes)
                if length is not None and len(buf) != length:
                    raise OSError("обрыв передачи: получено %d из %d байт" % (len(buf), length))
                return bytes(buf)
        except FeedError:
            raise
        except urllib.error.HTTPError as exc:
            last = "HTTP %d" % exc.code
            if exc.code in (400, 401, 403, 404, 410):
                raise FeedError("%s (повтор не поможет; проверьте URL и Auth-Key)" % last)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            last = redact(str(exc), secret)
        LOG.warning("попытка %d/%d не удалась: %s", attempt, cfg.http_retries, last)
        if attempt < cfg.http_retries:
            time.sleep(min(60, 5 * 2 ** (attempt - 1)))
    raise FeedError("загрузка не удалась после %d попыток: %s" % (cfg.http_retries, last))


def fetch_bytes(feed: Feed, cfg: Config, key: Optional[str]) -> bytes:
    if feed.name in _FIXTURES:
        return _FIXTURES[feed.name]
    url = feed.url
    secret: Optional[str] = None
    if "{AUTH_KEY}" in url or feed.auth == "abusech":
        if not key:
            raise FeedError("не найден Auth-Key abuse.ch (файл %s)" % cfg.auth_key_file)
        if "{AUTH_KEY}" not in url:
            raise FeedError("для auth=abusech в url должен быть маркер {AUTH_KEY}")
        secret = key
        url = url.replace("{AUTH_KEY}", urllib.parse.quote(key, safe=""))
    return http_get(url, cfg, secret)


def extract_text(feed: Feed, cfg: Config, data: bytes) -> str:
    if feed.compression == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                members = [m for m in zf.infolist() if not m.is_dir()]
                if not members:
                    raise FeedError("ZIP-архив пуст")
                member = members[0]
                limit = cfg.max_download_bytes * 5
                if member.file_size > limit:
                    raise FeedError("распакованный файл слишком большой")
                with zf.open(member) as fh:
                    raw = fh.read(limit + 1)
                if len(raw) > limit:
                    raise FeedError("распакованный файл слишком большой")
        except zipfile.BadZipFile:
            raise FeedError("повреждённый ZIP-архив")
        data = raw
    text = data.decode("utf-8", errors="replace")
    if text.startswith("﻿"):
        text = text[1:]
    return text


def fetch_feed(feed: Feed, cfg: Config, key: Optional[str]) -> ParseResult:
    data = fetch_bytes(feed, cfg, key)
    if not data:
        raise FeedError("пустой ответ")
    text = extract_text(feed, cfg, data)
    if HTML_RE.match(text):
        raise FeedError("получен HTML вместо данных (проверьте URL, Auth-Key и доступ)")
    stripped = text.lstrip()
    if stripped.startswith("{") and '"query_status"' in stripped[:400]:
        raise FeedError("сервис вернул сообщение об ошибке: %s" % stripped[:120].replace("\n", " "))
    res = parse_feed_text(feed.parser, text)
    if res.total >= 100 and res.rejected / float(res.total) > 0.5:
        raise FeedError(
            "ответ похож на повреждённый: отклонено %d из %d записей" % (res.rejected, res.total)
        )
    if len(res.domains) < feed.min_entries:
        raise FeedError(
            "слишком мало доменов: %d (минимум %d)" % (len(res.domains), feed.min_entries)
        )
    return res


# --------------------------------------------------------------------------- #
# Состояние (история last-seen)
# --------------------------------------------------------------------------- #
def load_store(path: Path) -> Dict[str, int]:
    try:
        with open(str(path), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        LOG.error("не удалось прочитать историю %s: %s (будет создана заново)", path, exc)
        return {}
    if not isinstance(data, dict):
        LOG.error("история %s имеет неверный формат (будет создана заново)", path)
        return {}
    out: Dict[str, int] = {}
    for k, v in data.items():
        if isinstance(k, str) and isinstance(v, int):
            out[k] = v
    return out


def atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_name(".%s.tmp.%d" % (path.name, os.getpid()))
    tmp.unlink(missing_ok=True)
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(str(tmp), str(path))
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def save_store(path: Path, store: Dict[str, int]) -> None:
    atomic_write_text(path, json.dumps(store, separators=(",", ":"), sort_keys=True))


def load_key(cfg: Config) -> Optional[str]:
    path = Path(cfg.auth_key_file)
    try:
        key = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        LOG.error("не удалось прочитать файл ключа %s: %s", path, exc)
        return None
    try:
        mode = path.stat().st_mode & 0o077
        if mode:
            LOG.warning("файл ключа %s доступен группе/всем (chmod 600 рекомендуется)", path)
    except OSError:
        pass
    return key or None


def load_allowlist(cfg: Config) -> Set[str]:
    path = Path(cfg.allowlist_file)
    out: Set[str] = set()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return out
    except OSError as exc:
        LOG.error("не удалось прочитать allowlist %s: %s", path, exc)
        return out
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        d = normalize_domain(line)
        if d:
            out.add(d)
        else:
            LOG.warning("allowlist: пропущена некорректная запись %r", line)
    return out


# --------------------------------------------------------------------------- #
# CDB
# --------------------------------------------------------------------------- #
def build_cdb(entries: Dict[str, List[str]]) -> str:
    if not entries:
        return SENTINEL_LINE + "\n"
    return "".join("%s:%s\n" % (d, ",".join(srcs)) for d, srcs in sorted(entries.items()))


def validate_cdb_text(text: str) -> int:
    """Проверяет формат CDB, возвращает число ключей. Бросает ValueError."""
    if not text.endswith("\n"):
        raise ValueError("файл не заканчивается переводом строки")
    seen: Set[str] = set()
    for num, line in enumerate(text.split("\n")[:-1], 1):
        if not CDB_LINE_RE.match(line):
            raise ValueError("строка %d имеет неверный формат: %r" % (num, line[:80]))
        key = line.split(":", 1)[0]
        if key in seen:
            raise ValueError("строка %d: повторяющийся ключ %s" % (num, key))
        seen.add(key)
    return len(seen)


def read_keys(path: Path) -> Set[str]:
    keys: Set[str] = set()
    try:
        with open(str(path), "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if ":" in line:
                    keys.add(line.split(":", 1)[0])
    except FileNotFoundError:
        pass
    except OSError as exc:
        LOG.warning("не удалось прочитать %s: %s", path, exc)
    keys.discard(SENTINEL_LINE.split(":", 1)[0])
    return keys


def resolve_gid(cfg: Config) -> Optional[int]:
    if not cfg.owner_group:
        return None
    try:
        return grp.getgrnam(cfg.owner_group).gr_gid
    except KeyError:
        LOG.warning("группа %s не найдена, права владельца не меняются", cfg.owner_group)
        return None


def apply_perms(path: Path, mode: int, gid: Optional[int]) -> None:
    os.chmod(str(path), mode)
    if gid is not None:
        try:
            os.chown(str(path), -1, gid)
        except OSError as exc:
            LOG.warning("chown группы для %s не удался: %s", path, exc)


def write_new_file(path: Path, text: str, mode: int, gid: Optional[int]) -> None:
    path.unlink(missing_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    apply_perms(path, mode, gid)


def fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def run_cmd(cmdline: str, timeout: int) -> Tuple[int, str]:
    try:
        argv = shlex.split(cmdline)
    except ValueError as exc:
        return 127, "некорректная команда: %s" % exc
    if not argv:
        return 0, ""
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
            errors="replace",
        )
        return proc.returncode, proc.stdout or ""
    except FileNotFoundError:
        return 127, "команда не найдена: %s" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, "превышен таймаут %d с" % timeout
    except OSError as exc:
        return 126, str(exc)


def log_tail(prefix: str, output: str, lines: int = 15) -> None:
    for line in output.strip().splitlines()[-lines:]:
        LOG.error("%s %s", prefix, line)


# --------------------------------------------------------------------------- #
# Публикация списков
# --------------------------------------------------------------------------- #
def rollback(
    cfg: Config, replaced: List[str], backup_dir: Path, had_prior: Dict[str, bool], gid: Optional[int]
) -> None:
    LOG.error("ВЫПОЛНЯЕТСЯ ОТКАТ списков: %s", ", ".join(replaced))
    for name in replaced:
        target = cfg.lists_dir / name
        try:
            if had_prior.get(name):
                tmp = cfg.lists_dir / (".%s.restore.%d" % (name, os.getpid()))
                shutil.copy2(str(backup_dir / name), str(tmp))
                apply_perms(tmp, cfg.file_mode, gid)
                os.replace(str(tmp), str(target))
                LOG.error("восстановлен предыдущий список %s", name)
            else:
                target.unlink(missing_ok=True)
                LOG.error("удалён новый список %s (предыдущего не было)", name)
        except OSError as exc:
            LOG.error("КРИТИЧНО: не удалось восстановить %s: %s (бэкап: %s)", name, exc, backup_dir)
    fsync_dir(cfg.lists_dir)


def prune_backups(cfg: Config) -> None:
    root = cfg.state_dir / "backups"
    if not root.is_dir():
        return
    dirs = sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name)
    for old in dirs[: max(0, len(dirs) - cfg.keep_backups)]:
        shutil.rmtree(str(old), ignore_errors=True)


def publish(cfg: Config, outputs: Dict[str, Tuple[str, int]], run_id: str) -> Tuple[int, List[str], str]:
    """Записывает списки. Возвращает (код, изменённые списки, статус reload)."""
    gid = resolve_gid(cfg)
    reload_marker = cfg.state_dir / "needs_reload"
    staged: List[Tuple[str, Path, Path]] = []
    unchanged: List[str] = []
    try:
        for name, (text, expected) in outputs.items():
            target = cfg.lists_dir / name
            try:
                if target.read_text(encoding="utf-8") == text:
                    unchanged.append(name)
                    continue
            except FileNotFoundError:
                pass
            except (OSError, UnicodeDecodeError):
                pass
            tmp = cfg.lists_dir / (".%s.new.%d" % (name, os.getpid()))
            write_new_file(tmp, text, cfg.file_mode, gid)
            readback = tmp.read_text(encoding="utf-8")
            if hashlib.sha256(readback.encode("utf-8")).digest() != hashlib.sha256(text.encode("utf-8")).digest():
                raise ValueError("контрольная сумма временного файла %s не совпала" % name)
            count = validate_cdb_text(readback)
            if count != expected:
                raise ValueError("%s: ожидалось %d ключей, в файле %d" % (name, expected, count))
            staged.append((name, tmp, target))
    except (OSError, ValueError) as exc:
        LOG.error("проверка временных файлов не пройдена: %s. Рабочие списки не изменены.", exc)
        for _, tmp, _t in staged:
            tmp.unlink(missing_ok=True)
        for name in outputs:
            (cfg.lists_dir / (".%s.new.%d" % (name, os.getpid()))).unlink(missing_ok=True)
        return EXIT_VALIDATE, [], "не выполнялся"

    need_reload = reload_marker.exists()
    if not staged:
        LOG.info("изменений в списках нет")
        if not need_reload:
            return EXIT_OK, [], "не требуется"
        LOG.warning("ранее не был выполнен reload Wazuh - повторяю")
    changed = [n for n, _, _ in staged]

    replaced: List[str] = []
    had_prior: Dict[str, bool] = {}
    backup_dir = cfg.state_dir / "backups" / run_id
    if staged:
        backup_dir.mkdir(parents=True, exist_ok=True)
        for name, tmp, target in staged:
            had_prior[name] = target.exists()
            if had_prior[name]:
                shutil.copy2(str(target), str(backup_dir / name))
        try:
            for name, tmp, target in staged:
                os.replace(str(tmp), str(target))
                replaced.append(name)
            fsync_dir(cfg.lists_dir)
        except OSError as exc:
            LOG.error("ошибка при замене списков: %s", exc)
            for _, tmp, _t in staged:
                tmp.unlink(missing_ok=True)
            rollback(cfg, replaced, backup_dir, had_prior, gid)
            return EXIT_VALIDATE, [], "не выполнялся"
        try:
            reload_marker.write_text(run_id + "\n", encoding="utf-8")
        except OSError as exc:
            LOG.warning("не удалось создать маркер reload: %s", exc)
        LOG.info("обновлены списки: %s (бэкап предыдущих: %s)", ", ".join(changed), backup_dir)

    if cfg.validate_command:
        LOG.info("проверка конфигурации Wazuh: %s", cfg.validate_command)
        rc, out = run_cmd(cfg.validate_command, cfg.command_timeout)
        if rc != 0:
            LOG.error("проверка конфигурации Wazuh завершилась с кодом %d", rc)
            log_tail("validate:", out)
            if replaced:
                rollback(cfg, replaced, backup_dir, had_prior, gid)
                reload_marker.unlink(missing_ok=True)
                rc2, out2 = run_cmd(cfg.validate_command, cfg.command_timeout)
                if rc2 == 0:
                    LOG.error("после отката конфигурация Wazuh корректна, предыдущие списки восстановлены")
                else:
                    LOG.error("после отката проверка всё ещё падает (код %d) - причина не в списках TI", rc2)
                    log_tail("validate(после отката):", out2)
            return EXIT_VALIDATE, [], "не выполнялся"

    reload_status = "пропущен (reload_command не задан)"
    if cfg.reload_command:
        LOG.info("применение изменений без рестарта: %s", cfg.reload_command)
        rc, out = run_cmd(cfg.reload_command, cfg.command_timeout)
        if rc != 0:
            LOG.error("reload Wazuh завершился с кодом %d (списки записаны, повтор при следующем запуске)", rc)
            log_tail("reload:", out)
            return EXIT_RELOAD, changed, "ошибка (код %d)" % rc
        reload_status = "выполнен"
    reload_marker.unlink(missing_ok=True)
    prune_backups(cfg)
    return EXIT_OK, changed, reload_status


# --------------------------------------------------------------------------- #
# Основной сценарий
# --------------------------------------------------------------------------- #
def check_shrink(cfg: Config, name: str, new_count: int, force: bool) -> None:
    prev = len(read_keys(cfg.lists_dir / name))
    if force or prev < cfg.min_shrink_base:
        return
    floor = prev * (100 - cfg.max_shrink_percent) / 100.0
    if new_count < floor:
        raise ShrinkError(
            "список %s сократился с %d до %d записей (порог -%d%%)"
            % (name, prev, new_count, cfg.max_shrink_percent)
        )


def write_status(cfg: Config, payload: Dict[str, object]) -> None:
    try:
        atomic_write_text(cfg.state_dir / "status.json", json.dumps(payload, ensure_ascii=False, indent=2))
    except OSError as exc:
        LOG.warning("не удалось записать status.json: %s", exc)


def run(cfg: Config, args: argparse.Namespace) -> int:
    started = time.time()
    now = int(started)
    run_id = time.strftime("%Y%m%dT%H%M%S", time.localtime(started))

    for sub in ("seen", "backups"):
        (cfg.state_dir / sub).mkdir(parents=True, exist_ok=True)
    if not cfg.lists_dir.is_dir():
        LOG.error("каталог списков не существует: %s", cfg.lists_dir)
        return EXIT_ERROR

    lock_fh = open(str(cfg.state_dir / "updater.lock"), "w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        LOG.error("другой экземпляр обновления уже выполняется")
        return EXIT_LOCKED

    selected = set(args.source or [])
    known = {s.id for s in cfg.sources}
    unknown = selected - known
    if unknown:
        LOG.error("неизвестные источники в --source: %s (доступны: %s)", ", ".join(sorted(unknown)), ", ".join(sorted(known)))
        return EXIT_ERROR

    key = load_key(cfg)
    allow = load_allowlist(cfg)
    if allow:
        LOG.info("allowlist: %d доменов", len(allow))

    effective: Dict[str, Set[str]] = {}
    report: Dict[str, Dict[str, object]] = {}
    fatal: List[str] = []
    degraded: List[str] = []

    for src in cfg.sources:
        store_path = cfg.state_dir / "seen" / ("%s.json" % src.id)
        store = load_store(store_path)
        fresh: Set[str] = set()
        feed_reports: List[Dict[str, object]] = []
        required_failed = False
        any_ok = False
        do_fetch = not selected or src.id in selected

        if do_fetch:
            for feed in src.feeds:
                t0 = time.time()
                try:
                    res = fetch_feed(feed, cfg, key)
                    fresh |= res.domains
                    any_ok = True
                    LOG.info(
                        "[%s/%s] OK: доменов=%d (записей=%d, отклонено=%d, прочих IOC=%d) за %.1f с",
                        src.label, feed.name, len(res.domains), res.total, res.rejected, res.ignored,
                        time.time() - t0,
                    )
                    feed_reports.append({"feed": feed.name, "status": "ok", "domains": len(res.domains)})
                except FeedError as exc:
                    LOG.error("[%s/%s] ОШИБКА: %s", src.label, feed.name, exc)
                    feed_reports.append({"feed": feed.name, "status": "error", "error": str(exc)})
                    if feed.required:
                        required_failed = True
                except Exception as exc:  # непредвиденная ошибка парсера не должна ронять весь запуск
                    LOG.exception("[%s/%s] НЕПРЕДВИДЕННАЯ ОШИБКА: %s", src.label, feed.name, exc)
                    feed_reports.append({"feed": feed.name, "status": "error", "error": repr(exc)})
                    if feed.required:
                        required_failed = True
        else:
            LOG.info("[%s] обновление пропущено (--source), используется накопленная история", src.label)

        use_fallback = (not do_fetch) or required_failed or not any_ok
        window_days = src.retention_days
        if use_fallback:
            window_days = max(src.retention_days, cfg.fallback_days)
        for d in fresh:
            store[d] = now
        cutoff = now - window_days * 86400
        eff = {d for d, ts in store.items() if ts >= cutoff} | fresh
        keep_cutoff = now - max(src.retention_days, cfg.fallback_days) * 86400
        pruned = {d: ts for d, ts in store.items() if ts >= keep_cutoff}

        if do_fetch and not args.dry_run:
            try:
                save_store(store_path, pruned)
            except OSError as exc:
                LOG.warning("[%s] не удалось сохранить историю: %s", src.label, exc)

        status = "ok"
        if use_fallback and do_fetch:
            status = "stale"
            LOG.warning(
                "[%s] деградированный режим: используются накопленные данные за %d дн. (доменов=%d)",
                src.label, window_days, len(eff),
            )
            degraded.append(src.label)
        elif not do_fetch:
            status = "cached"
        if len(eff) < src.min_entries:
            status = "failed"
            msg = "[%s] доменов %d < минимума %d: источник непригоден" % (src.label, len(eff), src.min_entries)
            LOG.error(msg)
            fatal.append(msg)
        eff -= allow
        effective[src.id] = eff
        report[src.id] = {
            "label": src.label, "status": status, "fresh": len(fresh),
            "effective": len(eff), "feeds": feed_reports,
        }

    if fatal and not cfg.allow_partial:
        LOG.error("ОБНОВЛЕНИЕ ПРЕРВАНО: рабочие CDB-списки не изменялись. %s", "; ".join(fatal))
        write_status(cfg, {"time": now, "result": "aborted", "sources": report})
        return EXIT_SOURCE
    if fatal:
        LOG.warning("allow_partial=true: продолжаем несмотря на недоступные источники")

    domain_sources: Dict[str, List[str]] = {}
    per_source: Dict[str, Dict[str, List[str]]] = {}
    for src in cfg.sources:
        per_source[src.list_name] = {d: [src.label] for d in effective[src.id]}
        for d in sorted(effective[src.id]):
            domain_sources.setdefault(d, []).append(src.label)
    multi = {d: s for d, s in domain_sources.items() if len(s) > 1}

    all_lists: Dict[str, Dict[str, List[str]]] = {cfg.merged_list: domain_sources}
    all_lists.update(per_source)
    all_lists[cfg.multi_list] = multi

    outputs: Dict[str, Tuple[str, int]] = {}
    try:
        for name, entries in all_lists.items():
            text = build_cdb(entries)
            expected = len(entries) if entries else 1
            validate_cdb_text(text)
            check_shrink(cfg, name, len(entries), args.force)
            outputs[name] = (text, expected)
    except ShrinkError as exc:
        LOG.error("ОБНОВЛЕНИЕ ПРЕРВАНО (защита от аномального сокращения): %s. Используйте --force после проверки.", exc)
        write_status(cfg, {"time": now, "result": "aborted-shrink", "sources": report})
        return EXIT_SOURCE
    except ValueError as exc:
        LOG.error("собранный список некорректен: %s", exc)
        return EXIT_VALIDATE

    for name, entries in all_lists.items():
        old = read_keys(cfg.lists_dir / name)
        new = set(entries)
        LOG.info("список %-16s записей=%d (+%d / -%d)", name, len(new), len(new - old), len(old - new))

    summary = ", ".join("%s=%d" % (s.label, len(effective[s.id])) for s in cfg.sources)

    if args.dry_run:
        LOG.info("DRY-RUN: %s; merged=%d; multi=%d. Файлы не записывались.", summary, len(domain_sources), len(multi))
        return EXIT_OK

    code, changed, reload_status = publish(cfg, outputs, run_id)
    write_status(
        cfg,
        {
            "time": now, "result": "ok" if code == EXIT_OK else "error", "exit_code": code,
            "changed_lists": changed, "reload": reload_status, "merged": len(domain_sources),
            "multi": len(multi), "sources": report, "duration_sec": round(time.time() - started, 1),
        },
    )
    LOG.info(
        "ИТОГ: %s; merged=%d; multi=%d; изменено списков=%d; reload=%s; код=%d; %.1f с",
        summary, len(domain_sources), len(multi), len(changed), reload_status, code, time.time() - started,
    )
    if code == EXIT_OK and degraded:
        LOG.warning("обновление выполнено, но источники работали в деградированном режиме: %s", ", ".join(degraded))
        return EXIT_DEGRADED
    return code


# --------------------------------------------------------------------------- #
# Самотест (без сети и без Wazuh)
# --------------------------------------------------------------------------- #
SELFTEST_CONFIG = """
[general]
lists_dir = {lists}
state_dir = {state}
log_file =
auth_key_file = {state}/none.key
allowlist_file = {state}/allowlist.txt
owner_group =
file_mode = 0644
min_shrink_base = 500
fallback_days = 3

[source:urlhaus]
label = URLhaus
list = ti-urlhaus
order = 1
min_entries = 3
retention_days = 14

[source:threatfox]
label = ThreatFox
list = ti-threatfox
order = 2
min_entries = 3
retention_days = 30

[source:phishingarmy]
label = PhishingArmy
list = ti-phishingarmy
order = 3
min_entries = 2
retention_days = 7

[feed:urlhaus-hostfile]
source = urlhaus
url = https://example.invalid/urlhaus-hostfile
parser = hostfile
required = false

[feed:urlhaus-csv]
source = urlhaus
url = https://example.invalid/urlhaus-csv
parser = csv_url

[feed:threatfox-hostfile]
source = threatfox
url = https://example.invalid/threatfox-hostfile
parser = hostfile
required = false

[feed:threatfox-csv]
source = threatfox
url = https://example.invalid/threatfox-csv
parser = csv_ioc
compression = zip

[feed:phishingarmy-domains]
source = phishingarmy
url = https://example.invalid/phishingarmy
parser = plain
"""

SELFTEST_URLHAUS_HOSTFILE = (
    "################################################################\n"
    "# abuse.ch URLhaus Host file\n"
    "################################################################\n"
    "127.0.0.1\turlhaus-malware.test\n"
    "127.0.0.1\tmulti-source.test\n"
    "127.0.0.1\tUPPER-CASE.test.\n"
    "127.0.0.1\t203.0.113.7\n"
    "127.0.0.1\tbad_domain!.test\n"
    "127.0.0.1\n"
)

SELFTEST_URLHAUS_CSV = (
    "################################################################\n"
    "# abuse.ch URLhaus Database Dump (CSV - recent URLs only)\n"
    "################################################################\n"
    "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    '"1","2026-11-12 10:00:00","http://urlhaus-malware.test/a.exe","online","2026-11-12 10:00:00","malware_download","elf","https://urlhaus.abuse.ch/url/1/","reporter1"\n'
    '"2","2026-11-12 10:00:00","http://203.0.113.9:8080/bin","online","2026-11-12 10:00:00","malware_download","elf","https://urlhaus.abuse.ch/url/2/","reporter1"\n'
    '"3","2026-11-12 10:00:00","https://CDN.urlhaus-malware.test:8443/x?y=1","online","2026-11-12 10:00:00","malware_download","exe","https://urlhaus.abuse.ch/url/3/","reporter2"\n'
    '"4","2026-11-12 10:00:00","not a url at all","online","2026-11-12 10:00:00","malware_download","exe","https://urlhaus.abuse.ch/url/4/","reporter2"\n'
)

SELFTEST_THREATFOX_HOSTFILE = (
    "# ThreatFox hostfile\n"
    "127.0.0.1 threatfox-c2.test\n"
    "127.0.0.1 multi-source.test\n"
)

SELFTEST_THREATFOX_CSV = (
    "################################################################\n"
    "# abuse.ch ThreatFox IOCs\n"
    "################################################################\n"
    '# "first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type", "fk_malware", "malware_alias", "malware_printable", "last_seen_utc", "confidence_level", "reference", "tags", "anonymous", "reporter"\n'
    '"2026-11-12 09:00:00", "11", "c2.deep-c2.test", "domain", "botnet_cc", "win.test", "None", "TestBot", "", "100", "None", "None", "0", "reporter"\n'
    '"2026-11-12 09:00:00", "12", "198.51.100.5:443", "ip:port", "botnet_cc", "win.test", "None", "TestBot", "", "100", "None", "None", "0", "reporter"\n'
    '"2026-11-12 09:00:00", "13", "http://threatfox-c2.test/gate.php", "url", "payload_delivery", "win.test", "None", "TestBot", "", "75", "None", "None", "0", "reporter"\n'
    '"2026-11-12 09:00:00", "14", "d41d8cd98f00b204e9800998ecf8427e", "md5_hash", "payload", "win.test", "None", "TestBot", "", "75", "None", "None", "0", "reporter"\n'
)

SELFTEST_PHISHING = (
    "# Phishing Army test list\n"
    "phish-army-login.test\n"
    "phishing-only.test\n"
    "PHISH-UPPER.TEST.\n"
)


def _zip_bytes(name: str, text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, text)
    return buf.getvalue()


def selftest(out_dir: Optional[str]) -> int:
    failures: List[str] = []

    def check(cond: bool, msg: str) -> None:
        print(("  OK    " if cond else "  FAIL  ") + msg)
        if not cond:
            failures.append(msg)

    print("== нормализация ==")
    check(normalize_domain("EXAMPLE.com.") == "example.com", "lowercase и удаление конечной точки")
    check(normalize_domain("*.evil.test") == "evil.test", "удаление wildcard-префикса")
    check(normalize_domain("203.0.113.7") is None, "IPv4 отклоняется")
    check(normalize_domain("evil.test:8080") is None, "домен с портом отклоняется")
    check(normalize_domain("bad_domain!.test") is None, "недопустимые символы отклоняются")
    check(normalize_domain("localhost") is None, "одиночная метка отклоняется")
    check(normalize_domain("-bad.test") is None, "метка, начинающаяся с '-', отклоняется")
    check(normalize_domain("тест.рф") == "xn--e1aybc.xn--p1ai", "IDN приводится к punycode")
    check(host_from_url("https://CDN.Evil.test:8443/x?y=1") == "cdn.evil.test", "хост из URL с портом и query")
    check(host_from_url("http://203.0.113.9:8080/bin") is None, "IP-хост из URL отклоняется")
    check(host_from_url("http://[2001:db8::1]/x") is None, "IPv6-хост из URL отклоняется")

    tmp_root = Path(tempfile.mkdtemp(prefix="ti-selftest-"))
    lists = tmp_root / "lists"
    state = tmp_root / "state"
    lists.mkdir()
    state.mkdir()
    cfg_path = tmp_root / "config.ini"
    cfg_path.write_text(SELFTEST_CONFIG.format(lists=lists, state=state), encoding="utf-8")
    cfg = load_config(str(cfg_path))

    _FIXTURES.clear()
    _FIXTURES["urlhaus-hostfile"] = SELFTEST_URLHAUS_HOSTFILE.encode()
    _FIXTURES["urlhaus-csv"] = SELFTEST_URLHAUS_CSV.encode()
    _FIXTURES["threatfox-hostfile"] = SELFTEST_THREATFOX_HOSTFILE.encode()
    _FIXTURES["threatfox-csv"] = _zip_bytes("full.csv", SELFTEST_THREATFOX_CSV)
    _FIXTURES["phishingarmy-domains"] = SELFTEST_PHISHING.encode()

    print("== полный цикл (без сети) ==")
    args = argparse.Namespace(dry_run=False, force=False, source=None)
    code = run(cfg, args)
    check(code == EXIT_OK, "run() вернул 0 (получен %d)" % code)

    def keys(name: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for line in (lists / name).read_text(encoding="utf-8").splitlines():
            k, v = line.split(":", 1)
            out[k] = v
        return out

    merged = keys("ti-domains")
    check(merged.get("urlhaus-malware.test") == "URLhaus", "URLhaus-домен получил метку источника")
    check(merged.get("threatfox-c2.test") == "ThreatFox", "ThreatFox-домен (hostfile+URL) получил метку")
    check(merged.get("c2.deep-c2.test") == "ThreatFox", "домен из ioc_type=domain")
    check(merged.get("phish-army-login.test") == "PhishingArmy", "Phishing Army домен")
    check(merged.get("multi-source.test") == "URLhaus,ThreatFox", "домен в двух источниках сохранил оба источника")
    check(merged.get("upper-case.test") == "URLhaus", "верхний регистр и точка нормализованы")
    check(merged.get("cdn.urlhaus-malware.test") == "URLhaus", "хост из URL (с портом) добавлен")
    check(merged.get("phish-upper.test") == "PhishingArmy", "нормализация в plain-списке")
    check("203.0.113.7" not in merged and "203.0.113.9" not in merged, "IP-адреса не попали в список")
    check("198.51.100.5:443" not in merged, "ip:port из ThreatFox проигнорирован")
    check(len(merged) == len(set(merged)), "дубликатов нет")
    check(set(keys("ti-multi")) == {"multi-source.test"}, "ti-multi содержит только домены из >=2 источников")
    check(keys("ti-urlhaus").get("multi-source.test") == "URLhaus", "персональный список источника: URLhaus")
    check(keys("ti-threatfox").get("multi-source.test") == "ThreatFox", "персональный список источника: ThreatFox")
    check((state / "status.json").exists(), "status.json записан")
    mode = (lists / "ti-domains").stat().st_mode & 0o777
    check(mode == 0o644, "права файла применены (0%o)" % mode)
    check(not list(lists.glob(".*")), "временные файлы удалены")

    if out_dir:
        dest = Path(out_dir)
        dest.mkdir(parents=True, exist_ok=True)
        for name in ["ti-domains", "ti-urlhaus", "ti-threatfox", "ti-phishingarmy", "ti-multi"]:
            shutil.copy2(str(lists / name), str(dest / name))
        print("образцы CDB-списков (до последующих сценариев) сохранены в %s" % dest)

    print("== повторный запуск: изменений нет ==")
    before = (lists / "ti-domains").stat().st_mtime_ns
    code = run(cfg, args)
    check(code == EXIT_OK, "повторный run() вернул 0 (получен %d)" % code)
    check((lists / "ti-domains").stat().st_mtime_ns == before, "файл не перезаписывался")

    print("== сбой источника: рабочий список не теряет IOC ==")
    _FIXTURES["urlhaus-csv"] = b"<html><body>Unauthorized</body></html>"
    _FIXTURES["urlhaus-hostfile"] = b""
    code = run(cfg, args)
    check(code == EXIT_DEGRADED, "деградированный режим даёт код 6 (получен %d)" % code)
    check("urlhaus-malware.test" in keys("ti-domains"), "IOC URLhaus сохранены из истории")

    print("== сбой источника без истории: рабочий список не перезаписывается ==")
    for p in (state / "seen").glob("phishingarmy.json"):
        p.unlink()
    _FIXTURES["phishingarmy-domains"] = b"<!DOCTYPE html><html></html>"
    snapshot = (lists / "ti-domains").read_text(encoding="utf-8")
    code = run(cfg, args)
    check(code == EXIT_SOURCE, "без резервных данных код 2 (получен %d)" % code)
    check((lists / "ti-domains").read_text(encoding="utf-8") == snapshot, "рабочий список не изменился")

    print("== защита от аномального сокращения ==")
    _FIXTURES["phishingarmy-domains"] = SELFTEST_PHISHING.encode()
    big = {("d%05d.test" % i): ["PhishingArmy"] for i in range(1000)}
    (lists / "ti-phishingarmy").write_text(build_cdb(big), encoding="utf-8")
    _FIXTURES["urlhaus-csv"] = SELFTEST_URLHAUS_CSV.encode()
    _FIXTURES["urlhaus-hostfile"] = SELFTEST_URLHAUS_HOSTFILE.encode()
    code = run(cfg, args)
    check(code == EXIT_SOURCE, "сокращение 1000 -> 3 заблокировано (код %d)" % code)
    check(len(read_keys(lists / "ti-phishingarmy")) == 1000, "список ti-phishingarmy не затронут")

    print("== откат при ошибке валидации Wazuh ==")
    (lists / "ti-phishingarmy").write_text(build_cdb({"old-entry.test": ["PhishingArmy"]}), encoding="utf-8")
    old_text = (lists / "ti-phishingarmy").read_text(encoding="utf-8")
    cfg.validate_command = "/bin/false"
    cfg.reload_command = ""
    _FIXTURES["phishingarmy-domains"] = (SELFTEST_PHISHING + "new-entry.test\n").encode()
    code = run(cfg, args)
    check(code == EXIT_VALIDATE, "ошибка валидации даёт код 3 (получен %d)" % code)
    check((lists / "ti-phishingarmy").read_text(encoding="utf-8") == old_text, "предыдущий список восстановлен")

    print("== успешная валидация и reload ==")
    cfg.validate_command = "/bin/true"
    cfg.reload_command = "/bin/true"
    code = run(cfg, args)
    check(code in (EXIT_OK, EXIT_DEGRADED), "валидация и reload пройдены (код %d)" % code)
    check(not (state / "needs_reload").exists(), "маркер reload снят")
    check("new-entry.test" in keys("ti-domains"), "новые IOC опубликованы")

    print("== защита Auth-Key abuse.ch ==")
    secret = "Zq9-selftest_KEY+/=7"
    masked = redact("ошибка при запросе https://x.test/%s/hostfile.txt" % urllib.parse.quote(secret, safe=""), secret)
    check(urllib.parse.quote(secret, safe="") not in masked and "***" in masked, "ключ в URL-кодировке маскируется")
    check(secret not in redact("ошибка: " + secret, secret), "ключ в исходном виде маскируется")
    check(redact("без ключа", None) == "без ключа", "без ключа текст не меняется")
    key_file = state / "selftest-abusech.key"
    key_file.write_text("  " + secret + "  \n", encoding="utf-8")
    key_file.chmod(0o600)
    cfg.auth_key_file = str(key_file)
    check(load_key(cfg) == secret, "ключ читается из файла без пробелов и перевода строки")
    check((key_file.stat().st_mode & 0o077) == 0, "файл ключа в самотесте имеет права 0600")
    cfg.auth_key_file = str(state / "no-such.key")
    check(load_key(cfg) is None, "отсутствующий файл ключа даёт None, а не исключение")

    print("== формат CDB ==")
    for name in ["ti-domains", "ti-urlhaus", "ti-threatfox", "ti-phishingarmy", "ti-multi"]:
        try:
            n = validate_cdb_text((lists / name).read_text(encoding="utf-8"))
            check(n > 0, "%s: корректный CDB, ключей=%d" % (name, n))
        except ValueError as exc:
            check(False, "%s: %s" % (name, exc))

    shutil.rmtree(str(tmp_root), ignore_errors=True)

    print()
    if failures:
        print("САМОТЕСТ НЕ ПРОЙДЕН: %d ошибок" % len(failures))
        return 1
    print("САМОТЕСТ ПРОЙДЕН")
    return 0


# --------------------------------------------------------------------------- #
# Точка входа
# --------------------------------------------------------------------------- #
def setup_logging(cfg: Optional[Config], verbose: bool) -> None:
    LOG.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(fmt)
    LOG.addHandler(stream)
    if cfg and cfg.log_file:
        try:
            Path(cfg.log_file).parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                cfg.log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            fh.setFormatter(fmt)
            LOG.addHandler(fh)
        except OSError as exc:
            LOG.warning("журнал %s недоступен: %s (вывод только в stderr)", cfg.log_file, exc)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Обновление Threat Intelligence CDB-списков Wazuh")
    ap.add_argument("-c", "--config", default="/var/ossec/wodles/wazuh-ti/config.ini", help="путь к config.ini")
    ap.add_argument("--source", action="append", help="обновить только указанный источник (можно несколько раз)")
    ap.add_argument("--dry-run", action="store_true", help="ничего не записывать, только показать результат")
    ap.add_argument("--force", action="store_true", help="отключить защиту от аномального сокращения списков")
    ap.add_argument("-v", "--verbose", action="store_true", help="подробный журнал")
    ap.add_argument("--selftest", action="store_true", help="автономная проверка без сети и без Wazuh")
    ap.add_argument("--selftest-out", help="сохранить образцы CDB, созданные самотестом, в каталог")
    ap.add_argument("--version", action="version", version="wazuh-ti-updater " + VERSION)
    args = ap.parse_args(argv)

    if args.selftest:
        setup_logging(None, args.verbose)
        LOG.setLevel(logging.WARNING)
        return selftest(args.selftest_out)

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        setup_logging(None, args.verbose)
        LOG.error("ошибка конфигурации: %s", exc)
        return EXIT_ERROR
    setup_logging(cfg, args.verbose)
    LOG.info("запуск wazuh-ti-updater %s", VERSION)
    try:
        return run(cfg, args)
    except Exception as exc:
        LOG.exception("необработанная ошибка: %s", exc)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
