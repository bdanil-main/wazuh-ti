#!/usr/bin/env bash
# Проверка декодера и правил через wazuh-logtest на работающем Wazuh Manager.
#
# По умолчанию события строятся из РЕАЛЬНЫХ доменов ваших текущих списков (make-live-events.py),
# по одному событию на каждое правило 100201-100204, 100210, 100211 и два контрольных запроса.
# Реальные DNS-запросы и алерты при этом не создаются: wazuh-logtest только разбирает строки.
#
# Запуск на хосте (Fish или Bash) из корня проекта:
#   ./tests/logtest.sh            события по реальным доменам из списков Manager
#   ./tests/logtest.sh --short    то же, но только ключевые строки вывода
#   ./tests/logtest.sh --fixtures события tests/fixtures/dns-events.log (домены .test). Работают
#                                 только на ТЕСТОВОМ стенде с образцами из tests/fixtures/lists.
# Переменная CONTAINER задаёт имя контейнера (по умолчанию single-node_wazuh.manager_1).
# Если podman на хосте недоступен, а скрипт запущен внутри контейнера, команды выполняются напрямую.
#
# В выводе смотрите: Phase 2 (srcip, query, query_type, dns_server, query_d2, query_d3) и Phase 3
# (rule id, level). Ожидаемые правила напечатаны таблицей перед прогоном.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
container="${CONTAINER:-single-node_wazuh.manager_1}"
py="/var/ossec/framework/python/bin/python3"
logtest="/var/ossec/bin/wazuh-logtest"

mode="live"
short="no"
for arg in "$@"; do
    case "$arg" in
        --fixtures) mode="fixtures" ;;
        --short) short="yes" ;;
        -h|--help) sed -n '2,17p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "Неизвестный параметр: $arg" >&2; exit 1 ;;
    esac
done

if command -v podman >/dev/null 2>&1 && podman container exists "$container" 2>/dev/null; then
    runner=(podman exec -i "$container")
elif [[ -x "$logtest" ]]; then
    runner=()
else
    echo "Не найден контейнер $container и локальный $logtest. Задайте CONTAINER=имя_контейнера" >&2
    exit 1
fi

events="$(mktemp)"
trap 'rm -f "$events"' EXIT

if [[ "$mode" == "fixtures" ]]; then
    cp "$here/fixtures/dns-events.log" "$events"
    echo "Режим fixtures: нужны образцы списков из tests/fixtures/lists (только тестовый стенд)." >&2
else
    "${runner[@]+"${runner[@]}"}" "$py" - < "$here/make-live-events.py" > "$events"
fi

n=0
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    n=$((n + 1))
    echo
    echo "=== событие $n: ${line#*named\[*\]: } ==="
    if [[ "$short" == "yes" ]]; then
        printf '%s\n' "$line" | "${runner[@]+"${runner[@]}"}" "$logtest" -v 2>&1 \
            | grep -E "Phase|name:|id:|level:|query|srcip|dns_server|Alert" || true
    else
        printf '%s\n' "$line" | "${runner[@]+"${runner[@]}"}" "$logtest" -v 2>&1
    fi
done < "$events"

echo
echo "Прогнано событий: $n"
