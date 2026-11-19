#!/usr/bin/env bash
# Интеграционный тест: дописывает события по реальным доменам из ваших списков в лог, который читает
# логколлектор Wazuh через временный <localfile>, затем ждёт и сверяет алерты в alerts.json.
#
# Перед запуском добавьте временный localfile и перезапустите Manager (см. README, раздел
# «Интеграционная проверка»). После теста обязательно удалите его (раздел «Очистка»).
#
# Запуск на хосте из корня проекта:
#   ./tests/send-events.sh                       файл /tmp/wazuh-ti-dashboard-test.log в контейнере
#   ./tests/send-events.sh /другой/путь.log       другой файл (он должен быть указан в <localfile>)
# Переменные: CONTAINER (имя контейнера), WAIT_SECONDS (пауза перед сверкой, по умолчанию 20).
# Код возврата: 0 все ожидаемые алерты найдены, 1 есть расхождения, остальное - ошибка запуска.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
container="${CONTAINER:-single-node_wazuh.manager_1}"
target="${1:-/tmp/wazuh-ti-dashboard-test.log}"
expect="/tmp/wazuh-ti-expected.tsv"
wait_seconds="${WAIT_SECONDS:-20}"
py="/var/ossec/framework/python/bin/python3"

if command -v podman >/dev/null 2>&1 && podman container exists "$container" 2>/dev/null; then
    runner=(podman exec -i "$container")
elif [[ -x "$py" ]]; then
    runner=()
else
    echo "Не найден контейнер $container. Задайте CONTAINER=имя_контейнера" >&2
    exit 2
fi

run() { "${runner[@]+"${runner[@]}"}" "$@"; }

run sh -c 'touch "$1" && chmod 0644 "$1"' _ "$target"
run "$py" - --append "$target" --expect "$expect" < "$here/make-live-events.py"

echo
echo "Жду $wait_seconds с, пока логколлектор прочитает файл и анализатор создаст алерты..."
sleep "$wait_seconds"

run "$py" - --minutes 10 --expect "$expect" < "$here/show_alerts.py"
