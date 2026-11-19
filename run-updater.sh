#!/bin/sh
# /var/ossec/wodles/wazuh-ti/run-updater.sh
# Запуск wazuh-ti-updater внутри контейнера Wazuh Manager. Все аргументы передаются updater как есть:
#   /var/ossec/wodles/wazuh-ti/run-updater.sh --dry-run
#
# Интерпретатор: системный python3, если он есть в образе, иначе встроенный Python из Wazuh
# (/var/ossec/framework/python/bin/python3). Код возврата updater (0-6) возвращается без изменений.
set -eu

dir="${WAZUH_TI_DIR:-/var/ossec/wodles/wazuh-ti}"
embedded="/var/ossec/framework/python/bin/python3"

py=""
if command -v python3 >/dev/null 2>&1; then
    py="$(command -v python3)"
elif [ -x "$embedded" ]; then
    py="$embedded"
fi
if [ -z "$py" ]; then
    echo "Python 3 не найден ни в PATH, ни в $embedded" >&2
    exit 1
fi

exec "$py" "$dir/wazuh-ti-updater.py" --config "$dir/config.ini" "$@"
