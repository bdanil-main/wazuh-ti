# Wazuh Threat Intelligence DNS

Ежедневная загрузка вредоносных доменов из URLhaus, ThreatFox и Phishing Army, сборка CDB-списков и обнаружение DNS-запросов BIND к этим доменам силами самого Wazuh. При обработке событий внешние сервисы не вызываются: раз в сутки обновляются только списки, а проверка каждого DNS-запроса выполняется локально.

Документ описывает фактическое состояние проекта после проверки на Wazuh 4.14.10 в Podman. Всё, что проверено на живом Manager, и всё, что проверено не было, разделено явно (разделы «Результаты интеграционного тестирования» и «Ограничения и непроверенные сценарии»).

## Совместимость и эталонная среда

| Параметр | Значение |
| --- | --- |
| Wazuh Manager, Indexer, Dashboard | 4.14.10 |
| Развёртывание | single-node, Podman Compose (wazuh-docker), rootless Podman |
| ОС хоста, оболочка | Arch Linux, Fish |
| Контейнер Manager | `single-node_wazuh.manager_1` |
| Dashboard | `https://localhost:8443` |
| Python | 3.8+ со стандартной библиотекой, сторонние пакеты не нужны |

Для других версий Wazuh сверяйте копию стандартного декодера (раздел «Конфликт со стандартным декодером»). Имя контейнера смотрите командой `podman ps`; если оно другое, замените его в переменной `C` ниже и в файле `wazuh-ti-updater.service`.

## Состав проекта

```text
wazuh-ti/
├── README.md                          этот документ
├── CHANGELOG.md                       что и почему изменено в этой версии
├── wazuh-ti-updater.py                загрузка, нормализация, сборка и публикация CDB
├── config.ini                         настройки источников и постоянные пути
├── allowlist.txt                      домены-исключения
├── run-updater.sh                     запуск updater внутри контейнера (выбор интерпретатора)
├── wazuh-ti-updater.service           пользовательский юнит systemd на хосте (podman exec)
├── wazuh-ti-updater.timer             ежедневный запуск юнита
├── wazuh-ti-updater.cron              альтернатива таймеру: строка для crontab
├── bind_named_dns_decoders.xml        декодер BIND (копия стандартного + named-dns-query-3plus)
├── local_ti_dns_rules.xml             правила 100200-100211
├── ossec.conf.snippet.xml             эталон блока ruleset и варианты приёма DNS-логов
├── tools/
│   └── patch_ossec_conf.py            безопасное добавление строк в существующий ossec.conf
├── tests/
│   ├── check_project.py               автономная проверка проекта (без Wazuh и без сети)
│   ├── logtest.sh                     прогон через wazuh-logtest по реальным доменам из списков
│   ├── send-events.sh                 интеграционный тест через временный localfile
│   ├── make-live-events.py            генератор событий BIND по текущим спискам
│   ├── show_alerts.py                 алерты TI из alerts.json и автосверка с ожиданиями
│   └── fixtures/                      данные автономных тестов (домены в зоне .test)
└── contrib/baremetal/                 установка без контейнера (systemd, cron, пути)
```

Итоговые боевые CDB-файлы создаёт сам updater в `/var/ossec/etc/lists/`: `ti-domains`, `ti-urlhaus`, `ti-threatfox`, `ti-phishingarmy`, `ti-multi`. Каталог `tests/fixtures/lists/` содержит образцы формата с синтетическими доменами `.test` только для автономных тестов. Реальные списки Manager они не заменяют, и копировать их на Manager не нужно.

### Где что лежит в контейнере

| Что | Путь в контейнере | Постоянное хранилище |
| --- | --- | --- |
| Скрипт, `config.ini`, `allowlist.txt`, `run-updater.sh` | `/var/ossec/wodles/wazuh-ti/` | да (том wodles) |
| Auth-Key abuse.ch | `/var/ossec/wodles/wazuh-ti/abusech.key` (0600) | да |
| История IOC, бэкапы списков, `status.json` | `/var/ossec/wodles/wazuh-ti/state/` | да |
| Журнал updater | `/var/ossec/logs/wazuh-ti-updater.log` | да (том logs) |
| CDB-списки, декодер, правила, `ossec.conf` | `/var/ossec/etc/lists`, `etc/decoders`, `etc/rules`, `etc/ossec.conf` | да (том etc) |
| `/usr/local/sbin`, `/etc/wazuh-ti`, `/var/lib/wazuh-ti`, `/tmp` | слой контейнера | нет, пропадают при пересоздании контейнера |

Постоянство томов проверяется командой из шага 0. Если в вашем развёртывании `/var/ossec/wodles` не является томом, выберите другой постоянный каталог и замените пути в `config.ini`, `run-updater.sh` и командах ниже.

## Важно знать до установки

1. **abuse.ch требует бесплатный Auth-Key.** Скачивание фидов URLhaus и ThreatFox без ключа не работает. Ключ создаётся бесплатно на https://auth.abuse.ch/. Условия abuse.ch разрешают бесплатный доступ для некоммерческих целей в рамках fair use. Для коммерческого использования сверьтесь с https://abuse.ch/terms-of-use/. Раз в сутки по два файла с каждого сервиса укладывается в fair use.
2. **Имена файлов в URL.** В документации abuse.ch подтверждены `recent.csv` (URLhaus) и `full.csv.zip` (ThreatFox). Имя `hostfile.txt` построено по тому же шаблону экспортов, и точную ссылку нужно сверить в кабинете abuse.ch. Hostfile-фиды помечены `required = false`, поэтому их недоступность не блокирует обновление: домены приходят и из CSV-дампов.
3. **Phishing Army**: `https://phishing.army/download/phishing-army-domains.txt`. Условия: https://phishing.army/license/.
4. **ThreatFox** отдаёт только IOC моложе 6 месяцев, URLhaus hostfile содержит только активные или добавленные за 48 часов хосты. Поэтому updater ведёт историю last-seen (`retention_days`) и не теряет IOC на следующий день.
5. **Домены в списках меняются со временем.** Тесты в этом проекте берут домены из ТЕКУЩИХ списков (`tests/make-live-events.py`), а не из фиксированного перечня.

## Как это работает

```text
URLhaus ───────┐
ThreatFox ─────┼──> wazuh-ti-updater.py ──> нормализация, дедупликация, история last-seen
Phishing Army ─┘                                   │
                                                   v
                       ti-domains  ti-urlhaus  ti-threatfox  ti-phishingarmy  ti-multi
                                                   │  (временный файл -> проверка -> бэкап -> атомарная замена
                                                   │   -> wazuh-analysisd -t -> wazuh-control reload)
                                                   v
BIND named ──> Decoder (srcip, query, query_type, dns_server, query_d2, query_d3) ──> Rules ──> Alert
```

### Формат списков

`ti-domains` хранит все домены и все источники каждого домена через запятую:

```text
c2.example-c2.net:ThreatFox
multi-source.example:URLhaus,ThreatFox
phishing-domain.example:PhishingArmy
```

CDB-проверка Wazuh не умеет возвращать значение ключа в алерт, поэтому для правил нужны отдельные списки: `ti-urlhaus`, `ti-threatfox`, `ti-phishingarmy` содержат домены одного источника, `ti-multi` содержит домены, найденные минимум в двух источниках. Какие именно источники указали домен, видно в `ti-domains`.

### Правила и статус проверки

CDB сравнивает ключ целиком, поэтому декодер дополнительно вычисляет `query_d2` (две последние метки имени) и `query_d3` (три последние). Точные совпадения проверяются раньше совпадений по родительскому домену.

| Правило | Условие | Уровень | Смысл | Статус на живом Wazuh 4.14.10 |
| --- | --- | ---: | --- | --- |
| 100200 | `query` декодирован (группа `named`) | 0 | Базовое правило, алерта нет | подтверждено (`wazuh-logtest`) |
| 100201 | `query` есть в `ti-multi` | 14 | Домен минимум в двух источниках | подтверждено (`wazuh-logtest`, интеграционный тест, Dashboard) |
| 100202 | `query` есть в `ti-threatfox` | 13 | C2 или доставка нагрузки | подтверждено (то же) |
| 100203 | `query` есть в `ti-urlhaus` | 12 | Распространение вредоносного ПО | подтверждено (то же) |
| 100204 | `query` есть в `ti-phishingarmy` | 10 | Фишинг | подтверждено (то же) |
| 100210 | `query_d2` есть в `ti-domains` | 8 | Поддомен домена из двух меток, требует проверки | не подтверждено интеграционным тестом на живом Wazuh (логика совпадает с 100211, проверена только эмуляцией) |
| 100211 | `query_d3` есть в `ti-domains` | 8 | Поддомен домена из трёх меток, требует проверки | подтверждено (`wazuh-logtest`, интеграционный тест, Dashboard) |

Совпадение по родительскому домену намеренно имеет низкий уровень и помечено «требует проверки»: поддомен домена из TI не обязательно вредоносен (общий хостинг, динамический DNS). Проверяются последние 2 и 3 метки имени. Для более глубоких вложений добавьте поле `query_d4` по тому же образцу.

MITRE ATT&CK: T1071.004 (DNS как протокол прикладного уровня) для 100201, 100202, 100210, 100211; T1105 для 100203; T1566 для 100204. Эти идентификаторы Wazuh принял при загрузке правил, а `rule.mitre` отображается в Dashboard.

### Защита рабочих списков

* Загрузка только по HTTPS, с повторами, лимитом размера, проверкой на HTML и JSON-ошибки вместо данных, проверкой доли отклонённых записей.
* Сначала временные файлы рядом с рабочими, проверка формата, количества ключей и контрольной суммы, и только затем атомарная замена (`os.replace`). Повреждённый CDB-файл в рабочий каталог не попадает.
* Перед заменой делается бэкап изменяемых списков в `/var/ossec/wodles/wazuh-ti/state/backups/<время>/` (хранится 7 последних запусков).
* После замены запускается `wazuh-analysisd -t`. При ошибке предыдущие списки восстанавливаются автоматически.
* Накопленные IOC не теряются: если источник недоступен, его IOC берутся из истории за `max(retention_days, fallback_days)` суток. Если резервных данных нет, обновление прерывается и рабочие списки не трогаются (код 2).
* Если список сократился более чем на 60% (при размере от 500 записей), обновление прерывается: это признак обрезанного ответа. После ручной проверки используйте `--force`.
* Если списки изменились, а reload не удался, при следующем запуске reload будет повторён (маркер `needs_reload`).
* Если изменений нет, файлы не перезаписываются и Wazuh не перезагружается.
* Auth-Key хранится в файле с правами 0600, в URL подставляется только в памяти и маскируется (`***`) в сообщениях об ошибках; ни в журнал, ни в терминал не выводится.

## Особенности установки в Podman

1. **Внутри контейнера нет systemd.** Расписание создаётся на хосте: пользовательский таймер systemd (или cron) запускает `podman exec ... run-updater.sh`. Команда `systemctl` внутри контейнера не используется; управление Wazuh выполняется командами `/var/ossec/bin/wazuh-control` и `podman restart`.
2. **Данные только в постоянных томах** (таблица выше). Пересоздание контейнера (`podman-compose down` и `up -d`) их не удаляет.
3. **`ossec.conf` может приходить из смонтированного файла.** В wazuh-docker файл `config/wazuh_cluster/wazuh_manager.conf` монтируется в контейнер как `/wazuh-config-mount/etc/ossec.conf`. Поэтому строки блока `<ruleset>` добавляются и в активный `/var/ossec/etc/ossec.conf`, и в этот файл на хосте (шаг 7). Иначе после пересоздания контейнера исключение декодера и регистрация списков могут пропасть.
4. **Rootless Podman:** для таймера без открытой сессии нужен `loginctl enable-linger`, для cron нужна переменная `XDG_RUNTIME_DIR` (уже задана в `wazuh-ti-updater.cron`), порты ниже 1024 на хосте по умолчанию недоступны (важно для варианта Б).
5. **Никогда не выполняйте** `podman-compose down -v`, `podman volume rm` и `podman volume prune`: эти команды удаляют тома с данными Wazuh, включая списки, историю IOC и ключ. Ничего из этого README не требует удаления томов или переустановки Podman.

## Установка

Все команды выполняются на хосте в Fish из каталога проекта (после `unzip wazuh-ti-bundle.zip` и `cd wazuh-ti`). Python на хосте нужен только для шага 7 (правка смонтированного файла).

### Шаг 0. Переменные и проверка контейнера

```fish
set -g C single-node_wazuh.manager_1
set -g PY /var/ossec/framework/python/bin/python3
set -g TI /var/ossec/wodles/wazuh-ti
podman ps --filter name=$C --format '{{.Names}} {{.Status}}'
podman exec $C /var/ossec/bin/wazuh-control info
podman inspect $C --format '{{range .Mounts}}{{.Type}} {{.Destination}}{{"\n"}}{{end}}'
```

В выводе последней команды должны быть тома для `/var/ossec/etc`, `/var/ossec/logs` и `/var/ossec/wodles`. Если какого-то нет, остановитесь и выберите другой постоянный каталог (см. выше).

Проверьте, что в `etc/decoders` нет других файлов, определяющих декодер `named` (например, диагностических), и что ID правил 1002xx свободны:

```fish
podman exec $C sh -c "grep -ln '<decoder name=\"named\"' /var/ossec/etc/decoders/*.xml"
podman exec $C sh -c "grep -rn 'rule id=\"1002' /var/ossec/etc/rules/"
```

На чистом Manager обе команды ничего не выводят. При повторной установке в первой допустим только `bind_named_dns_decoders.xml`, во второй только `local_ti_dns_rules.xml`.

### Шаг 1. Файлы updater в постоянное хранилище

```fish
podman exec $C mkdir -p $TI/state
podman cp wazuh-ti-updater.py $C:$TI/wazuh-ti-updater.py
podman cp run-updater.sh $C:$TI/run-updater.sh
podman cp config.ini $C:$TI/config.ini
podman cp allowlist.txt $C:$TI/allowlist.txt
podman exec $C chown -R root:wazuh $TI
podman exec $C chmod 0750 $TI $TI/state $TI/wazuh-ti-updater.py $TI/run-updater.sh
podman exec $C chmod 0640 $TI/config.ini $TI/allowlist.txt
podman exec $C ls -l $TI
```

Пути в `config.ini` уже указывают на постоянные тома, менять их не нужно.

### Шаг 2. Auth-Key abuse.ch

Создайте ключ на https://auth.abuse.ch/. Ключ вводится в скрытом приглашении, не попадает в историю команд и не печатается:

```fish
read -s -P "Auth-Key abuse.ch: " abusech_key
printf '%s\n' $abusech_key | podman exec -i $C sh -c 'umask 077; cat > /var/ossec/wodles/wazuh-ti/abusech.key'
set -e abusech_key
podman exec $C chown root:root $TI/abusech.key
podman exec $C chmod 0600 $TI/abusech.key
podman exec $C ls -l $TI/abusech.key
podman exec $C sh -c 'wc -c < /var/ossec/wodles/wazuh-ti/abusech.key'
```

Последние две команды показывают права (`-rw-------`) и длину файла, но не сам ключ. Не вставляйте ключ в команды, в файлы проекта и в чаты. Updater предупредит в журнале, если права на файл шире 0600.

### Шаг 3. Самотест (без сети и без Wazuh)

```fish
podman exec $C $TI/run-updater.sh --selftest
```

Ожидаемый итог: `САМОТЕСТ ПРОЙДЕН`, 53 проверки (47 прежних и 6 проверок защиты ключа).

### Шаг 4. Пробный запуск без записи

```fish
podman exec $C $TI/run-updater.sh --dry-run
```

В журнале должны быть строки `[URLhaus/urlhaus-csv] OK`, `[ThreatFox/threatfox-csv] OK`, `[PhishingArmy/phishingarmy-domains] OK` и количество записей по каждому списку. При `HTTP 401/403/404` проверьте ключ и ссылки (раздел «Важно знать»).

### Шаг 5. Первый боевой запуск (создаёт списки)

```fish
podman exec $C $TI/run-updater.sh
podman exec $C ls -l /var/ossec/etc/lists/ti-domains /var/ossec/etc/lists/ti-urlhaus /var/ossec/etc/lists/ti-threatfox /var/ossec/etc/lists/ti-phishingarmy /var/ossec/etc/lists/ti-multi
```

На этом шаге `ossec.conf` ещё не ссылается на списки, поэтому проверка `wazuh-analysisd -t` проходит. Списки должны существовать до того, как правила и `ossec.conf` начнут на них ссылаться, поэтому шаг 5 стоит перед шагами 6 и 7.

### Шаг 6. Декодер и правила

```fish
podman cp bind_named_dns_decoders.xml $C:/var/ossec/etc/decoders/bind_named_dns_decoders.xml
podman cp local_ti_dns_rules.xml $C:/var/ossec/etc/rules/local_ti_dns_rules.xml
podman exec $C chown root:wazuh /var/ossec/etc/decoders/bind_named_dns_decoders.xml /var/ossec/etc/rules/local_ti_dns_rules.xml
podman exec $C chmod 0660 /var/ossec/etc/decoders/bind_named_dns_decoders.xml /var/ossec/etc/rules/local_ti_dns_rules.xml
```

### Конфликт со стандартным декодером

Wazuh 4.14.10 содержит стандартный файл `ruleset/decoders/0155-named_decoders.xml` с декодером `named-query`, который извлекает `srcip`, `query`, `query_type`, `dns_server`. Дочерние декодеры перебираются по порядку загрузки, побеждает первый подошедший. Поэтому отдельный пользовательский декодер никогда не выполнялся, а поля `query_d2` и `query_d3` не заполнялись: правила поддоменов молчали.

Решение, которое уже заложено в проект:

* `bind_named_dns_decoders.xml` содержит полную копию стандартного файла (декодеры `named`, `named-query`, `named_client`, `named-master`, `named_from` без изменений) и дополнительный декодер `named-dns-query-3plus` ПЕРЕД `named-query`. Он обрабатывает имена из трёх и более меток и добавляет `query_d2` и `query_d3`. Имена из одной-двух меток разбирает стандартный `named-query`.
* Оригинал исключается строкой `<decoder_exclude>0155-named_decoders.xml</decoder_exclude>` в `<ruleset>`. Без неё декодер `named` определён дважды. Эта строка обязательна (шаг 7).
* `prematch` нового декодера повторяет всё условие его regex, включая требование трёх меток. Если prematch подошёл, а regex нет, Wazuh не извлекает поля и не пробует следующий декодер; слабый prematch сделал бы невидимыми запросы к именам вроде `example.org`.
* Правило 100200 привязано через `<if_group>named</if_group>` ко всем стандартным правилам группы `named`, а не только к 12100: стандартное правило вроде 12138 (`Domain A record found.`) останавливает перебор раньше, чем он дойдёт до правила, привязанного только к 12100. Группу `named` в `<group>` файла правил добавлять нельзя.

После обновления Wazuh сверяйте копию со стандартным файлом: `podman exec $C grep -n "<decoder name" /var/ossec/ruleset/decoders/0155-named_decoders.xml`. Если в новой версии появились новые декодеры или поля, перенесите их в `bind_named_dns_decoders.xml`.

### Шаг 7. `ossec.conf`: добавить строки, не заменяя файл

Полная эталонная секция `<ruleset>` рабочего Manager (проектные строки в конце, под комментарием `Threat Intelligence DNS`):

```xml
<ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <list>etc/lists/malicious-ioc/malicious-ip</list>
    <list>etc/lists/malicious-ioc/malicious-domains</list>
    <list>etc/lists/malicious-ioc/malware-hashes</list>

    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>

    <!-- Threat Intelligence DNS -->
    <decoder_exclude>0155-named_decoders.xml</decoder_exclude>
    <list>etc/lists/ti-domains</list>
    <list>etc/lists/ti-urlhaus</list>
    <list>etc/lists/ti-threatfox</list>
    <list>etc/lists/ti-phishingarmy</list>
    <list>etc/lists/ti-multi</list>
</ruleset>
```

Стандартные строки и каталоги `etc/decoders`, `etc/rules` в рабочей конфигурации уже есть и повторно не добавляются. Ваш `ossec.conf` целиком заменять НЕЛЬЗЯ. Скрипт `tools/patch_ossec_conf.py` добавляет в существующий `<ruleset>` только недостающие шесть строк, игнорирует закомментированные, ничего вокруг не трогает, проверяет, что результат остаётся корректным XML, делает копию `ossec.conf.bak-ti-ВРЕМЯ` рядом с файлом и пишет в тот же файл (inode сохраняется). Повторный запуск ничего не меняет.

Активный файл в контейнере (скрипт передаётся через stdin, копировать его в контейнер не нужно):

```fish
podman exec -i $C $PY - check --file /var/ossec/etc/ossec.conf < tools/patch_ossec_conf.py
podman exec -i $C $PY - apply --file /var/ossec/etc/ossec.conf --dry-run < tools/patch_ossec_conf.py
podman exec -i $C $PY - apply --file /var/ossec/etc/ossec.conf < tools/patch_ossec_conf.py
```

Первая команда показывает, каких строк не хватает, вторая показывает diff без записи, третья вносит изменения.

Смонтированный файл на хосте (чтобы исправление пережило пересоздание контейнера):

```fish
set -g conf_src (podman inspect $C --format '{{range .Mounts}}{{if eq .Destination "/wazuh-config-mount/etc/ossec.conf"}}{{.Source}}{{end}}{{end}}')
echo $conf_src
python3 tools/patch_ossec_conf.py check --file $conf_src
python3 tools/patch_ossec_conf.py apply --file $conf_src
```

Если `echo $conf_src` ничего не вывел, файл в вашем развёртывании не монтируется, и этот блок можно пропустить.

### Шаг 8. Проверка конфигурации и перезапуск

```fish
podman exec $C /var/ossec/bin/wazuh-analysisd -t
echo $status
podman restart $C
podman exec $C /var/ossec/bin/wazuh-control status
```

Ожидается код 0 (допустимы предупреждения, ошибок `ERROR` быть не должно). После перезапуска все демоны должны быть в состоянии `is running`. Копии `ossec.conf.bak-ti-ВРЕМЯ` в `/var/ossec/etc/` после успешной проверки можно удалить (раздел «Очистка»).

### Шаг 9. Расписание на хосте

Вариант 1, пользовательский таймер systemd (рекомендуется):

```fish
mkdir -p ~/.config/systemd/user
cp wazuh-ti-updater.service wazuh-ti-updater.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now wazuh-ti-updater.timer
loginctl enable-linger $USER
systemctl --user list-timers wazuh-ti-updater.timer
```

Проверка запуска вручную:

```fish
systemctl --user start wazuh-ti-updater.service
systemctl --user status wazuh-ti-updater.service
podman exec $C tail -n 20 /var/ossec/logs/wazuh-ti-updater.log
```

Ненулевой код updater делает юнит `failed`, что удобно для мониторинга. Если контейнер в момент запуска остановлен, `podman exec` завершится ошибкой, и обновление произойдёт в следующий запуск.

Вариант 2, cron (используйте ОДИН из двух способов, не оба сразу). Строка добавляется к существующему crontab пользователя, под которым работает Podman, ничего не стирая:

```fish
begin; crontab -l 2>/dev/null; cat wazuh-ti-updater.cron; end | crontab -
crontab -l
```

### Шаг 10. Получение DNS-логов BIND

Выберите ОДИН способ, подходящий вашей инфраструктуре. Включать оба для одного DNS-сервера не нужно: события будут приходить дважды. Оба блока находятся в `ossec.conf.snippet.xml`.

**Формат события, который ожидает декодер:**

```text
2026-11-09T14:05:57.757165+03:00 dc-02 named[641085]: queries: client @0x78c719d8bd88 10.16.18.117#54328 (kubernetes.default.svc.default.svc.cluster.local): query: kubernetes.default.svc.default.svc.cluster.local IN A +E(0) (10.16.18.13)
```

Требования:

* **Syslog-заголовок:** время, имя хоста и `named[PID]:`. Программа (`predecoder.program_name`) должна начинаться с `named`. Подходит ISO-время, как в примере, и обычный syslog-заголовок.
* **Категория `queries:`** в начале сообщения. Серьёзность `info:` после неё допустима.
* **Адрес DNS-сервера в скобках в конце строки** обязателен: из него берётся `dns_server`. Он появляется в логах современных версий BIND. Если его нет, поля не извлекаются.
* Остальное: `client [@0x...] IP#порт (имя): [view имя: ] query: имя IN ТИП флаги`.
* Если named пишет лог сам, без syslog-заголовка, направьте категорию `queries` в syslog. Справочный пример для `named.conf` (в проекте не проверялся):

```text
logging {
    channel query_syslog {
        syslog daemon;
        severity info;
        print-category yes;
    };
    category queries { query_syslog; };
};
```

**Вариант А. Агент Wazuh на DNS-сервере (`<localfile>`).** Агент установлен и зарегистрирован на DNS-сервере, rsyslog пишет `named` в файл, агент читает файл. Блок добавляется в `ossec.conf` агента или в `agent.conf` группы на Manager:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/named/queries.log</location>
</localfile>
```

Справочный пример правила rsyslog, которое пишет строки с ISO-временем, как в примере события (в проекте не проверялся): `if $programname == 'named' then /var/log/named/queries.log;RSYSLOG_FileFormat`. Агентам нужен доступ к портам 1514 и 1515 Manager (в compose они должны быть опубликованы).

**Вариант Б. Прямая передача syslog на Manager (`<remote>`).** rsyslog на DNS-сервере пересылает сообщения `named` по UDP на Manager. Блок добавляется в `ossec.conf` Manager (то же правило: добавить строки, не заменять файл):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.16.18.13</allowed-ips>
</remote>
```

`allowed-ips` задаёт адрес DNS-сервера, замените его адресом вашего сервера. В Podman порт контейнера нужно опубликовать на хосте. Rootless Podman по умолчанию не занимает привилегированные порты, поэтому обычно публикуют `5514:514/udp` и указывают порт 5514 в rsyslog. Исходный адрес пакета в контейнере может подменяться (зависит от сетевого режима rootless Podman), и тогда `allowed-ips` не совпадёт. Этот вариант в проекте не проверялся (см. раздел «Ограничения и непроверенные сценарии»); если адрес подменяется, надёжнее вариант А.

## Проверка

Проверка разделена на три уровня. Каждый следующий проверяет больше, но требует больше окружения.

| Уровень | Что проверяет | Что нужно | Где запускается |
| --- | --- | --- | --- |
| 1. Автономные тесты | XML, пути, согласованность файлов, эмуляция декодера и правил, самотест updater, скрипт правки `ossec.conf` | Только Python 3.8+ | Хост, без Wazuh и сети |
| 2. `wazuh-logtest` | Настоящие декодер и правила Manager на строках лога | Работающий Manager и списки | Хост через `podman exec` |
| 3. Интеграционная проверка | Весь путь: файл, `wazuh-logcollector`, анализ, `alerts.json`, Dashboard | Manager, временный `localfile` | Хост через `podman exec` и браузер |

### Уровень 1. Автономные тесты

```fish
python3 -I tests/check_project.py
```

Скрипт проверяет состав архива, отсутствие секретов, резервных копий и временных логов, XML, декодеры (порядок, фаззинг prematch против regex), правила (порядок, поля, уровни, MITRE), согласованность имён списков в `config.ini`, правилах, `ossec.conf.snippet.xml` и `tools/patch_ossec_conf.py`, постоянные пути, эмуляцию на `tests/fixtures/dns-events.log` против ожиданий в `tests/fixtures/dns-events.expected.tsv`, генератор событий и сверку алертов, скрипт правки `ossec.conf` (идемпотентность, комментарии, удаление временного `localfile`), самотест updater и этот README. Итог: `ПРОВЕРКА ПРОЙДЕНА: N проверок`.

Это не замена уровням 2 и 3: стандартные правила Wazuh в эмуляции не моделируются, а `wazuh-logtest`, перезагрузка списков и `alerts.json` без Manager не проверяются. Эти шаги требуют интеграционной проверки на работающем Wazuh.

### Уровень 2. `wazuh-logtest`

```fish
./tests/logtest.sh
./tests/logtest.sh --short
```

Скрипт строит события из реальных доменов ваших текущих списков (по одному на каждое правило 100201, 100202, 100203, 100204, 100210, 100211 и два контрольных запроса), печатает таблицу ожидаемых правил и прогоняет каждое событие через `wazuh-logtest -v`. Алерты при этом не создаются. В выводе смотрите Phase 2 (поля `srcip`, `query`, `query_type`, `dns_server`, `query_d2`, `query_d3`) и Phase 3 (`id`, `level`).

Одно событие вручную (домен подставьте из своего списка, например `podman exec $C head -n 3 /var/ossec/etc/lists/ti-urlhaus`):

```fish
echo '2026-11-09T14:05:57.757165+03:00 dc-02 named[641085]: queries: client @0x78c719d8bd88 10.16.18.117#54328 (x.123.ywxww.net): query: x.123.ywxww.net IN A +E(0) (10.16.18.13)' | podman exec -i $C /var/ossec/bin/wazuh-logtest -v
```

Режим `./tests/logtest.sh --fixtures` берёт события из `tests/fixtures/dns-events.log` (домены `.test`) и годится только для ТЕСТОВОГО стенда, где установлены образцы из `tests/fixtures/lists/`. На рабочем Manager он ничего не найдёт.

В `-v` должна быть строка `Trying rule: 100200`, затем перебор дочерних правил и `*Rule 1002xx matched`. Если строки `Trying rule: 100200` нет, смотрите раздел «Устранение неполадок».

### Проверка применения списков

После каждого обновления updater выполняет `wazuh-analysisd -t` и `wazuh-control reload`. Убедитесь, что Manager действительно использует свежие списки:

```fish
podman exec $C tail -n 30 /var/ossec/logs/wazuh-ti-updater.log
podman exec $C sh -c "grep -i 'reload' /var/ossec/logs/ossec.log | tail -n 5"
./tests/logtest.sh --short
```

В журнале updater не должно быть строк `reload ... не удался`, а `./tests/logtest.sh` должен находить домены, взятые из свежих списков. Формулировка сообщений в `ossec.log` зависит от версии. Если после reload новые IOC не срабатывают, а после перезапуска срабатывают, значит reload внутри контейнера списки не подхватывает. Тогда перезапускайте Manager командой `podman restart` на хосте после обновления или замените `reload_command` в `config.ini` на `/var/ossec/bin/wazuh-control restart`. Отдельная проверка reload без рестарта в эталонной среде не выполнялась (см. «Ограничения»).

### Интеграционная проверка (временный localfile)

Проверяются настоящий сбор и анализ: файл, `wazuh-logcollector`, анализатор, `alerts.json`, Dashboard. События синтетические и берутся по реальным доменам ваших списков. Реальный DNS-сервер не нужен и не участвует. Временный `localfile` НЕ входит в постоянную конфигурацию проекта: он добавляется и удаляется отдельными командами, а после проверки обязательно убирается (раздел «Очистка»).

**1. Временный файл и `localfile`.** Скрипт ставит блок с комментариями-маркерами `wazuh-ti-integration-test` и делает копию `ossec.conf`:

```fish
podman exec $C sh -c 'touch /tmp/wazuh-ti-dashboard-test.log && chmod 0644 /tmp/wazuh-ti-dashboard-test.log'
podman exec -i $C $PY - add-test-localfile --file /var/ossec/etc/ossec.conf < tools/patch_ossec_conf.py
```

В `ossec.conf` появится:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/tmp/wazuh-ti-dashboard-test.log</location>
</localfile>
```

**2. Проверка конфигурации и перезапуск Manager.**

```fish
podman exec $C /var/ossec/bin/wazuh-analysisd -t
podman restart $C
```

**3. Проверка `wazuh-logcollector`.**

```fish
podman exec $C /var/ossec/bin/wazuh-control status
podman exec $C sh -c "grep 'wazuh-ti-dashboard-test' /var/ossec/logs/ossec.log | tail -n 3"
```

В статусе `wazuh-logcollector` должен быть `is running`; в `ossec.log` обычно есть строка о том, что файл `/tmp/wazuh-ti-dashboard-test.log` анализируется.

**4. Запись событий и автосверка алертов.**

```fish
./tests/send-events.sh
```

Скрипт дописывает события в временный файл, ждёт 20 секунд (`WAIT_SECONDS`), читает `alerts.json` и сверяет каждый домен с ожидаемым правилом и уровнем: строки `PASS` или `FAIL`, код возврата 0 при успехе. Для контрольных доменов ожидается отсутствие TI-алерта.

**5. Проверка алертов в `alerts.json` вручную.**

```fish
podman exec $C sh -c "grep -E '\"id\":\"1002(0[1-4]|1[01])\"' /var/ossec/logs/alerts/alerts.json | tail -n 6"
podman exec -i $C $PY - --minutes 30 < tests/show_alerts.py
```

Вторая команда выводит таблицу: время, `rule.id`, уровень, декодер, `data.query`, `data.query_d2`, `data.query_d3`, `data.srcip`, агент. Алерты читаются из `/var/ossec/logs/alerts/alerts.json`; за время теста на Manager читается только хвост файла.

**6. Проверка в Dashboard.** Откройте `https://localhost:8443`, раздел Discover (меню Explore) с шаблоном индекса `wazuh-alerts-*` или модуль Threat Hunting, события, период «Last 30 minutes». Названия пунктов меню зависят от версии Dashboard. Примеры запросов (DQL) для поиска по Rule ID:

```text
rule.id: 100201
rule.id: (100201 or 100202 or 100203 or 100204 or 100210 or 100211)
rule.groups: ti_dns
rule.groups: ti_exact_match
rule.groups: ti_subdomain_match
rule.level >= 10 and rule.groups: ti_dns
data.query: "123.ywxww.net"
agent.name: "wazuh.manager" and location: "/tmp/wazuh-ti-dashboard-test.log"
```

В карточке события проверьте поля: `predecoder.program_name`, `data.query`, `data.query_d2`, `data.query_d3`, `data.srcip`, `data.dns_server`, `data.query_type`, `rule.id`, `rule.level`, `rule.description`, `rule.mitre`. Поскольку файл читает логколлектор самого Manager, у событий `agent.name: wazuh.manager`. Поля `data.query_d2` и `data.query_d3` есть только у имён из трёх и более меток.

### Очистка после интеграционной проверки

Выполните всегда, когда проверка закончена:

```fish
podman exec -i $C $PY - remove-test-localfile --file /var/ossec/etc/ossec.conf < tools/patch_ossec_conf.py
podman exec -i $C $PY - check --file /var/ossec/etc/ossec.conf < tools/patch_ossec_conf.py
echo $status
podman exec $C /var/ossec/bin/wazuh-analysisd -t
podman restart $C
podman exec $C /var/ossec/bin/wazuh-control status
podman exec $C rm -f /tmp/wazuh-ti-dashboard-test.log /tmp/wazuh-ti-expected.tsv
podman exec $C sh -c 'rm -f /var/ossec/etc/ossec.conf.bak-ti-*'
```

Ожидается: `check` печатает «Конфигурация в порядке» и код 0 (код 2 означает, что временный `localfile` остался), `wazuh-analysisd -t` проходит, `wazuh-logcollector` запущен с новым PID, временные файлы удалены. Удалять копии `bak-ti-*` стоит после того, как вы убедились, что Manager работает. Рабочие TI-правила, декодер и CDB-списки при очистке не затрагиваются; проверить это можно командой `./tests/logtest.sh --short`.

Если вы также правили смонтированный файл на хосте, временный `localfile` туда не добавлялся и очищать там нечего. Тестовые алерты, уже попавшие в Indexer, остаются в истории; чтобы скрыть их в Dashboard, добавьте условие `not location: "/tmp/wazuh-ti-dashboard-test.log"`.

## Результаты интеграционного тестирования

Проверка выполнена на Wazuh Manager, Indexer и Dashboard 4.14.10 (single-node, rootless Podman, Arch Linux), ноябрь 2026.

**Что проверялось:** создан временный файл DNS-событий; в активный `ossec.conf` добавлен временный `<localfile>`; Manager перезапущен; `wazuh-logcollector` запущен; в файл записаны пять синтетических событий BIND; все пять событий появились в `/var/ossec/logs/alerts/alerts.json` и были отображены в Dashboard. Проверялись синтетические события BIND, проходящие через настоящий механизм сбора и анализа Wazuh. Подключение настоящего DNS-сервера и приём реального DNS-трафика НЕ проверялись.

| Домен (запись списка) | Источники | Rule ID | Уровень |
| --- | --- | ---: | ---: |
| `ahiak.com` | URLhaus и ThreatFox | 100201 | 14 |
| `000.hikvision-cctv.su` | ThreatFox | 100202 | 13 |
| `123.ywxww.net` | URLhaus | 100203 | 12 |
| `0-ilxrc-w285.p9bckp.sbs` | PhishingArmy | 100204 | 10 |
| `test.000.hikvision-cctv.su` (поддомен) | родитель `000.hikvision-cctv.su` | 100211 | 8 |

Домены взяты из реальных списков на момент проверки; со временем они могут выйти из фидов, поэтому при повторной проверке используйте `./tests/send-events.sh`, который подбирает домены из текущих списков.

В Dashboard подтверждены поля `predecoder.program_name`, `data.query`, `data.query_d2`, `data.query_d3`, `data.srcip`, `data.dns_server`, `data.query_type`, `rule.id`, `rule.level`, `rule.description`, `rule.mitre`. У всех пяти событий `agent.name: wazuh.manager`.

**Результаты `wazuh-logtest`** (при установке и исправлении декодера): `x.123.ywxww.net` даёт 100211; `123.ywxww.net` даёт 100203; `example.org` и `localhost` декодируются полностью (`srcip`, `query`, `query_type`, `dns_server`) и дают базовое правило 100200 без алерта; по одному двухметочному домену из `ti-urlhaus`, `ti-threatfox`, `ti-phishingarmy` и `ti-multi` срабатывают 100203, 100202, 100204 и 100201 соответственно; стандартная строка BIND `denied` по-прежнему даёт стандартное правило 12108.

**Правило 100210 интеграционным тестом на живом Wazuh не подтверждено.** Его логика отличается от подтверждённого 100211 только полем (`query_d2` вместо `query_d3`) и списком условий; на живом Manager это не проверялось. Генератор `tests/make-live-events.py` формирует для него событие `test.` плюс двухметочный домен из `ti-domains`, поэтому оно проверяется той же командой `./tests/send-events.sh` (строка `100210` в итоговой сверке). До такой проверки считайте правило ожидающим подтверждения.

## Эксплуатация

```fish
# обновить прямо сейчас
podman exec $C $TI/run-updater.sh

# посмотреть, что изменится, ничего не записывая
podman exec $C $TI/run-updater.sh --dry-run

# обновить один источник (остальные берутся из накопленной истории)
podman exec $C $TI/run-updater.sh --source phishingarmy

# обновить несмотря на защиту от резкого сокращения списка (после ручной проверки причины)
podman exec $C $TI/run-updater.sh --force

# журнал, итог последнего запуска, число IOC по источникам
podman exec $C tail -n 50 /var/ossec/logs/wazuh-ti-updater.log
podman exec $C cat $TI/state/status.json
```

Коды возврата: `0` успех, `1` ошибка конфигурации, `2` источник недоступен и резервных данных нет (списки не тронуты), `3` не прошла проверка и выполнен откат, `4` списки обновлены, но reload не удался (повтор при следующем запуске), `5` уже запущен другой экземпляр, `6` обновление выполнено, но часть источников работала по накопленной истории.

**Ручной откат списков.** Бэкап хранится по запускам и содержит только те списки, которые изменил запуск:

```fish
podman exec $C ls $TI/state/backups
set -g last (podman exec $C sh -c 'ls -1 /var/ossec/wodles/wazuh-ti/state/backups | tail -n 1')
podman exec $C sh -c "cp -p /var/ossec/wodles/wazuh-ti/state/backups/$last/* /var/ossec/etc/lists/"
podman exec $C /var/ossec/bin/wazuh-control reload
```

**Ложные срабатывания.** Добавьте домен в `/var/ossec/wodles/wazuh-ti/allowlist.txt` (точное совпадение, по одному в строке): он исчезнет из списков при следующем запуске.

Посмотреть текущий список исключений и заменить его своей версией (локальный `allowlist.txt` из проекта считается источником правды):

```fish
podman exec $C cat $TI/allowlist.txt
podman cp allowlist.txt $C:$TI/allowlist.txt
podman exec $C chown root:wazuh $TI/allowlist.txt
podman exec $C chmod 0640 $TI/allowlist.txt
```

**Обновление проекта на уже настроенном Manager.** Скопируйте только `wazuh-ti-updater.py` и `run-updater.sh` (шаг 1), декодер и правила (шаг 6), затем выполните шаги 7 и 8 (повторный `apply` безопасен). Не перезаписывайте `config.ini`, `allowlist.txt`, `abusech.key` и каталог `state`: в них ваши настройки, исключения, ключ и накопленные IOC.

**Проверка постоянства данных (по желанию, не выполнялась автором).** Остановка SIEM на время проверки неизбежна. Выполните в каталоге вашего compose-файла `podman-compose down`, затем `podman-compose up -d` (без ключа `-v`: ключ `-v` удаляет тома и запрещён), после чего проверьте, что на месте `$TI/abusech.key`, `$TI/state`, списки `ti-*`, декодер и правила, а `./tests/logtest.sh` по-прежнему даёт правила TI.

## Ограничения и непроверенные сценарии

Не проверялось на живом окружении:

* **Реальный DNS-сервер и DNS-трафик.** Ни вариант А (агент на DNS-сервере), ни вариант Б (прямой syslog) не подключались. Проверялись только синтетические события BIND через `localfile` Manager.
* **Правило 100210** не подтверждено интеграционным тестом (см. выше).
* **Вариант Б в rootless Podman:** публикация порта, привилегированные порты и возможная подмена исходного адреса (`allowed-ips`).
* **`wazuh-control reload` внутри контейнера** как способ применения списков без рестарта проверен отдельно не был (см. «Проверка применения списков»).
* **Расписание на хосте** (пользовательский таймер и cron): юниты составлены по поведению `podman exec`, но в рамках этой актуализации не запускались на эталонном хосте.
* **Пересоздание контейнера** (`down` и `up`): постоянство обеспечено размещением данных в томах, сама процедура не выполнялась.
* **Адреса hostfile-фидов abuse.ch** (`hostfile.txt`) не подтверждены; фиды помечены `required = false`.
* **Другие версии Wazuh.** Копия стандартного декодера сделана с версии 4.14.10.
* **Кластер Wazuh.** Updater нужно запускать на master-узле, синхронизацию `etc/lists` на worker-узлы нужно проверить отдельно.

Свойства решения:

* **Регистр.** CDB различает регистр, списки хранят домены в нижнем регистре. Запросы с рандомизацией регистра (0x20) не совпадут. Нормализуйте регистр в источнике логов или rsyslog.
* **Точное совпадение ключей.** CDB сравнивает ключ целиком, поэтому родительский домен вычисляется в декодере (последние 2 и 3 метки). Более глубокие вложения требуют поля `query_d4`.
* **IP-адреса.** Хосты, заданные IP-адресом, в списки не попадают: DNS-проверка к ним не применима. DoH и DoT этим решением не видны.
* **Шумные списки.** `retention_days` увеличивает охват, но и число ложных срабатываний. Значения по умолчанию: URLhaus 14, ThreatFox 30, Phishing Army 7 суток.
* **Установка без контейнера** описана отдельно в `contrib/baremetal/README.txt`; в варианте Podman эти файлы не используются.

## Устранение неполадок

| Симптом | Причина и действие |
| --- | --- |
| `HTTP 401/403` в журнале | Неверный или не созданный Auth-Key; пересоздайте файл по шагу 2 |
| `HTTP 404` для hostfile | Неверное имя файла в `url`; возьмите ссылку из кабинета abuse.ch |
| `получен HTML вместо данных` | Прокси или портал перехватывает запрос, либо ошибка авторизации |
| Код 2, `ОБНОВЛЕНИЕ ПРЕРВАНО` | Источник недоступен без резервных данных или сработала защита от сокращения списка; смотрите строку выше в журнале |
| Код 3 | `wazuh-analysisd -t` вернул ошибку; смотрите строки `validate:` в журнале, чаще причина в `ossec.conf` или XML |
| `podman exec` сообщает, что контейнер не найден или не запущен | Проверьте имя через `podman ps -a`; для таймера задайте его в `wazuh-ti-updater.service` |
| Таймер не срабатывает при закрытой сессии | Выполните `loginctl enable-linger $USER` |
| Cron не запускает `podman exec` | В crontab нет `XDG_RUNTIME_DIR`; используйте строку из `wazuh-ti-updater.cron` |
| `List 'etc/lists/...' could not be loaded` в `ossec.log` | Список не объявлен в `<ruleset>` или файла нет (шаг 5 и шаг 7) |
| Алертов нет, декодирование есть | Списки не применены (нужен перезапуск, см. «Проверка применения списков»), либо регистр имени, либо домена нет в списках |
| `wazuh-logtest` не извлекает поля | Строка не подходит под формат декодера (шаг 10): нет адреса DNS-сервера в конце, нет `queries:` или `named` в заголовке |
| Для поддоменов нет `query_d2`, `query_d3`, правила 100210 и 100211 не срабатывают | Событие разбирает стандартный `named-query`. Нужны `decoder_exclude` для `0155-named_decoders.xml` (шаг 7) и файл декодеров из проекта (шаг 6) |
| Для имён вроде `example.org` пропали `query`, `srcip`, `dns_server` | Установлена устаревшая версия декодера со слабым `prematch`; установите файл из этого архива |
| Поля есть, но в `wazuh-logtest -v` нет `Trying rule: 100200`, срабатывает стандартное правило 121xx | Правило 100200 затенено стандартным соседом. Нужна версия файла правил с `<if_group>named</if_group>` |
| После пересоздания контейнера пропали правила поддоменов | В смонтированном `ossec.conf` на хосте нет строк TI; повторите шаг 7 для `$conf_src` |
| `check` печатает код 2 | Остался временный localfile интеграционной проверки; выполните очистку |
| `wazuh-analysisd -t` сообщает о дублирующемся декодере | Не добавлен `decoder_exclude` или в `etc/decoders` лежит ещё один файл с декодером `named` (команды шага 0) |
