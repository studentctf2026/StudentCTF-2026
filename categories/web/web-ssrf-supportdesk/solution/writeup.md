## SupportDesk

| Событие | Название | Категория |
| :------ | ---- | ---- |
| Student CTF 2026 | SupportDesk | web |

### Описание

> SupportDesk — кабинет поддержки продавцов маркетплейса. К обращению можно
> приложить ссылку на товар: сервис автоматически проверит её перед тем, как
> показать оператору. Для диагностики интеграций доступен персональный Callback
> Inbox с журналом входящих уведомлений.

### Решение

Сначала создаём Callback Inbox в разделе «Инспектор уведомлений». После создания
нам один раз показывают callback URL вида:

```text
http://callback.support.local:3000/api/callbacks/<inbox-id>/<token>
```

Этот адрес недоступен из браузера игрока, но его не нужно открывать напрямую:
все запросы на него появляются в журнале созданного Inbox. Значит, если какой-то
внутренний сервис сделает туда запрос, мы увидим его method, body и headers.

Дальше смотрим форму создания обращения и справку о вложениях. Scanner принимает
ссылки на доверенный корпоративный short-link `go.support.local`; поле формы
подсказывает формат `http://go.support.local/r?to=...`. В legacy-документации
интеграций есть сервис `notifier` и его тестовый endpoint:

```text
GET /subscriptions/test?callback=<registered callback URL>
```

Внутри Docker-сети notifier работает на `notifier:8080`. Он принимает
зарегистрированный callback URL и отправляет на него тестовое уведомление.

Проверяем, как scanner валидирует прикреплённую ссылку. Он разрешает только
исходный URL с hostname `go.support.local`, но затем выполняет HTTP-запрос с
автоматическим переходом по redirect. URL после `302` повторно не валидируется.
Поэтому прямой запрос к `notifier` будет отклонён, а запрос к доверенному `go`,
который редиректит на notifier, пройдёт.

Собираем внутренний URL notifier, подставляя callback URL своего Inbox:

```text
http://notifier:8080/subscriptions/test?callback=<URL-encoded callback URL>
```

Затем URL-encode'им его целиком и передаём в `to` short-link:

```text
http://go.support.local/r?to=<URL-encoded notifier URL>
```

Получившуюся ссылку прикладываем к новому тикету. Происходит следующая цепочка:

1. scanner проверяет hostname исходного URL и видит разрешённый
   `go.support.local`;
2. `go` отвечает `302 Found` с `Location` на `notifier`;
3. scanner следует redirect и вызывает `/subscriptions/test`;
4. notifier отправляет `POST` в наш Callback Inbox;
5. notifier получает флаг из своего `flag.txt` и передаёт его в заголовке
   `X-Verification-Code`;
6. web сохраняет доставку, и мы видим этот заголовок в журнале Inbox.

Это blind SSRF: в карточке тикета scanner показывает лишь успешный статус
проверки. Response body notifier, конечный URL и заголовки игроку не отдаются.
Флаг появляется только как побочный эффект — во входящей callback-доставке.

Готовый автоматизированный вариант находится в
[solve.py](solve.py). Он создаёт Inbox, формирует оба вложенных
URL, ждёт статус тикета `passed` и извлекает `x-verification-code` из delivery
log.

### Флаг

В локальной конфигурации:

```text
stctf{S5PP0rtd3Sk_b11Nd_R3d1Rect_C411b4ck}
```

На боевом инстансе значение определяется содержимым `flag.txt`.
