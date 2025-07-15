# Linux as a service (LaaS)

## Dev run

Запустите докер композ

```powershell
docker-compose up --build
```

Теперь зайдите в постман и запустите первый GET эндпоинт (`{{base_url}}/auth/new`)
Вам должен прийти ответ следующего типа

```json
{
    "id": 1,
    "pubKey": {
        "e": 65537,
        "n": 8005186501273859401339992441661974480606907813508113919617996890637798184491989447874245491118254334962410075546665741190207922015778208339654413661181267
    }
}
```

Из него вам нужны поля `pubKey.e` и `pubKey.n` вставьте их в скрипт tmp/encrypt_secret.py
Запустите этот скрипт

```powershell
& C:/Users/FINet/Documents/LaaS/.venv/Scripts/python.exe c:/Users/FINet/Documents/LaaS/tmp/encrypt_secret.py
```

```txt
--- Use these values in your next Postman request ---
Generated JWT Secret Key (for your reference): b203ca9c-6023-495d-aa99-5d205c295ddd
Encrypted Hex Cipher (for the 'hex_cipher' field): 55f539d0d1d181080d2866ae58a370bd6bd036b26109fb055b87489644bf3dbd364e32763ba6875a4b03fc3341c19ce2b41d34ba8d6198d5b30ae17f840c8369
```

теперь, возьмите последний hex и вставьте его в поле `hex_cipher` во вкладке Globals
Запустите POST запрос на `{{base_url}}/auth/complete`

Получите следующий ответ

```json
{"id": 1, "token": "JWT token"}
```

возьмите token и вставьте его в поле `jwt_token` во вкладке Globals
Запустите следующий POST запрос `{{base_url}}/linux/`

Вы должны увидеть вывод команды `ls` в raw формате
Запустите эндпоит GET `{{base_url}}/linux/`
Вам придет информация о вашей сессии

Тесты я не писал (пары только на следующей неделе ¯\\\_(ツ)_/¯) так что не судите строго, мой первый проект без вайб-кодинга
