# TovarScout Bot 

## Описание

Это чистая версия Telegram-бота TovarScout для поиска товаров по украинским магазинам. Все секреты и конфигурация берутся из файла `secrets.example.json`. 

## Как запустить

1. Установите Python 3.11+ и необходимые зависимости:
   ```sh
   pip install -r requirements.txt
   ```
2. Скопируйте `secrets.example.json` в `secrets.json` и укажите свой Telegram Bot Token:
   ```json
   {
     "TELEGRAM_TOKEN": "ваш_токен_бота",
     "DB_PATH": "data/tovarscout.db"
   }
   ```
3. Запустите бота:
   ```sh
   python TovarScout.py
   ```

## Docker

1. Соберите образ:
   ```sh
   docker build -t tovarscout .
   ```
2. Запустите через docker-compose:
   ```sh
   docker-compose up --build
   ```

## Для корректной работы
- Укажите свой Telegram Bot Token в `secrets.json`.
- Проверьте, что папка `data/` существует (для хранения базы данных).
- Для поиска товаров бот использует публичные сайты и не требует дополнительных ключей.

