FROM python:3.10-alpine3.16

LABEL version="swarm-1.1"

RUN mkdir -p /app/Source
RUN mkdir -p /app/TelegramImages

RUN addgroup -S botgroup && adduser -Ds /sbin/nologin discordbot -G botgroup

ENV TZ="Europe/Paris"

WORKDIR /app

COPY . ./
RUN chown -R discordbot:botgroup /app/* && chmod +x ./Source/TelegramIntelBot.py

USER discordbot:botgroup

ENV PATH="${PATH}:/home/discordbot/.local/bin"

RUN python3.10 -m pip install --upgrade pip
RUN python3.10 -m pip install -r requirements.txt

CMD [ "python3.10", "/app/Source/TelegramIntelBot.py" ]
