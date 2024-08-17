FROM python:3.11-alpine

LABEL version="swarm-2.0.0"

RUN mkdir -p /app/Source/Bots

RUN addgroup -S botgroup && adduser -Ds /sbin/nologin discordbot -G botgroup
RUN apk update --no-cache && apk add gcc musl-dev

ENV TZ="Europe/Paris"

WORKDIR /app

USER discordbot:botgroup

ENV PATH="${PATH}:/home/discordbot/.local/bin"

RUN python3.11 -m pip install --upgrade pip
COPY ./requirements.txt ./
COPY ./config.ini ./
RUN python3.11 -m pip install -r requirements.txt

COPY ./Source/*.py ./Source/
COPY ./Source/Bots/RSS.py ./Source/Bots

USER root:root
RUN chown -R discordbot:botgroup /app/* && chmod +x ./Source/*.py && chmod +x ./Source/Bots/*.py

USER discordbot:botgroup

CMD [ "python3.11", "-m", "Source", "rss" ]
