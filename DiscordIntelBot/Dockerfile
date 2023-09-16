FROM python:3.10-alpine3.16

LABEL version="swarm-1.6.2"

RUN mkdir -p /app/Source

RUN addgroup -S botgroup && adduser -Ds /sbin/nologin discordbot -G botgroup

ENV TZ="Europe/Paris"

WORKDIR /app

USER discordbot:botgroup

ENV PATH="${PATH}:/home/discordbot/.local/bin"

RUN python3.10 -m pip install --upgrade pip
COPY ./requirements.txt ./
RUN python3.10 -m pip install -r requirements.txt

COPY ./Source/*.py ./Source/

USER root:root
RUN chown -R discordbot:botgroup /app/* && chmod +x ./Source/DiscordIntelBot.py && chmod +x ./Source/Formatting.py

USER discordbot:botgroup

CMD [ "python3.10", "/app/Source/DiscordIntelBot.py" ]
