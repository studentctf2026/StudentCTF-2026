FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y gcc socat && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY task /app/task
COPY flag.txt /flag.txt

RUN useradd -m ctf && \
    chown root:ctf /flag.txt && \
    chmod 640 /flag.txt && \
    chmod 755 /app/task

USER ctf

EXPOSE 45454

CMD ["socat", "TCP-LISTEN:45454,reuseaddr,fork", "EXEC:/app/task,stderr"]