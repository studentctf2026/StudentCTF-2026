FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libc6 \
        libgcc-s1 \
        libstdc++6 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash stctf

WORKDIR /home/stctf

COPY task .
COPY flag .

RUN chmod 755 task && \
    chmod 444 flag && \
    chown -R stctf:stctf /home/stctf

EXPOSE 5555

USER stctf

CMD ["./task"]