# netmon · add-on con la sonda. Stessa base di Raspberry Pi OS (Debian 12) e stessi pacchetti di
# installa-sonda.sh: la sonda gira qui come sul Raspberry.
FROM debian:bookworm-slim

# requests non arriva da Debian (2.28, con vulnerabilità note): la sonda non lo usa, serve solo a
# fritzconnection, e pip installa nell'ambiente della sonda la versione corrente con le correzioni.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv python3-yaml \
        iputils-ping iproute2 iw ca-certificates openssl \
    && python3 -m venv --system-site-packages /opt/netprobe/venv \
    && /opt/netprobe/venv/bin/pip install --no-cache-dir fritzconnection==1.15.1 \
    && rm -rf /var/lib/apt/lists/* /root/.cache

COPY probe/ /opt/netprobe/
COPY addon.py /opt/netprobe/addon.py
COPY systemctl /usr/local/bin/systemctl
# bytecode già pronto: la pagina locale parte su richiesta e così non ricompila config_web.py
RUN python3 -m compileall -q /opt/netprobe/*.py

CMD ["/opt/netprobe/venv/bin/python", "/opt/netprobe/addon.py"]
