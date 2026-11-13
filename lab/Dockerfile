ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE} AS target
RUN apt-get update && apt-get install -y --no-install-recommends samba python3 \
    && rm -rf /var/lib/apt/lists/*
COPY server.py /lab/server.py
ENTRYPOINT ["python3", "-B", "/lab/server.py"]

FROM ${BASE_IMAGE} AS runner
RUN apt-get update && apt-get install -y --no-install-recommends python3 nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
ENTRYPOINT ["python3", "-B", "lab/run_lab.py"]
