FROM debian:bookworm-slim AS tool-target
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl vsftpd \
    && rm -rf /var/lib/apt/lists/*
COPY tool_target.py /lab/tool_target.py
ENTRYPOINT ["python3", "-B", "/lab/tool_target.py"]

FROM debian:bookworm-slim AS tool-runner
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl ca-certificates bsdextrautils procps dnsutils \
    && rm -rf /var/lib/apt/lists/*
COPY install_tools.py /lab/install_tools.py
RUN python3 -B /lab/install_tools.py
ENV PATH="/opt/bin:${PATH}" PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /workspace
ENTRYPOINT ["python3", "-B", "lab/tool_lab.py"]
