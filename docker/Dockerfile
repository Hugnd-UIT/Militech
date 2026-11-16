FROM kalilinux/kali-rolling

LABEL maintainer="Militech"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

RUN sed -i 's|http://http.kali.org/kali|http://kali.download/kali|g' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true && \
    apt-get update -o Acquire::http::No-Cache=True -o Acquire::Retries=5 && \
    apt-get install -y --no-install-recommends -o Acquire::Retries=5 \
    ca-certificates \
    curl \
    wget \
    openvpn \
    git \
    unzip \
    tar \
    file \
    jq \
    build-essential \
    clang \
    cmake \
    ninja-build \
    meson \
    pkg-config \
    zlib1g-dev \
    cppcheck \
    gdb \
    strace \
    valgrind \
    binutils \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    python3-requests \
    sudo \
    && rm -rf /var/lib/apt/lists/*

RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED && git config --global --add safe.directory '*'

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm -f /tmp/requirements.txt

COPY . /app
RUN mkdir -p /data /outputs && ln -sf /data /workspace
WORKDIR /data

ENTRYPOINT ["python3", "/app/src/core.py"]