FROM mcr.microsoft.com/devcontainers/dotnet:2-9.0-noble

RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    ninja-build \
    pkg-config \
    git \
    libnss3-dev \
    libnspr4-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel 8.0 --install-dir /usr/share/dotnet \
    && rm /tmp/dotnet-install.sh