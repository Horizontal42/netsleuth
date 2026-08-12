FROM mcr.microsoft.com/devcontainers/python:1-3.12

# Install system dependencies
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        net-tools \
        iputils-ping \
        traceroute \
        dnsutils \
        curl \
        git \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
RUN pip install --upgrade pip uv

# Set working directory
WORKDIR /workspace

# Copy project files
COPY . .

# Install dependencies
RUN uv pip install -e .[dev]

# Default command
CMD ["bash"]
