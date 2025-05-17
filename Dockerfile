# =========================
#   Volatility MCP Server
# =========================
FROM python:3.11-slim

LABEL maintainer="OMGhozlan @ Github"
LABEL description="Volatility 3-based memory forensics API server with FastMCP"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV VOLATILITY_DIR=/opt/volatility3 
ENV VOLATILITY_PYTHON=/usr/local/bin/python3
ENV VOLATILITY_SCRIPT=/opt/volatility3/vol.py
ENV SYMBOLS_DIR=/opt/volatility3/symbols
ENV MCP_PORT=8888
ENV MCP_HOST=0.0.0.0
ENV PYTHONPATH="$PYTHONPATH:/opt/volatility3"

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git curl unzip build-essential \
    libffi-dev libssl-dev libmagic-dev \
    libpython3-dev python3-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Setup Volatility 3
RUN git clone https://github.com/volatilityfoundation/volatility3 ${VOLATILITY_DIR}

# Install volatility3 in editable mode with full extras
RUN pip install -e "${VOLATILITY_DIR}[full]"

# Create directories for symbols
RUN mkdir -p ${SYMBOLS_DIR}

# Setup symbol download with build arg
ARG DOWNLOAD_SYMBOLS=true

# Download symbols based on build arg
RUN if [ "$DOWNLOAD_SYMBOLS" = "true" ]; then \
    echo "📦 Downloading Volatility 3 symbols..." && \
    cd ${SYMBOLS_DIR} && \
    for os in windows mac linux; do \
        echo "📥 Downloading $os symbols..." && \
        curl -s -O https://downloads.volatilityfoundation.org/volatility3/symbols/${os}.zip && \
        unzip -q ${os}.zip && rm ${os}.zip; \
    done; \
    else echo "⚠️ Skipping symbol download"; fi

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY volatility_mcp_server.py rich_logger.py /app/

# Create a volume for memory dumps
VOLUME ["/memory_dumps"]

# Expose the MCP server port
EXPOSE ${MCP_PORT}

# Run the server
CMD ["fastmcp", "run", "volatility_mcp_server.py:mcp", "--transport", "sse", "--host", "${MCP_HOST}", "--port", "${MCP_PORT}"]
