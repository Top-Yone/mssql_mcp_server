FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for pymssql
RUN apt-get update && apt-get install -y \
    freetds-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Install local package (src layout)
RUN pip install --no-cache-dir -e .

EXPOSE 8000

# Run the MCP server
CMD ["python", "-m", "mssql_mcp_server"]
