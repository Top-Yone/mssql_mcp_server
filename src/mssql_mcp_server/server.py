import asyncio
import logging
import os
import re
from contextlib import asynccontextmanager
from typing import Literal, cast

import pymssql
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Resource, Tool, TextContent
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Mount, Route

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mssql_mcp_server")

SUPPORTED_TRANSPORTS = {"stdio", "sse", "streamable-http"}
TRANSPORT_ALIASES = {
    "http": "streamable-http",
    "streamable_http": "streamable-http",
    "streamablehttp": "streamable-http",
}


def _normalize_http_path(path: str, env_name: str) -> str:
    """Normalize an HTTP path and validate basic format."""
    path = path.strip()
    if not path:
        raise ValueError(f"{env_name} cannot be empty")

    if not path.startswith("/"):
        path = f"/{path}"

    return path


def get_transport() -> Literal["stdio", "sse", "streamable-http"]:
    """Get MCP transport mode from environment variables."""
    raw_transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    normalized_transport = TRANSPORT_ALIASES.get(raw_transport, raw_transport)

    if normalized_transport not in SUPPORTED_TRANSPORTS:
        raise ValueError(
            "Invalid MCP_TRANSPORT value: "
            f"{raw_transport}. Supported values: stdio, sse, streamable-http"
        )

    return cast(Literal["stdio", "sse", "streamable-http"], normalized_transport)


def get_http_config():
    """Get HTTP server configuration from environment variables."""
    host = os.getenv("MCP_HOST", "127.0.0.1")
    port_raw = os.getenv("MCP_PORT", "8000")
    log_level = os.getenv("MCP_LOG_LEVEL", "info").lower()

    try:
        port = int(port_raw)
    except ValueError as exc:
        raise ValueError(f"Invalid MCP_PORT value: {port_raw}") from exc

    config = {
        "host": host,
        "port": port,
        "log_level": log_level,
        "mcp_path": _normalize_http_path(os.getenv("MCP_PATH", "/mcp"), "MCP_PATH"),
        "sse_path": _normalize_http_path(os.getenv("MCP_SSE_PATH", "/sse"), "MCP_SSE_PATH"),
        "message_path": _normalize_http_path(
            os.getenv("MCP_MESSAGE_PATH", "/messages"),
            "MCP_MESSAGE_PATH",
        ),
        "stateless_http": os.getenv("MCP_STATELESS_HTTP", "false").strip().lower() == "true",
    }

    return config

def validate_table_name(table_name: str) -> str:
    """Validate and escape table name to prevent SQL injection."""
    # Allow only alphanumeric, underscore, and dot (for schema.table)
    if not re.match(r'^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)?$', table_name):
        raise ValueError(f"Invalid table name: {table_name}")
    
    # Split schema and table if present
    parts = table_name.split('.')
    if len(parts) == 2:
        # Escape both schema and table name
        return f"[{parts[0]}].[{parts[1]}]"
    else:
        # Just table name
        return f"[{table_name}]"

def get_db_config():
    """Get database configuration from environment variables."""
    # Basic configuration
    server = os.getenv("MSSQL_SERVER", "localhost")
    logger.info(f"MSSQL_SERVER environment variable: {os.getenv('MSSQL_SERVER', 'NOT SET')}")
    logger.info(f"Using server: {server}")
    
    # Handle LocalDB connections (Issue #6)
    # LocalDB format: (localdb)\instancename
    if server.startswith("(localdb)\\"):
        # For LocalDB, pymssql needs special formatting
        # Convert (localdb)\MSSQLLocalDB to localhost\MSSQLLocalDB with dynamic port
        instance_name = server.replace("(localdb)\\", "")
        server = f".\\{instance_name}"
        logger.info(f"Detected LocalDB connection, converted to: {server}")
    
    config = {
        "server": server,
        "user": os.getenv("MSSQL_USER"),
        "password": os.getenv("MSSQL_PASSWORD"),
        "database": os.getenv("MSSQL_DATABASE"),
        "port": os.getenv("MSSQL_PORT", "1433"),  # Default MSSQL port
    }    
    # Port support (Issue #8)
    port = os.getenv("MSSQL_PORT")
    if port:
        try:
            config["port"] = int(port)
        except ValueError:
            logger.warning(f"Invalid MSSQL_PORT value: {port}. Using default port.")
    
    # Encryption settings for Azure SQL (Issue #11)
    # Check if we're connecting to Azure SQL
    if config["server"] and ".database.windows.net" in config["server"]:
        config["tds_version"] = "7.4"  # Required for Azure SQL
        # Azure SQL requires encryption - use connection string format for pymssql 2.3+
        # This improves upon TDS-only approach by being more explicit
        if os.getenv("MSSQL_ENCRYPT", "true").lower() == "true":
            config["server"] += ";Encrypt=yes;TrustServerCertificate=no"
    else:
        # For non-Azure connections, respect the MSSQL_ENCRYPT setting
        # Use connection string format in addition to TDS version for better compatibility
        encrypt_str = os.getenv("MSSQL_ENCRYPT", "false")
        if encrypt_str.lower() == "true":
            config["tds_version"] = "7.4"  # Keep existing TDS approach
            config["server"] += ";Encrypt=yes;TrustServerCertificate=yes"  # Add explicit setting
            
    # Windows Authentication support (Issue #7)
    use_windows_auth = os.getenv("MSSQL_WINDOWS_AUTH", "false").lower() == "true"
    
    if use_windows_auth:
        # For Windows authentication, user and password are not required
        if not config["database"]:
            logger.error("MSSQL_DATABASE is required")
            raise ValueError("Missing required database configuration")
        # Remove user and password for Windows auth
        config.pop("user", None)
        config.pop("password", None)
        logger.info("Using Windows Authentication")
    else:
        # SQL Authentication - user and password are required
        if not all([config["user"], config["password"], config["database"]]):
            logger.error("Missing required database configuration. Please check environment variables:")
            logger.error("MSSQL_USER, MSSQL_PASSWORD, and MSSQL_DATABASE are required")
            raise ValueError("Missing required database configuration")
    
    return config

def get_command():
    """Get the command to execute SQL queries."""
    return os.getenv("MSSQL_COMMAND", "execute_sql")

def is_select_query(query: str) -> bool:
    """
    Check if a query is a SELECT statement, accounting for comments.
    Handles both single-line (--) and multi-line (/* */) SQL comments.
    """
    # Remove multi-line comments /* ... */
    query_cleaned = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)
    
    # Remove single-line comments -- ...
    lines = query_cleaned.split('\n')
    cleaned_lines = []
    for line in lines:
        # Find -- comment marker and remove everything after it
        comment_pos = line.find('--')
        if comment_pos != -1:
            line = line[:comment_pos]
        cleaned_lines.append(line)
    
    query_cleaned = '\n'.join(cleaned_lines)
    
    # Get the first non-empty word after stripping whitespace
    first_word = query_cleaned.strip().split()[0] if query_cleaned.strip() else ""
    return first_word.upper() == "SELECT"

# Initialize server
app = Server("mssql_mcp_server")

@app.list_resources()
async def list_resources() -> list[Resource]:
    """List SQL Server tables as resources."""
    config = get_db_config()
    try:
        conn = pymssql.connect(**config)
        cursor = conn.cursor()
        # Query to get user tables from the current database
        cursor.execute("""
            SELECT TABLE_NAME 
            FROM INFORMATION_SCHEMA.TABLES 
            WHERE TABLE_TYPE = 'BASE TABLE'
        """)
        tables = cursor.fetchall()
        logger.info(f"Found tables: {tables}")
        
        resources = []
        for table in tables:
            resources.append(
                Resource(
                    uri=f"mssql://{table[0]}/data",
                    name=f"Table: {table[0]}",
                    mimeType="text/plain",
                    description=f"Data in table: {table[0]}"
                )
            )
        cursor.close()
        conn.close()
        return resources
    except Exception as e:
        logger.error(f"Failed to list resources: {str(e)}")
        return []

@app.read_resource()
async def read_resource(uri: AnyUrl) -> str:
    """Read table contents."""
    config = get_db_config()
    uri_str = str(uri)
    logger.info(f"Reading resource: {uri_str}")
    
    if not uri_str.startswith("mssql://"):
        raise ValueError(f"Invalid URI scheme: {uri_str}")
        
    parts = uri_str[8:].split('/')
    table = parts[0]
    
    try:
        # Validate table name to prevent SQL injection
        safe_table = validate_table_name(table)
        
        conn = pymssql.connect(**config)
        cursor = conn.cursor()
        # Use TOP 100 for MSSQL (equivalent to LIMIT in MySQL)
        cursor.execute(f"SELECT TOP 100 * FROM {safe_table}")
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        result = [",".join(map(str, row)) for row in rows]
        cursor.close()
        conn.close()
        return "\n".join([",".join(columns)] + result)
                
    except Exception as e:
        logger.error(f"Database error reading resource {uri}: {str(e)}")
        raise RuntimeError(f"Database error: {str(e)}")

@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available SQL Server tools."""
    command = get_command()
    logger.info("Listing tools...")
    return [
        Tool(
            name=command,
            description="Execute an SQL query on the SQL Server",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The SQL query to execute"
                    }
                },
                "required": ["query"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute SQL commands."""
    config = get_db_config()
    command = get_command()
    logger.info(f"Calling tool: {name} with arguments: {arguments}")
    
    if name != command:
        raise ValueError(f"Unknown tool: {name}")
    
    query = arguments.get("query")
    if not query:
        raise ValueError("Query is required")
    
    try:
        conn = pymssql.connect(**config)
        cursor = conn.cursor()
        cursor.execute(query)
        
        # Special handling for table listing
        if is_select_query(query) and "INFORMATION_SCHEMA.TABLES" in query.upper():
            tables = cursor.fetchall()
            result = ["Tables_in_" + config["database"]]  # Header
            result.extend([table[0] for table in tables])
            cursor.close()
            conn.close()
            return [TextContent(type="text", text="\n".join(result))]
        
        # Regular SELECT queries
        elif is_select_query(query):
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            result = [",".join(map(str, row)) for row in rows]
            cursor.close()
            conn.close()
            return [TextContent(type="text", text="\n".join([",".join(columns)] + result))]
        
        # Non-SELECT queries
        else:
            conn.commit()
            affected_rows = cursor.rowcount
            cursor.close()
            conn.close()
            return [TextContent(type="text", text=f"Query executed successfully. Rows affected: {affected_rows}")]
                
    except Exception as e:
        logger.error(f"Error executing SQL '{query}': {e}")
        return [TextContent(type="text", text=f"Error executing query: {str(e)}")]

async def main():
    """Main entry point to run the MCP server."""
    logger.info("Starting MSSQL MCP server...")
    config = get_db_config()
    transport = get_transport()
    # Log connection info without exposing sensitive data
    server_info = config['server']
    if 'port' in config:
        server_info += f":{config['port']}"
    user_info = config.get('user', 'Windows Auth')
    logger.info(f"Database config: {server_info}/{config['database']} as {user_info}")
    logger.info(f"Using MCP transport: {transport}")

    if transport == "stdio":
        await run_stdio_server()
    else:
        await run_http_server(transport)


async def run_stdio_server():
    """Run MCP server over stdio transport."""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        try:
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options()
            )
        except Exception as e:
            logger.error(f"Server error: {str(e)}", exc_info=True)
            raise


def create_sse_app() -> Starlette:
    """Create a Starlette app for SSE transport."""
    http_config = get_http_config()
    sse_transport = SseServerTransport(http_config["message_path"])

    async def handle_sse(request: Request) -> Response:
        async with sse_transport.connect_sse(
            request.scope,
            request.receive,
            request._send,  # type: ignore[attr-defined]
        ) as streams:
            await app.run(
                streams[0],
                streams[1],
                app.create_initialization_options(),
            )
        return Response()

    routes = [
        Route(http_config["sse_path"], endpoint=handle_sse, methods=["GET"]),
        Mount(http_config["message_path"], app=sse_transport.handle_post_message),
    ]
    return Starlette(routes=routes)


def create_streamable_http_app() -> Starlette:
    """Create a Starlette app for Streamable HTTP transport."""
    http_config = get_http_config()
    session_manager = StreamableHTTPSessionManager(
        app=app,
        stateless=http_config["stateless_http"],
    )

    class StreamableHTTPASGIApp:
        """Small ASGI adapter for session manager request handling."""

        def __init__(self, manager: StreamableHTTPSessionManager):
            self.manager = manager

        async def __call__(self, scope, receive, send) -> None:
            await self.manager.handle_request(scope, receive, send)

    @asynccontextmanager
    async def lifespan(_: Starlette):
        async with session_manager.run():
            yield

    routes = [
        Route(http_config["mcp_path"], endpoint=StreamableHTTPASGIApp(session_manager)),
    ]
    return Starlette(routes=routes, lifespan=lifespan)


async def run_http_server(transport: Literal["sse", "streamable-http"]):
    """Run MCP server over HTTP transport."""
    import uvicorn

    http_config = get_http_config()
    if transport == "sse":
        starlette_app = create_sse_app()
        logger.info(
            "Starting SSE MCP server at http://%s:%d%s (message endpoint: %s)",
            http_config["host"],
            http_config["port"],
            http_config["sse_path"],
            http_config["message_path"],
        )
    else:
        starlette_app = create_streamable_http_app()
        logger.info(
            "Starting Streamable HTTP MCP server at http://%s:%d%s",
            http_config["host"],
            http_config["port"],
            http_config["mcp_path"],
        )

    uvicorn_config = uvicorn.Config(
        starlette_app,
        host=http_config["host"],
        port=http_config["port"],
        log_level=http_config["log_level"],
    )
    server = uvicorn.Server(uvicorn_config)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
