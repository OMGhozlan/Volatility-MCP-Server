from fastmcp import FastMCP, Client
import asyncio

mcp = FastMCP("Dynamic Args Server")

@mcp.tool()
def flexible_tool(required_arg: str, kw_args: dict = None) -> dict:
    """A tool that accepts any additional keyword arguments."""
    result = {"required": required_arg, "kw_args": {}}
    if kw_args:
        result["kw_args"].update(kw_args)
    return result

# Test with a client
async def test():
    client = Client(mcp)
    async with client:
        # Call with just the required argument
        result1 = await client.call_tool("flexible_tool", {"required_arg": "hello1"})
        print(f"Res1: {result1}")
        
        # Call with additional arguments
        result2 = await client.call_tool(
            "flexible_tool", 
            {
                "required_arg": "hello2",
                "kw_args": {"optional1": 123, "optional2": "test"}
            }
        )
        print(f"Res2: {result2}")

if __name__ == "__main__":
    asyncio.run(test())