import logging
from agent_setup import get_chat_agent

def main():
    logging.basicConfig(level=logging.INFO)
    agent = get_chat_agent()
    print("Agent initialized.")
    prompt = input("Enter a prompt for the agent: ")
    print("Sending prompt to agent...")
    response = agent.run(prompt)
    print("\n=== Agent Raw Response Object ===")
    print(repr(response))
    # Try to extract action_output, tool calls, etc.
    if hasattr(response, 'action_output'):
        print("\n=== action_output ===")
        print(response.action_output)
    if hasattr(response, 'steps'):
        print("\n=== Steps (Tool Calls) ===")
        for i, step in enumerate(response.steps):
            print(f"Step {i+1}:")
            print(step)
    if hasattr(response, 'tool_calls'):
        print("\n=== tool_calls ===")
        print(response.tool_calls)
    print("\n=== Agent Final Output ===")
    print(str(response))

if __name__ == "__main__":
    main()
