from smolagents import ToolCallingAgent, LiteLLMModel, Tool, ToolCollection
from smolagents import PromptTemplates, ManagedAgentPromptTemplate, FinalAnswerPromptTemplate
from rich_logger import RichLogger
from typing import Union, Dict, Any, List, Optional
import os
from dotenv import load_dotenv
import traceback

# Load environment variables
load_dotenv()
GEMINI_MODEL_ID = os.getenv("GEMINI_MODEL_ID")
OLLAMA_MODEL_ID = os.getenv("OLLAMA_MODEL_ID", "ollama/qwen2.5:7b") # Default model, prefixed with 'ollama/' for LiteLLM compatibility
OLLAMA_API_BASE = os.getenv("OLLAMA_API_BASE", "http://localhost:11434") # Default Ollama URL

# Initialize logger
logger_agent = RichLogger.get_logger(__name__)


logger_agent.info("RAG tool created successfully")

def get_chat_agent():
    """Initializes and returns the SmolAgents ToolCallingAgent with all available tools."""
    logger_agent.info("Initializing SmolAgents ToolCallingAgent...")
    try:
        system_prompt = """
        You are SmolGemMCPAgent, a powerful agentic AI assistant specializing in cybersecurity. You operate in a collaborative environment, helping users with coding tasks, malware analysis, threat intelligence, digital forensics, and security operations.

        Your responsibilities and behavior guidelines:
        - You are a senior cybersecurity analyst AI assistant, highly skilled in both offensive (red team) and defensive (blue team) techniques.
        - If the user asks about your identity, respond: 'I am a senior cybersecurity analyst AI assistant, here to help with malware analysis, threat intelligence, digital forensics, and security operations.'
        - Provide expert analysis on malware, threat intelligence, digital forensics, incident response, and security operations.
        - Clearly outline your actions and reasoning step-by-step, especially when using tools or analyzing technical/cybersecurity content.
        - Use tools ONLY when the user asks for an explanation, or when the text is complex, technical, or cybersecurity-related.
        - When a tool provides a formatted markdown report, ALWAYS display the tool's output verbatim at the TOP of your response.
        - NEVER use tools for greetings, obvious language, or simple conversational input.
        - If you are unsure whether to use a tool, ask a clarifying question first.

        Tool use and code editing rules:
        - If you state that you will use a tool, immediately call that tool as your next action.
        - Always follow the exact schema and requirements for tool calls.
        - Before calling each tool, briefly explain why you are calling it.
        - When making code changes, NEVER output code to the user unless requested.
        - Ensure all generated code is immediately runnable.
        - When editing code, always combine all changes into a single edit call per file.
        - After making code changes, provide a BRIEF summary of what was changed and why.
        """

        prompt_templates = PromptTemplates(
            system_prompt=system_prompt,
            managed_agent=ManagedAgentPromptTemplate(
                task="{task}",
                report="{report}"
            ),
            final_answer=FinalAnswerPromptTemplate(
                pre_messages="{action_output}\n\n",
                post_messages="{llm_output}"
            )
        )
        
        # Initialize Gemini model
        logger_agent.info("Initializing Gemini model")
        gemini_model = LiteLLMModel(
            model_id=OLLAMA_MODEL_ID,
            api_base=OLLAMA_API_BASE,
            system_prompt=system_prompt,
            encoding="utf-8",
            temperature=0.7,
            max_tokens=8192,
        )
        # gemini_model = LiteLLMModel(
        #     model_id=GEMINI_MODEL_ID,
        #     api_key=os.getenv("GOOGLE_API_KEY"),
        #     system_prompt=system_prompt,
        #     encoding="utf-8",
        #     temperature=0.7,
        #     max_tokens=2048,
        # )
        logger_agent.info(f"Gemini model initialized with model_id: {os.getenv('GEMINI_MODEL_ID')}")

        # Initialize MCP server parameters
        server_parameters = {
            "url": "http://127.0.0.1:8000/sse"
        }
        logger_agent.info(f"Initializing MCP with parameters: {server_parameters}")

        # Get tools from MCP
        with ToolCollection.from_mcp(server_parameters) as tool_collection:
            logger_agent.info(f"Retrieved {len(tool_collection.tools)} tools from MCP")
            
            # Combine MCP tools with our RAG tool
            all_tools = [*tool_collection.tools]
            logger_agent.info(f"Combined {len(all_tools)} tools for agent")
            
            agent = ToolCallingAgent(
                model=gemini_model,
                max_steps=7,
                prompt_templates=prompt_templates,
                tools=all_tools,
            )
            
            logger_agent.info("SmolAgents ToolCallingAgent initialized successfully.")
            return agent

    except Exception as e:
        logger_agent.error(f"Failed to initialize LLM agent: {str(e)}")
        logger_agent.error(f"Stack trace: {traceback.format_exc()}")