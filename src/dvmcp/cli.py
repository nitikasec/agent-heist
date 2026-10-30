"""Command-line entry point: `dvmcp list | play N | submit N FLAG`."""

import argparse
import asyncio
import json
import sys

import anthropic
from mcp import Client, StdioServerParameters

from dvmcp.agent import Agent
from dvmcp.flags import check_flag, find_flags, load_progress, mark_solved
from dvmcp.levels import LEVELS, get_level

DIM, BOLD, GREEN, RED, YELLOW, RESET = "\033[2m", "\033[1m", "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def cmd_list(_: argparse.Namespace) -> int:
    solved = load_progress()
    for number, level in LEVELS.items():
        mark = f"{GREEN}[solved]{RESET}" if number in solved else "[      ]"
        print(f"{mark} Level {number}: {level.title}")
    return 0


def show_tool_call(name: str, arguments: dict, output: str) -> None:
    preview = output if len(output) <= 300 else output[:300] + "..."
    print(f"{DIM}  -> tool {name}({json.dumps(arguments)})\n     {preview.replace(chr(10), chr(10) + '     ')}{RESET}")


async def play(level_number: int) -> int:
    level = get_level(level_number)
    print(f"{BOLD}Level {level.number}: {level.title}{RESET}\n\n{level.briefing}\n")
    print(f"{DIM}Type your messages to the agent. Commands: /quit, /reset{RESET}\n")

    server = StdioServerParameters(command=sys.executable, args=["-m", level.module_name])
    async with Client(server) as mcp_client:
        agent = Agent(mcp_client, level.system_prompt, on_tool_call=show_tool_call)
        while True:
            try:
                user_message = input(f"{BOLD}you>{RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return 0
            if not user_message:
                continue
            if user_message == "/quit":
                return 0
            if user_message == "/reset":
                agent.messages.clear()
                print(f"{DIM}Conversation reset.{RESET}")
                continue

            try:
                reply = await agent.send(user_message)
            except anthropic.AuthenticationError:
                print(f"{RED}Authentication failed. Check your ANTHROPIC_API_KEY and try again.{RESET}")
                return 1
            except TypeError as exc:
                # Raised by the SDK when no credentials are configured at all.
                if "authentication" not in str(exc):
                    raise
                print(f"{RED}No Claude API credentials found. Export ANTHROPIC_API_KEY and try again.{RESET}")
                return 1
            except anthropic.APIConnectionError:
                print(f"{RED}Could not reach the Claude API. Check your connection.{RESET}")
                continue
            except anthropic.APIStatusError as exc:
                print(f"{RED}API error {exc.status_code}: {exc.message}{RESET}")
                continue

            print(f"{BOLD}agent>{RESET} {reply}\n")
            if find_flags(reply):
                print(f"{YELLOW}Looks like a flag! Submit it with: dvmcp submit {level.number} <flag>{RESET}\n")


def cmd_play(args: argparse.Namespace) -> int:
    return asyncio.run(play(args.level))


def cmd_submit(args: argparse.Namespace) -> int:
    get_level(args.level)
    if check_flag(args.level, args.flag):
        mark_solved(args.level)
        print(f"{GREEN}Correct! Level {args.level} solved.{RESET}")
        return 0
    print(f"{RED}Wrong flag for level {args.level}. Keep trying.{RESET}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="dvmcp", description="Damn Vulnerable MCP - a hackable AI agent lab")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list levels and progress").set_defaults(func=cmd_list)
    play_parser = sub.add_parser("play", help="chat with a level's agent")
    play_parser.add_argument("level", type=int)
    play_parser.set_defaults(func=cmd_play)
    submit_parser = sub.add_parser("submit", help="check a flag")
    submit_parser.add_argument("level", type=int)
    submit_parser.add_argument("flag")
    submit_parser.set_defaults(func=cmd_submit)

    args = parser.parse_args()
    try:
        return args.func(args)
    except KeyError as exc:
        print(f"{RED}{exc.args[0]}{RESET}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
