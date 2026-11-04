"""Command-line entry point: `agentheist list | play N | submit N FLAG`."""

import argparse
import asyncio
import json
import os
import sys
from urllib.parse import unquote_plus, urlsplit

import anthropic
from mcp import Client, StdioServerParameters
from mcp.client.stdio import get_default_environment

from agentheist.agent import Agent
from agentheist.backends import BackendError
from agentheist.flags import check_flag, find_flags, load_progress, mark_solved
from agentheist.hints import hint
from agentheist.levels import LEVELS, Level, get_level
from agentheist.web import ATTACKER_HOST, AttackerSite

DIM, BOLD, GREEN, RED, YELLOW, RESET = "\033[2m", "\033[1m", "\033[32m", "\033[31m", "\033[33m", "\033[0m"
TOOL_PREVIEW_CHARS = 1200


def cmd_list(_: argparse.Namespace) -> int:
    solved = load_progress()
    for number, level in LEVELS.items():
        mark = f"{GREEN}[solved]{RESET}" if number in solved else "[      ]"
        print(f"{mark} Level {number}: {level.title}")
    return 0


def show_tool_call(name: str, arguments: dict, output: str) -> None:
    # Long enough to show a full bearer token or ticket body, short enough to keep the chat readable.
    preview = output if len(output) <= TOOL_PREVIEW_CHARS else output[:TOOL_PREVIEW_CHARS] + "..."
    print(f"{DIM}  -> tool {name}({json.dumps(arguments)})\n     {preview.replace(chr(10), chr(10) + '     ')}{RESET}")


AUTH_FAILED = object()


async def send_or_report(agent: Agent, message: str) -> str | object | None:
    """Send a message; on API problems print why and return None, or AUTH_FAILED if there's no way on."""
    try:
        return await agent.send(message)
    except anthropic.AuthenticationError:
        print(f"{RED}Authentication failed. Check your ANTHROPIC_API_KEY and try again.{RESET}")
        return AUTH_FAILED
    except TypeError as exc:
        # Raised by the SDK when no credentials are configured at all.
        if "authentication" not in str(exc):
            raise
        print(f"{RED}No Claude API credentials found. Export ANTHROPIC_API_KEY and try again.{RESET}")
        return AUTH_FAILED
    except anthropic.APIConnectionError:
        print(f"{RED}Could not reach the Claude API. Check your connection.{RESET}")
        return None
    except anthropic.APIStatusError as exc:
        print(f"{RED}API error {exc.status_code}: {exc.message}{RESET}")
        return None
    except BackendError as exc:
        print(f"{RED}{exc}{RESET}")
        return None


def level_server(level: Level) -> StdioServerParameters:
    # Pass AGENTHEIST_HOME through so the level's server and the CLI agree on where files live.
    env = get_default_environment()
    if "AGENTHEIST_HOME" in os.environ:
        env["AGENTHEIST_HOME"] = os.environ["AGENTHEIST_HOME"]
    return StdioServerParameters(command=sys.executable, args=["-m", level.module_name], env=env)


def show_victim_tool_call(name: str, arguments: dict, _output: str) -> None:
    # The attacker can't see inside the victim's session, so show only which tool ran and,
    # for fetches, which host was contacted. Arguments and outputs stay hidden.
    detail = ""
    if name == "fetch_url":
        detail = f" (host: {urlsplit(str(arguments.get('url', ''))).hostname})"
    print(f"{DIM}  -> Remy called {name}{detail}{RESET}")


def read_new_log_lines(site: AttackerSite, offset: int) -> list[str]:
    with site.log.open() as log:
        log.seek(offset)
        return [unquote_plus(line.rstrip("\n")) for line in log if line.strip()]


async def play_victim(level: Level) -> int:
    site = AttackerSite.for_level(level.module.SITE_DIR)
    site.ensure()
    default_url = f"http://{ATTACKER_HOST}/"
    print(f"{BOLD}Level {level.number}: {level.title}{RESET}\n")
    print(level.briefing.format(site_root=site.root, site_log=site.log) + "\n")
    print(
        f"{DIM}Edit your site, then press Enter to email Dana the link {default_url}\n"
        f"(or type another URL). Commands: /quit{RESET}\n"
    )

    while True:
        try:
            url = input(f"{BOLD}link>{RESET} ").strip() or default_url
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if url == "/quit":
            return 0

        offset = site.log.stat().st_size
        print(f"{DIM}Dana asks Remy to review {url} ...{RESET}")
        # A fresh server and conversation per attempt: Dana starts a new chat each time.
        async with Client(level_server(level)) as mcp_client:
            agent = Agent(mcp_client, level.system_prompt, on_tool_call=show_victim_tool_call)
            reply = await send_or_report(agent, level.module.VICTIM_REQUEST.format(url=url))
        if reply is AUTH_FAILED:
            return 1
        if reply is None:
            continue
        print(f"{DIM}Remy replied to Dana ({len(reply)} characters). You can't see Dana's screen.{RESET}")

        lines = read_new_log_lines(site, offset)
        print(f"\n{BOLD}New requests in your access log:{RESET}")
        print("\n".join(f"  {line}" for line in lines) if lines else f"  {DIM}(none){RESET}")
        print()
        if any(find_flags(line) for line in lines):
            print(f"{YELLOW}Looks like a flag! Submit it with: agentheist submit {level.number} <flag>{RESET}\n")


async def play(level_number: int) -> int:
    level = get_level(level_number)
    if level.mode == "victim":
        return await play_victim(level)
    print(f"{BOLD}Level {level.number}: {level.title}{RESET}\n\n{level.briefing}\n")
    print(f"{DIM}Type your messages to the agent. Commands: /quit, /reset{RESET}\n")

    async with Client(level_server(level)) as mcp_client:
        seen_outputs: list[str] = []

        def on_tool_call(name: str, arguments: dict, output: str) -> None:
            seen_outputs.append(output)
            show_tool_call(name, arguments, output)

        agent = Agent(mcp_client, level.system_prompt, on_tool_call=on_tool_call)
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

            seen_outputs.clear()
            reply = await send_or_report(agent, user_message)
            if reply is AUTH_FAILED:
                return 1
            if reply is None:
                continue

            print(f"{BOLD}agent>{RESET} {reply}\n")
            # The flag may show up only in a tool result the player can see, not in the agent's words.
            if find_flags(reply) or any(find_flags(output) for output in seen_outputs):
                print(f"{YELLOW}Looks like a flag! Submit it with: agentheist submit {level.number} <flag>{RESET}\n")


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


def cmd_hint(args: argparse.Namespace) -> int:
    get_level(args.level)
    print(f"{YELLOW}Hint {args.tier}/3 for level {args.level}:{RESET} {hint(args.level, args.tier)}")
    if args.tier < 3:
        print(f"{DIM}Still stuck? agentheist hint {args.level} {args.tier + 1}{RESET}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="agentheist", description="Agent Heist - a hackable AI agent lab")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list levels and progress").set_defaults(func=cmd_list)
    play_parser = sub.add_parser("play", help="chat with a level's agent")
    play_parser.add_argument("level", type=int)
    play_parser.set_defaults(func=cmd_play)
    submit_parser = sub.add_parser("submit", help="check a flag")
    submit_parser.add_argument("level", type=int)
    submit_parser.add_argument("flag")
    submit_parser.set_defaults(func=cmd_submit)
    hint_parser = sub.add_parser("hint", help="get a hint (tier 1 = nudge, 3 = nearly the answer)")
    hint_parser.add_argument("level", type=int)
    hint_parser.add_argument("tier", type=int, nargs="?", default=1)
    hint_parser.set_defaults(func=cmd_hint)

    args = parser.parse_args()
    try:
        return args.func(args)
    except KeyError as exc:
        print(f"{RED}{exc.args[0]}{RESET}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
