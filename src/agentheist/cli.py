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
from agentheist import benchmarks, owasp, provenance
from agentheist.flags import check_flag, find_flags, load_progress, mark_solved
from agentheist.hints import hint
from agentheist.levels import LEVELS, Level, get_level
from agentheist.trace import (
    BROKEN, ENFORCED, ENFORCED_PROVEN, MODEL_DECLINED, Trace, classify_defence,
)
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
    mod = level.module
    site = AttackerSite.for_level(mod.SITE_DIR)
    site.ensure()
    artifact = mod.ensure_artifact()
    needs_url = "{url}" in mod.VICTIM_REQUEST
    edit_hint = getattr(mod, "EDIT_HINT", "Edit your attack")
    run_hint = getattr(mod, "RUN_HINT", "press Enter to run")

    print(f"{BOLD}Level {level.number}: {level.title}{RESET}\n")
    print(level.briefing.format(artifact=artifact, site_log=site.log) + "\n")
    print(f"{DIM}{edit_hint}: {artifact}\nThen {run_hint}. Commands: /quit{RESET}\n")

    while True:
        try:
            command = input(f"{BOLD}run>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if command == "/quit":
            return 0

        offset = site.log.stat().st_size
        request = mod.VICTIM_REQUEST.format(url=f"http://{ATTACKER_HOST}/") if needs_url else mod.VICTIM_REQUEST
        print(f"{DIM}The victim's assistant runs a normal task...{RESET}")
        # A fresh server and conversation per attempt: the victim starts a new chat each time.
        async with Client(level_server(level)) as mcp_client:
            agent = Agent(mcp_client, level.system_prompt, on_tool_call=show_victim_tool_call)
            reply = await send_or_report(agent, request)
        if reply is AUTH_FAILED:
            return 1
        if reply is None:
            continue
        print(f"{DIM}The assistant replied to the victim ({len(reply)} characters). You can't see their screen.{RESET}")

        lines = read_new_log_lines(site, offset)
        print(f"\n{BOLD}New requests in your attacker log:{RESET}")
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


def _print_level_report(number: int) -> None:
    level = get_level(number)
    mapping = owasp.for_level(number)
    print(f"{BOLD}Level {number}: {level.title}{RESET}")
    if benchmarks.TASK_SUMMARIES.get(number):
        print(f"  {DIM}Attack:{RESET} {benchmarks.TASK_SUMMARIES[number]}")
    print(f"  {BOLD}Mapped to:{RESET}")
    for c in mapping.categories:
        print(f"    - {c.framework}: {c.label}\n      {DIM}{c.url}{RESET}")
    print(f"  {BOLD}Root-cause weakness:{RESET} {mapping.weakness}")
    print(f"  {GREEN}Control (secure reference):{RESET} {mapping.control}\n")


def cmd_report(args: argparse.Namespace) -> int:
    numbers = sorted(owasp.MAPPINGS) if args.level == "all" else [int(args.level)]
    for n in numbers:
        get_level(n)  # validate
        if n not in owasp.MAPPINGS:
            print(f"{RED}No standards mapping for level {n}.{RESET}")
            return 1
    print(f"{BOLD}Agent Heist — level security reports{RESET}  "
          f"{DIM}(OWASP LLM Top 10, Agentic Security Initiative, MCP spec){RESET}\n")
    for n in numbers:
        _print_level_report(n)
    if args.report:
        body = "\n".join(owasp.level_markdown(n) for n in numbers)
        with open(args.report, "w") as fh:
            fh.write("# Agent Heist — level security reports\n\n" + body + "\n")
        print(f"{DIM}Saved level report(s) to {args.report}{RESET}")
    return 0


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


def _tally(results, runs):
    """Reduce N runs to (classification, plain detail) with no color codes."""
    leaked = sum(r.solved for r in results)
    errors = [r.error for r in results if r.error]
    if leaked:
        return "leaked", f"{leaked}/{runs} ({round(100 * leaked / runs)}% success)"
    if len(errors) == runs:
        return "error", errors[0]
    clean = runs - len(errors)
    return "held", f"{clean}/{runs}" + (f" ({len(errors)} model errors)" if errors else "")


def _bench_rows(levels, models, runs, compare):
    """Run the board and yield (level, title, model, variant, klass, detail) rows."""
    for n in levels:
        title = get_level(n).title
        variants = [("attack", False)] + ([("secure", True)] if compare else [])
        for model in models:
            for label, secure in variants:
                results = [asyncio.run(benchmarks.run_one(n, model, secure=secure)) for _ in range(runs)]
                klass, detail = _tally(results, runs)
                yield n, title, model, label, klass, detail


def cmd_bench(args: argparse.Namespace) -> int:
    levels = sorted(benchmarks.RUNNERS) if args.level == "all" else [int(args.level)]
    for n in levels:
        get_level(n)  # validate
    models = benchmarks.models_from_arg(args.models)
    rows = list(_bench_rows(levels, models, args.runs, args.compare))

    print(f"{BOLD}Model scoreboard{RESET}  {DIM}(attacker fixed; does the model leak the flag?){RESET}\n")
    colors = {"leaked": RED, "held": GREEN, "error": YELLOW}
    words = {"leaked": "LEAKED", "held": "safe  ", "error": "error "}
    last = None
    for n, title, model, variant, klass, detail in rows:
        if n != last:
            print(f"{BOLD}Level {n}: {title}{RESET}")
            last = n
        tag = "" if not args.compare else f"{DIM}[{'vulnerable' if variant == 'attack' else 'fixed server'}]{RESET} "
        note = detail if args.runs > 1 or klass == "error" else ("flag captured" if klass == "leaked" else "no flag")
        print(f"  {colors[klass]}{words[klass]}{RESET}  {tag}{model:<26} {DIM}{note}{RESET}")
    print()

    verdicts = []
    if args.compare:
        print(f"{DIM}A good fix flips every LEAKED to safe on the fixed server, whatever the model does.{RESET}\n")
        print(f"{BOLD}Defence verdict{RESET}  {DIM}(why the fixed server held: a control that fired, or just the model declining?){RESET}")
        for n in levels:
            if n not in benchmarks.SECURE_MODULES:
                continue
            for model in models:
                verdict, error = _defence_verdict(n, model)
                if error:
                    print(f"  {YELLOW}?{RESET}  Level {n} {model:<26} {DIM}could not run: {error}{RESET}")
                    continue
                verdicts.append((n, model, verdict))
                color = VERDICT_COLORS.get(verdict.kind, YELLOW)
                print(f"  {color}{verdict.headline}{RESET}  Level {n} {model}\n"
                      f"       {DIM}{verdict.detail}{RESET}")
        print()
    if args.report:
        prov = provenance.collect(
            models, args.runs, levels,
            provenance.reproduce_command(args.level, args.models, args.runs, args.compare),
        )
        _write_report(args.report, rows, args.runs, verdicts, prov)
        print(f"{DIM}Saved reproducible report to {args.report}{RESET}")
    return 0


def _run_trace(level_number: int, model: str, secure: bool) -> Trace:
    level = get_level(level_number)
    target = "fixed server" if secure else "vulnerable"
    trace = Trace(level_number, level.title, model, target,
                  task=benchmarks.TASK_SUMMARIES.get(level_number, ""))
    result = asyncio.run(benchmarks.run_one(level_number, model, secure=secure, record=trace.record_tool))
    if result.error:
        raise RuntimeError(result.error)
    trace.finish(result.solved)
    return trace


VERDICT_COLORS = {ENFORCED_PROVEN: GREEN, ENFORCED: GREEN, MODEL_DECLINED: YELLOW, BROKEN: RED}


def _defence_verdict(level_number: int, model: str):
    """Run the attack once against both servers (traced) and classify why the fix held.

    Returns (DefenceVerdict, None) or (None, error-message)."""
    title = get_level(level_number).title
    task = benchmarks.TASK_SUMMARIES.get(level_number, "")
    vuln = Trace(level_number, title, model, "vulnerable", task=task)
    v = asyncio.run(benchmarks.run_one(level_number, model, secure=False, record=vuln.record_tool))
    if v.error:
        return None, v.error
    vuln.finish(v.solved)
    fixed = Trace(level_number, title, model, "fixed server", task=task)
    f = asyncio.run(benchmarks.run_one(level_number, model, secure=True, record=fixed.record_tool))
    if f.error:
        return None, f.error
    fixed.finish(f.solved)
    return classify_defence(fixed, vuln), None


def cmd_trace(args: argparse.Namespace) -> int:
    get_level(int(args.level))  # validate
    model = benchmarks.models_from_arg(args.models)[0]
    print(f"{BOLD}Attack forensics{RESET}  {DIM}(how the flag escapes, step by step){RESET}\n")
    try:
        trace = _run_trace(int(args.level), model, args.secure)
    except RuntimeError as exc:
        print(f"{RED}Could not run the attack: {exc}{RESET}")
        return 1
    print(trace.render())
    print()
    if args.secure:
        # On the fixed server, say *why* it held: a control that fired, or just the model declining.
        verdict = classify_defence(trace)
        color = VERDICT_COLORS.get(verdict.kind, YELLOW)
        print(f"  {color}Defence: {verdict.headline}{RESET} {DIM}— {verdict.detail}{RESET}\n")
    if args.report:
        with open(args.report, "w") as fh:
            fh.write(trace.to_markdown() + "\n")
        print(f"{DIM}Saved trace to {args.report}{RESET}")
    return 0


def _write_report(path: str, rows, runs: int, verdicts=None, prov=None) -> None:
    lines = ["# Agent Heist — model scoreboard",
             "",
             f"Attacker is fixed; each cell is {runs} run(s). `leaked k/N` = flag captured k of N times.",
             ""]
    if prov is not None:
        lines += prov.to_markdown() + [""]
    lines += ["## Results",
              "",
              "| Level | Model | Target | Result | Detail |",
              "|---|---|---|---|---|"]
    for n, title, model, variant, klass, detail in rows:
        target = "vulnerable" if variant == "attack" else "fixed server"
        lines.append(f"| {n} {title} | `{model}` | {target} | {klass} | {detail} |")
    if verdicts:
        lines += ["",
                  "## Defence verdict",
                  "",
                  "Why the fixed server held: a server-side control that fires in code (holds for every "
                  "model), or merely the model declining (a weaker model may still comply).",
                  "",
                  "| Level | Model | Verdict | Why |",
                  "|---|---|---|---|"]
        for n, model, verdict in verdicts:
            why = verdict.detail.replace("|", "\\|")
            lines.append(f"| {n} {get_level(n).title} | `{model}` | {verdict.headline} | {why} |")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


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
    bench_parser = sub.add_parser("bench", help="run a level's attack against one or more models")
    bench_parser.add_argument("level", help='level number, or "all"')
    bench_parser.add_argument("--models", help="comma-separated model ids (default: current model)")
    bench_parser.add_argument("--runs", type=int, default=1, help="repeat each attack N times (default 1)")
    bench_parser.add_argument("--compare", action="store_true", help="also run the attack against the fixed server")
    bench_parser.add_argument("--report", metavar="FILE", help="write a reproducible markdown report")
    bench_parser.set_defaults(func=cmd_bench)
    trace_parser = sub.add_parser("trace", help="show a step-by-step forensic trace of a level's attack")
    trace_parser.add_argument("level", help="level number")
    trace_parser.add_argument("--models", help="model id to run the attack with (default: current model)")
    trace_parser.add_argument("--secure", action="store_true", help="trace the fixed server to see where a control fires")
    trace_parser.add_argument("--report", metavar="FILE", help="write the trace as markdown")
    trace_parser.set_defaults(func=cmd_trace)
    report_parser = sub.add_parser("report", help="per-level security report mapped to OWASP/MCP standards (offline)")
    report_parser.add_argument("level", help='level number, or "all"')
    report_parser.add_argument("--report", metavar="FILE", help="write the report(s) as markdown")
    report_parser.set_defaults(func=cmd_report)

    args = parser.parse_args()
    try:
        return args.func(args)
    except KeyError as exc:
        print(f"{RED}{exc.args[0]}{RESET}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
