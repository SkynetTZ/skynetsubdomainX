from __future__ import annotations

import argparse
import socket
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .sources import DEFAULT_SOURCES, Source

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="skynetsubdomain",
        description="SkyNetSubdomain passive subdomain enumeration engine || Coded with ❤️ by AuxGrep",
    )
    parser.add_argument("domain", help="Target root domain (e.g. example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="HTTP timeout in seconds")
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=8,
        help="Concurrent workers for source enumeration and DNS resolution",
    )
    parser.add_argument(
        "--source-timeout",
        type=int,
        default=12,
        help="Hard timeout per source task in seconds (default: 12)",
    )
    parser.add_argument("--no-resolve", action="store_true", help="Skip DNS resolution checks")
    parser.add_argument("-o", "--output", type=Path, help="Write discovered subdomains to file")
    return parser.parse_args()


def resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def collect_from_sources(
    domain: str,
    timeout: int,
    workers: int,
    sources: list[Source],
    source_timeout: int,
) -> tuple[set[str], dict[str, str]]:
    discovered: set[str] = set()
    source_status: dict[str, str] = {}
    source_workers = max(1, min(workers, len(sources)))
    with ThreadPoolExecutor(max_workers=source_workers) as pool:
        futures = {pool.submit(source.fetch, domain, timeout): source for source in sources}
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Querying passive sources...", total=len(futures))
            pending = set(futures.keys())
            while pending:
                done, pending = wait(pending, timeout=source_timeout, return_when=FIRST_COMPLETED)
                if not done:
                    for stalled in list(pending):
                        source = futures[stalled]
                        source_status[source.name] = f"timeout after {source_timeout}s"
                        stalled.cancel()
                        progress.advance(task)
                    pending.clear()
                    break
                for future in done:
                    source = futures[future]
                    try:
                        names = future.result()
                        discovered.update(names)
                        source_status[source.name] = f"{len(names)} results"
                    except Exception as exc:  # noqa: BLE001
                        source_status[source.name] = f"error: {exc.__class__.__name__}"
                    progress.advance(task)
    for source in sources:
        source_status.setdefault(source.name, "no response")
    return discovered, source_status


def resolve_subdomains(subdomains: list[str], workers: int) -> dict[str, str]:
    resolved: dict[str, str] = {}
    if not subdomains:
        return resolved
    dns_workers = max(1, min(workers, len(subdomains)))
    with ThreadPoolExecutor(max_workers=dns_workers) as pool:
        futures = {pool.submit(resolve_host, host): host for host in subdomains}
        with Progress(
            SpinnerColumn(),
            TextColumn("[green]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Resolving discovered subdomains...", total=len(futures))
            for future in as_completed(futures):
                host = futures[future]
                ip = future.result()
                if ip:
                    resolved[host] = ip
                progress.advance(task)
    return resolved


def print_source_table(source_status: dict[str, str]) -> None:
    table = Table(title="SkyNetSubdomain Sources", header_style="bold magenta")
    table.add_column("Source", style="cyan")
    table.add_column("Status", style="white")
    for source_name, status in sorted(source_status.items()):
        table.add_row(source_name, status)
    console.print(table)


def print_results_table(subdomains: list[str], resolved: dict[str, str], resolve_enabled: bool) -> None:
    table = Table(title="Discovered Subdomains", header_style="bold blue")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Subdomain", style="green")
    if resolve_enabled:
        table.add_column("DNS", style="yellow")

    for idx, host in enumerate(subdomains, start=1):
        if resolve_enabled:
            table.add_row(str(idx), host, resolved.get(host, "unresolved"))
        else:
            table.add_row(str(idx), host)
    console.print(table)


def save_output(subdomains: list[str], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(subdomains) + "\n", encoding="utf-8")
    console.print(f"[bold green]Saved[/bold green] {len(subdomains)} entries to {output_path}")


def main() -> None:
    args = parse_args()
    domain = args.domain.lower().strip().strip(".")

    console.print(
        f"[bold cyan]SkyNetSubdomain[/bold cyan] | Target: [bold white]{domain}[/bold white]\n"
    )
    discovered, source_status = collect_from_sources(
        domain=domain,
        timeout=args.timeout,
        workers=args.workers,
        sources=DEFAULT_SOURCES,
        source_timeout=args.source_timeout,
    )
    subdomains = sorted(discovered)

    if not subdomains:
        print_source_table(source_status)
        console.print("[bold red]No subdomains discovered.[/bold red]")
        return

    resolved: dict[str, str] = {}
    if not args.no_resolve:
        resolved = resolve_subdomains(subdomains, args.workers)

    print_source_table(source_status)
    print_results_table(subdomains, resolved, resolve_enabled=not args.no_resolve)

    console.print(
        f"[bold]Total:[/bold] {len(subdomains)} | "
        f"[bold]Resolved:[/bold] {len(resolved) if not args.no_resolve else 'n/a'}"
    )

    if args.output:
        save_output(subdomains, args.output)


if __name__ == "__main__":
    main()
