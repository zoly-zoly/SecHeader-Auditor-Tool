import asyncio
import json
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from secheader.auditor import HeaderAuditor

app = typer.Typer(
    name="secheader",
    help="🛡️ SecHeader-Auditor: Fast, Asynchronous HTTP Security Header, Cookie & CORS Compliance Scanner.",
    add_completion=False,
)
console = Console()


def render_report(result: dict) -> None:
    if "error" in result:
        console.print(
            Panel(
                f"[bold red]Connection Error:[/bold red] {result['error']}",
                title=f"🌐 Target: {result['target']}",
                border_style="red",
            )
        )
        return

    grade = result["grade"]
    grade_color = "green" if grade in ("A+", "A") else "yellow" if grade in ("B", "C") else "red"

    header_summary = (
        f"[bold]Final URL:[/bold] {result['final_url']}  |  "
        f"[bold]Status:[/bold] {result['status_code']}  |  "
        f"[bold]Score:[/bold] {result['score']}/100  |  "
        f"[bold]Grade:[/bold] [{grade_color}]{grade}[/{grade_color}]"
    )
    console.print(Panel(header_summary, title=f"🛡️ Audit Report: {result['target']}", border_style=grade_color))

    # 1. Table for Missing & Present Security Headers
    table = Table(title="HTTP Security Headers", show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Status", width=10)
    table.add_column("Header Name", ratio=2)
    table.add_column("Impact / Weight", width=16)
    table.add_column("Value / Remediation Advice", ratio=4)

    for item in result["present"]:
        table.add_row(
            "[bold green]✔ PASS[/bold green]",
            item["header"],
            f"+{item['weight']} pts",
            f"[dim]{item['value']}[/dim]",
        )

    for item in result["missing"]:
        sev_color = "red" if item["severity"] == "HIGH" else "yellow" if item["severity"] == "MEDIUM" else "blue"
        table.add_row(
            "[bold red]✘ MISS[/bold red]",
            item["header"],
            f"[{sev_color}]{item['severity']} (-{item['weight']})[/{sev_color}]",
            item["remediation"],
        )

    console.print(table)

    # 2. Table for Set-Cookie Security Analysis
    if result.get("cookies"):
        cookie_table = Table(title="🍪 Set-Cookie Security Audit", show_header=True, header_style="bold magenta", expand=True)
        cookie_table.add_column("Cookie Name", ratio=2)
        cookie_table.add_column("Secure", width=10, justify="center")
        cookie_table.add_column("HttpOnly", width=10, justify="center")
        cookie_table.add_column("SameSite", width=12, justify="center")
        cookie_table.add_column("Findings / Remediation", ratio=4)

        for c in result["cookies"]:
            sec_badge = "[bold green]✔ Yes[/bold green]" if c["secure"] else "[bold red]✘ No[/bold red]"
            http_badge = "[bold green]✔ Yes[/bold green]" if c["httponly"] else "[bold red]✘ No[/bold red]"
            ss_val = c["samesite"]
            ss_badge = (
                f"[bold green]{ss_val}[/bold green]"
                if ss_val.lower() in ("strict", "lax")
                else f"[bold yellow]{ss_val}[/bold yellow]"
                if ss_val.lower() == "none"
                else "[bold red]✘ Missing[/bold red]"
            )
            advice = (
                "[dim green]All security flags properly configured.[/dim green]"
                if c["status"] == "SECURE"
                else f"[yellow]{', '.join(c['issues'])}.[/yellow] {c['remediation']}"
            )
            cookie_table.add_row(f"[bold]{c['name']}[/bold]", sec_badge, http_badge, ss_badge, advice)

        console.print(cookie_table)

    if result["disclosed"]:
        disc_text = ", ".join(f"[bold yellow]{k}[/bold yellow]: {v}" for k, v in result["disclosed"].items())
        console.print(f"🕵️  [bold]Information Disclosure headers detected:[/bold] {disc_text}")

    for warn in result["warnings"]:
        console.print(f"⚠️  [bold yellow]Warning:[/bold yellow] {warn}")

    console.print("")


@app.command()
def main(
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Single target URL to audit."),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Path to file containing multiple target URLs."),
    concurrency: int = typer.Option(10, "--concurrency", "-c", help="Number of concurrent async workers."),
    timeout: float = typer.Option(8.0, "--timeout", "-t", help="HTTP request timeout in seconds."),
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Disable SSL/TLS certificate verification."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Export full audit results to JSON file."),
):
    targets: List[str] = []
    if url:
        targets.append(url)
    if file:
        if not file.exists():
            console.print(f"[bold red]Error:[/bold red] File '{file}' not found.")
            raise typer.Exit(code=1)
        targets.extend(file.read_text(encoding="utf-8").splitlines())

    if not targets:
        console.print("[bold yellow]Please specify a target using --url (-u) or --file (-f). Use --help for usage.[/bold yellow]")
        raise typer.Exit(code=1)

    auditor = HeaderAuditor(timeout=timeout, concurrency=concurrency, verify_ssl=not insecure)
    results = asyncio.run(auditor.run_batch(targets))

    for res in results:
        render_report(res)

    if output:
        output.write_text(json.dumps(results, indent=2), encoding="utf-8")
        console.print(f"[bold green]✔ Audit report successfully exported to {output}[/bold green]")


if __name__ == "__main__":
    app()
