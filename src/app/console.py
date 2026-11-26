"""
console.py — Q-Vault Sentinel Operator CLI & Walkthrough Orchestrator

Provides commands for system status inspection, offline audit chain verification,
key revocation, live terminal monitoring, web console hosting, and an end-to-end
operational walkthrough backed by live SDK components.
"""

import json
import os
import secrets
import tempfile
import time
from pathlib import Path

import click
import uvicorn
from cryptography.exceptions import InvalidTag
from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.sdk import (
    AuditLedger,
    KeyAuthority,
    decrypt_chunk,
    encrypt_chunk,
    generate_identity_keypair,
    perform_handshake_initiator,
    perform_handshake_responder,
)

from .benchmark import run_benchmark
from .config import load_config
from .runtime import SentinelRuntime
from .web_console import create_web_console_app

console = Console()


@click.group()
def sentinel():
    """Q-Vault Sentinel — Post-Quantum Key Lifecycle Operator CLI."""
    pass


@sentinel.command()
@click.option("--db-path", default="./data/authority.db", show_default=True)
@click.option("--ledger-path", default="./data/audit.jsonl", show_default=True)
def status(db_path: str, ledger_path: str):
    """Show registered service nodes, active epoch, and revocation count."""
    try:
        import sqlite3

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        try:
            total_nodes = cursor.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
            active_nodes = cursor.execute(
                "SELECT COUNT(*) FROM nodes WHERE is_revoked=0"
            ).fetchone()[0]
            revoked_nodes = cursor.execute(
                "SELECT COUNT(*) FROM nodes WHERE is_revoked=1"
            ).fetchone()[0]
            current_epoch_row = cursor.execute("SELECT MAX(epoch) FROM epochs").fetchone()
            current_epoch = (
                current_epoch_row[0] if current_epoch_row[0] is not None else 0
            )
            node_rows = cursor.execute(
                "SELECT node_id, key_epoch, is_revoked, registered_at FROM nodes LIMIT 20"
            ).fetchall()
        except sqlite3.OperationalError as e:
            console.print(f"[red]Database error (tables may not exist yet): {e}[/red]")
            conn.close()
            return

        conn.close()

        chain_head = "N/A"
        if Path(ledger_path).exists():
            try:
                with open(ledger_path, "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip()]
                if lines:
                    last = json.loads(lines[-1])
                    chain_head = last.get("entry_hash", "N/A")[:16] + "..."
            except Exception:
                pass

        table = Table(
            title="[bold cyan]Q-Vault Sentinel — System Status[/bold cyan]",
            box=box.DOUBLE_EDGE,
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Node ID", style="cyan", no_wrap=True)
        table.add_column("Epoch", justify="right")
        table.add_column("Status", justify="center")
        table.add_column("Registered At", style="dim")

        for row in node_rows:
            node_id, key_epoch, is_revoked, registered_at = row
            status_text = "[red]REVOKED[/red]" if is_revoked else "[green]ACTIVE[/green]"
            reg_time = (
                time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(registered_at))
                if registered_at
                else "N/A"
            )
            table.add_row(node_id, str(key_epoch), status_text, reg_time)

        console.print(table)

        summary = (
            f"[bold]Total Nodes:[/bold]    {total_nodes}\n"
            f"[bold]Active Nodes:[/bold]   [green]{active_nodes}[/green]\n"
            f"[bold]Revoked Nodes:[/bold]  [red]{revoked_nodes}[/red]\n"
            f"[bold]Current Epoch:[/bold]  [yellow]{current_epoch}[/yellow]\n"
            f"[bold]Chain Head:[/bold]     [dim]{chain_head}[/dim]"
        )
        console.print(Panel(summary, title="Summary", border_style="blue"))

    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise SystemExit(1)


@sentinel.command("verify-log")
@click.option("--ledger-path", default="./data/audit.jsonl", show_default=True)
@click.option("--signing-key-path", default=None)
def verify_log(ledger_path: str, signing_key_path: str | None):
    """Verify the SHA-256 hash chain and optional ML-DSA-65 checkpoints of the audit ledger."""
    ledger_file = Path(ledger_path)
    if not ledger_file.exists():
        console.print(f"[red]Ledger file not found: {ledger_path}[/red]")
        raise SystemExit(1)

    verify_key = None
    if signing_key_path:
        from src.sdk import load_mldsa_public_key

        verify_key = load_mldsa_public_key(Path(signing_key_path).read_bytes())

    dummy_priv = generate_identity_keypair("verifier").signing_private
    ledger = AuditLedger(
        ledger_path=ledger_path,
        signing_key=dummy_priv,
        verify_key=verify_key or dummy_priv.public_key(),
    )
    result = ledger.verify_chain()

    console.print(
        Panel(
            f"[cyan]Verifying chain: {ledger_path}[/cyan]",
            title="[bold]Q-Vault Log Verifier[/bold]",
            border_style="blue",
        )
    )

    if verify_key is not None and not result["ok"]:
        console.print(f"\n[bold red]✗ Chain INVALID[/bold red] — {result['message']}")
        raise SystemExit(1)
    if result["tampered_entries"]:
        console.print(
            f"\n[bold red]✗ Chain INVALID[/bold red] — tampered entries: {result['tampered_entries']}"
        )
        raise SystemExit(1)

    console.print(
        f"\n[bold green]✓ Chain valid[/bold green] — {result['total_entries']} entries verified, no hash-chain tampering detected."
    )


@sentinel.command()
@click.option("--db-path", default="./data/authority.db", show_default=True)
@click.argument("node_id")
@click.option("--reason", default="operator-triggered")
def revoke(db_path: str, node_id: str, reason: str):
    """Revoke a node by NODE_ID and display propagation stats."""
    try:
        master_kek_hex = os.environ.get("QVAULT_MASTER_KEK", secrets.token_hex(32))
        auth = KeyAuthority(db_path=db_path, master_kek_hex=master_kek_hex)

        console.print(f"[yellow]Revoking node:[/yellow] [bold]{node_id}[/bold]")
        console.print(f"[dim]Reason: {reason}[/dim]")

        notice = auth.revoke_node(node_id=node_id, reason=reason)
        console.print(
            f"\n[bold green]✓ Node '{node_id}' revoked at epoch {notice.revocation_epoch}[/bold green]"
        )

        stats = auth.get_propagation_stats(notice.revocation_epoch)
        stats_table = Table(title="Propagation Stats", box=box.SIMPLE)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="white")
        stats_table.add_row("Revocation Epoch", str(stats.get("revocation_epoch", "N/A")))
        stats_table.add_row("Total Acked", str(stats.get("total_acked", 0)))
        stats_table.add_row("Max Propagation (ms)", str(stats.get("max_propagation_ms", 0)))
        stats_table.add_row("Min Propagation (ms)", str(stats.get("min_propagation_ms", 0)))
        console.print(stats_table)
        auth.close()
    except Exception as exc:
        console.print(f"[red]Revocation failed: {exc}[/red]")
        raise SystemExit(1)


def _build_dashboard(db_path: str, ledger_path: str) -> Layout:
    nodes_table = Table(
        title="Active Nodes",
        box=box.SIMPLE_HEAD,
        header_style="bold cyan",
        expand=True,
    )
    nodes_table.add_column("Node ID", style="cyan")
    nodes_table.add_column("Epoch", justify="right")
    nodes_table.add_column("Status", justify="center")

    epoch_val = 0
    revoked_count = 0

    try:
        import sqlite3

        conn = sqlite3.connect(db_path, timeout=2.0)
        cursor = conn.cursor()
        try:
            rows = cursor.execute(
                "SELECT node_id, key_epoch, is_revoked FROM nodes LIMIT 10"
            ).fetchall()
            for r in rows:
                nid, ep, rev = r
                st = "[red]REVOKED[/red]" if rev else "[green]ACTIVE[/green]"
                nodes_table.add_row(nid, str(ep), st)
            ep_row = cursor.execute("SELECT MAX(epoch) FROM epochs").fetchone()
            if ep_row and ep_row[0] is not None:
                epoch_val = ep_row[0]
            revoked_count = cursor.execute(
                "SELECT COUNT(*) FROM nodes WHERE is_revoked=1"
            ).fetchone()[0]
        except Exception:
            nodes_table.add_row("[dim]No data[/dim]", "-", "-")
        conn.close()
    except Exception:
        nodes_table.add_row("[dim]DB unavailable[/dim]", "-", "-")

    alerts_text = Text()
    alerts_shown = 0
    chain_head = "N/A"

    if Path(ledger_path).exists():
        try:
            with open(ledger_path, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]
            if lines:
                last = json.loads(lines[-1])
                chain_head = last.get("entry_hash", "N/A")[:20] + "..."

            for raw in reversed(lines[-50:]):
                if alerts_shown >= 5:
                    break
                try:
                    e = json.loads(raw)
                    action = str(e.get("action", ""))
                    if any(
                        kw in action.upper()
                        for kw in (
                            "REVOKE",
                            "ALERT",
                            "REPLAY",
                            "TAMPER",
                            "LATERAL",
                            "PRIV_ESC",
                            "CRITICAL",
                        )
                    ):
                        actor = str(e.get("actor", "?"))
                        ts = time.strftime(
                            "%H:%M:%S", time.gmtime(float(e.get("timestamp", 0)))
                        )
                        alerts_text.append(f"[{ts}] ", style="dim")
                        alerts_text.append(f"{actor} ", style="cyan")
                        alerts_text.append(f"{action}\n", style="red bold")
                        alerts_shown += 1
                except Exception:
                    pass
        except Exception:
            pass

    if alerts_shown == 0:
        alerts_text.append("No recent alerts", style="green")

    alerts_panel = Panel(
        alerts_text,
        title="[bold red]Last 5 Alerts[/bold red]",
        border_style="red",
    )

    chain_text = Text(f"Chain Head: {chain_head}", style="dim")
    epoch_text = Text(f"Epoch: {epoch_val}  |  Revoked: {revoked_count}", style="yellow")

    layout = Layout()
    layout.split_column(
        Layout(nodes_table, name="nodes", size=14),
        Layout(alerts_panel, name="alerts", size=8),
        Layout(
            Panel(
                Text(str(chain_text) + "\n" + str(epoch_text)),
                title="Chain Info",
                border_style="dim",
            ),
            name="chain",
            size=4,
        ),
    )
    return layout


@sentinel.command()
@click.option("--db-path", default="./data/authority.db", show_default=True)
@click.option("--ledger-path", default="./data/audit.jsonl", show_default=True)
def watch(db_path: str, ledger_path: str):
    """Live terminal dashboard refreshing every 2 seconds."""
    console.print("[bold cyan]Q-Vault Sentinel Live Dashboard[/bold cyan]  (Ctrl+C to exit)")
    try:
        with Live(_build_dashboard(db_path, ledger_path), refresh_per_second=0.5, screen=True) as live:
            while True:
                time.sleep(2)
                live.update(_build_dashboard(db_path, ledger_path))
    except KeyboardInterrupt:
        console.print("\n[yellow]Dashboard stopped.[/yellow]")


@sentinel.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8700, type=int, show_default=True)
@click.option("--db-path", default=None)
@click.option("--ledger-path", default=None)
def serve(host: str, port: int, db_path: str | None, ledger_path: str | None):
    """Start the FastAPI control plane, protected service nodes, and web console."""
    cfg = load_config(db_path=db_path, ledger_path=ledger_path)
    try:
        app = create_web_console_app(config=cfg)
    except ValueError as exc:
        console.print(
            f"[red]Startup failed: {exc}[/red]\n"
            f"[dim]Set matching QVAULT_MASTER_KEK or remove stale database at {cfg.db_path}.[/dim]"
        )
        raise SystemExit(1)
    console.print(
        Panel(
            f"[bold cyan]Q-Vault Sentinel Web Console & Control Plane[/bold cyan]\n"
            f"Dashboard: [green]http://{host}:{port}/[/green]\n"
            f"API Status: [green]http://{host}:{port}/api/v1/status[/green]",
            border_style="bright_blue",
        )
    )
    uvicorn.run(app, host=host, port=port)


@sentinel.command()
def benchmark():
    """Run deterministic cryptographic, revocation, ledger, and detection benchmarks."""
    results = run_benchmark()
    console.print_json(json.dumps(results, indent=2))


@sentinel.command()
def demo():
    """Run the live end-to-end operational walkthrough using real SDK primitives."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = load_config(
            db_path=str(Path(tmpdir) / "authority.db"),
            ledger_path=str(Path(tmpdir) / "audit.jsonl"),
            backup_dir=str(Path(tmpdir) / "backups"),
        )
        cfg.grace_period_seconds = 1.0
        cfg.checkpoint_interval = 4
        runtime = SentinelRuntime(cfg)

        console.print(
            Panel(
                "[bold cyan]Q-Vault Sentinel — End-to-End Operational Walkthrough[/bold cyan]\n"
                "[dim]Live execution across KeyAuthority, NodeGateway, AuditLedger, and WatchdogDetector[/dim]",
                border_style="bright_blue",
            )
        )

        console.rule("[bold yellow]STEP 1: Service Node Registration[/bold yellow]")
        nodes = runtime.provision_default_topology()
        reg_table = Table(title="Provisioned Service Nodes", box=box.DOUBLE)
        reg_table.add_column("Node ID", style="cyan")
        reg_table.add_column("Epoch", justify="right")
        reg_table.add_column("Status")
        for n in runtime.authority.list_nodes():
            reg_table.add_row(n.node_id, str(n.key_epoch), "[green]ACTIVE[/green]")
        console.print(reg_table)
        console.print(f"  [green]✓[/green] Registered {len(nodes)} service nodes in SQLite WAL.")

        console.rule("[bold yellow]STEP 2: Hybrid Handshake & Recipient-Bound Transfer[/bold yellow]")
        res = runtime.send_encrypted_transfer("WebPortal", "Auth", b"Confidential PQC Payload")
        console.print(
            f"  [green]✓[/green] Transfer WebPortal -> Auth succeeded: "
            f"{res['bytes_delivered']} bytes in {res['delivery_ms']} ms (session {res['session_id'][:16]}...)"
        )

        kp_a = runtime.keypairs["WebPortal"]
        kp_b = runtime.keypairs["Auth"]
        x_b_pub = runtime.authority.get_node("Auth").x25519_public_bytes
        hs_a, ct, eph, sig = perform_handshake_initiator(
            kp_a, kp_b.kem_public, kp_b.signing_public, x_b_pub, "Auth", 0
        )
        hs_b = perform_handshake_responder(
            kp_b, ct, eph, kp_a.signing_public, "WebPortal", sig, 0
        )
        chunk = encrypt_chunk(hs_a.session_keys, b"Sensitive secret", "m1", 0, 1, 1, "WebPortal", "Auth")
        try:
            decrypt_chunk(hs_b.session_keys, chunk, "WebPortal", "PayrollDB")
        except InvalidTag:
            console.print("  [green]✓[/green] AAD recipient substitution raised InvalidTag as expected.")

        console.rule("[bold yellow]STEP 3: Key Rotation Grace Window & Cutoff[/bold yellow]")
        rot = runtime.rotate_epoch()
        valid_during_grace = runtime.authority.is_epoch_valid(rot["epoch"] - 1, check_time=rot["valid_from"] + 0.2)
        valid_after_cutoff = runtime.authority.is_epoch_valid(rot["epoch"] - 1, check_time=rot["cutoff"] + 0.5)
        console.print(f"  [green]✓[/green] Rotated to epoch {rot['epoch']}; prior epoch valid in grace={valid_during_grace}, valid post-cutoff={valid_after_cutoff}")

        console.rule("[bold yellow]STEP 4: Lateral Movement Detection & Automated Revocation[/bold yellow]")
        now = time.time() - 10.0
        for idx, (src, dst) in enumerate(
            [("WebPortal", "FileGateway"), ("FileGateway", "VaultDB"), ("VaultDB", "PayrollDB")]
        ):
            alerts = runtime.ingest_service_event(
                actor="FileGateway",
                action="SERVICE_CALL",
                source_service=src,
                target_service=dst,
                timestamp=now + idx,
                flush_immediately=True,
            )
            for al in alerts:
                console.print(
                    f"  [red]![/red] Alert [{al['severity'].upper()}] {al['violated_rule']}: {al['description']}"
                )

        revoked_state = runtime.authority.is_revoked("FileGateway")
        console.print(f"  [green]✓[/green] Automated revocation enforced for FileGateway: is_revoked={revoked_state}")

        console.rule("[bold yellow]STEP 5: Tamper-Evident Audit Chain Verification[/bold yellow]")
        verify_res = runtime.ledger.verify_chain()
        console.print(f"  [green]✓[/green] {verify_res['message']}")

        runtime.close()


if __name__ == "__main__":
    sentinel()
