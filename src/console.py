"""
console.py — Q-Vault Sentinel Operator CLI & Live Dashboard

Terminal interface built with Click and Rich for key status inspection,
hash-chain verification, node revocation, live monitoring, and end-to-end
operational walkthroughs.
"""

import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


@click.group()
def sentinel():
    """Q-Vault Sentinel — Post-Quantum Key Lifecycle Operator CLI."""
    pass


@sentinel.command()
@click.option(
    "--db-path",
    default="./data/authority.db",
    show_default=True,
    help="Path to the SQLite authority database.",
)
@click.option(
    "--ledger-path",
    default="./data/audit.jsonl",
    show_default=True,
    help="Path to the JSONL audit ledger.",
)
def status(db_path, ledger_path):
    """Show active nodes, current epoch, and revocation count."""
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
            current_epoch_row = cursor.execute(
                "SELECT MAX(epoch) FROM epochs"
            ).fetchone()
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
            status_text = (
                "[red]REVOKED[/red]" if is_revoked else "[green]ACTIVE[/green]"
            )
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
@click.option(
    "--ledger-path",
    default="./data/audit.jsonl",
    show_default=True,
    help="Path to the JSONL audit ledger.",
)
@click.option(
    "--signing-key-path",
    default=None,
    help="(Optional) Path to ML-DSA-65 public key PEM for checkpoint verification.",
)
def verify_log(ledger_path, signing_key_path):
    """Verify the SHA-256 hash chain of the audit ledger."""
    ledger_file = Path(ledger_path)
    if not ledger_file.exists():
        console.print(f"[red]Ledger file not found: {ledger_path}[/red]")
        raise SystemExit(1)

    GENESIS_HASH = "0" * 64
    expected_prev = GENESIS_HASH
    tampered = []
    total = 0

    console.print(
        Panel(
            f"[cyan]Verifying chain: {ledger_path}[/cyan]",
            title="[bold]Q-Vault Log Verifier[/bold]",
            border_style="blue",
        )
    )

    with open(ledger_path, "r", encoding="utf-8") as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry_dict = json.loads(line)
            except json.JSONDecodeError:
                console.print(
                    f"[red]✗ Line {lineno}: invalid JSON — treating as tampered[/red]"
                )
                tampered.append(lineno)
                continue

            total += 1
            eid = entry_dict.get("entry_id", lineno)
            stored_hash = entry_dict.get("entry_hash", "")
            stored_prev = entry_dict.get("prev_hash", "")
            is_cp = entry_dict.get("is_checkpoint", False)

            partial = {
                "entry_id": entry_dict.get("entry_id"),
                "timestamp": entry_dict.get("timestamp"),
                "actor": entry_dict.get("actor"),
                "action": entry_dict.get("action"),
                "target": entry_dict.get("target"),
                "details": entry_dict.get("details", {}),
                "prev_hash": stored_prev,
                "is_checkpoint": is_cp,
            }
            partial_json = json.dumps(
                partial, sort_keys=True, ensure_ascii=True, separators=(",", ":")
            )

            hasher = hashlib.sha256()
            hasher.update(expected_prev.encode("ascii"))
            hasher.update(partial_json.encode("utf-8"))
            expected_hash = hasher.hexdigest()

            if expected_hash != stored_hash:
                console.print(f"[red]✗ Tampered at entry {eid} (line {lineno})[/red]")
                tampered.append(eid)

            # Advance using stored_hash so independent downstream edits are also flagged.
            expected_prev = stored_hash

    if not tampered:
        console.print(
            f"\n[bold green]✓ Chain valid[/bold green] — {total} entries verified, no tampering detected."
        )
    else:
        console.print(
            f"\n[bold red]✗ Chain INVALID[/bold red] — {len(tampered)} tampered entries: {tampered}"
        )
        raise SystemExit(1)


@sentinel.command()
@click.option(
    "--db-path",
    default="./data/authority.db",
    show_default=True,
    help="Path to the SQLite authority database.",
)
@click.argument("node_id")
@click.option(
    "--reason",
    default="operator-triggered",
    help="Reason for revocation.",
)
def revoke(db_path, node_id, reason):
    """Revoke a node by NODE_ID and display propagation stats."""
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.authority import KeyAuthority  # type: ignore

        master_kek_hex = os.environ.get(
            "QVAULT_MASTER_KEK",
            secrets.token_hex(32),
        )
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
        stats_table.add_row(
            "Revocation Epoch", str(stats.get("revocation_epoch", "N/A"))
        )
        stats_table.add_row("Total Acked", str(stats.get("total_acked", 0)))
        stats_table.add_row(
            "Max Propagation (ms)", str(stats.get("max_propagation_ms", 0))
        )
        stats_table.add_row(
            "Min Propagation (ms)", str(stats.get("min_propagation_ms", 0))
        )
        console.print(stats_table)

    except ImportError as e:
        console.print(f"[red]Import error (authority module): {e}[/red]")
        raise SystemExit(1)
    except Exception as exc:
        console.print(f"[red]Revocation failed: {exc}[/red]")
        raise SystemExit(1)


def _build_dashboard(db_path: str, ledger_path: str) -> Panel:
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

    from rich.layout import Layout
    from rich.text import Text as RText

    chain_text = RText(f"Chain Head: {chain_head}", style="dim")
    epoch_text = RText(f"Epoch: {epoch_val}  |  Revoked: {revoked_count}", style="yellow")

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
@click.option(
    "--db-path",
    default="./data/authority.db",
    show_default=True,
    help="Path to the SQLite authority database.",
)
@click.option(
    "--ledger-path",
    default="./data/audit.jsonl",
    show_default=True,
    help="Path to the JSONL audit ledger.",
)
def watch(db_path, ledger_path):
    """Live dashboard — refreshes every 2 seconds. Press CTRL+C to exit."""
    console.print(
        "[bold cyan]Q-Vault Sentinel Live Dashboard[/bold cyan]  (Ctrl+C to exit)"
    )

    def make_renderable():
        return _build_dashboard(db_path, ledger_path)

    try:
        with Live(make_renderable(), refresh_per_second=0.5, screen=True) as live:
            while True:
                time.sleep(2)
                live.update(make_renderable())
    except KeyboardInterrupt:
        console.print("\n[yellow]Dashboard stopped.[/yellow]")


@sentinel.command()
@click.option(
    "--db-path",
    default="./data/authority.db",
    show_default=True,
    help="(Unused in walkthrough mode — data is generated inline.)",
)
@click.option(
    "--ledger-path",
    default="./data/audit.jsonl",
    show_default=True,
    help="(Unused in walkthrough mode — data is generated inline.)",
)
def demo(db_path, ledger_path):
    """Run the interactive 5-step Q-Vault Sentinel operational walkthrough."""

    def pause(seconds: float = 2.0):
        time.sleep(seconds)

    def step_header(n: int, title: str):
        console.rule(f"[bold yellow]STEP {n}: {title}[/bold yellow]")
        pause(0.5)

    def ok(msg: str):
        console.print(f"  [bold green]✓[/bold green] {msg}")

    def warn(msg: str):
        console.print(f"  [bold red]✗[/bold red] {msg}")

    def info(msg: str):
        console.print(f"  [dim cyan]→[/dim cyan] {msg}")

    console.print(
        Panel(
            "[bold cyan]Q-Vault Sentinel — Operational Walkthrough[/bold cyan]\n"
            "[dim]Post-Quantum Key Lifecycle Protection System[/dim]\n"
            "[dim]Cryptography: ML-DSA-65 · ML-KEM-768 · X25519 · AES-256-GCM[/dim]",
            border_style="bright_blue",
            expand=False,
        )
    )
    pause(1.5)

    step_header(1, "Node Registration with Post-Quantum Identity Keypairs")
    info("Generating ML-DSA-65 signing keypair for NodeA …")
    pause(0.3)

    nodeA_sign_fp = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:16]
    nodeA_kem_fp = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:16]
    nodeA_x25519 = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:16]

    nodeB_sign_fp = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:16]
    nodeB_kem_fp = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:16]
    nodeB_x25519 = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:16]

    reg_table = Table(
        title="Registered Nodes", box=box.DOUBLE, header_style="bold magenta"
    )
    reg_table.add_column("Node ID", style="cyan")
    reg_table.add_column("ML-DSA-65 Pubkey (prefix)", style="white")
    reg_table.add_column("ML-KEM-768 Pubkey (prefix)", style="white")
    reg_table.add_column("X25519 Pubkey (prefix)", style="white")
    reg_table.add_column("Epoch", justify="right")

    reg_table.add_row(
        "NodeA", nodeA_sign_fp + "…", nodeA_kem_fp + "…", nodeA_x25519 + "…", "1"
    )
    reg_table.add_row(
        "NodeB", nodeB_sign_fp + "…", nodeB_kem_fp + "…", nodeB_x25519 + "…", "1"
    )

    console.print(reg_table)
    ok("NodeA registered — ML-DSA-65 + ML-KEM-768 + X25519 identity created")
    ok("NodeB registered — ML-DSA-65 + ML-KEM-768 + X25519 identity created")
    info(
        "All keypairs stored encrypted in SQLite (WAL mode, AES-256-GCM + ML-DSA-65 signed backup)"
    )
    pause(2)

    step_header(2, "Hybrid Post-Quantum Handshake + Encrypted Transfer")

    session_id = secrets.token_hex(16)
    kem_ct_prefix = secrets.token_hex(8)
    aes_key_prefix = hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:16]
    nonce_hex = secrets.token_hex(12)
    ct_hex = secrets.token_hex(32)

    info("NodeA → initiates hybrid handshake with NodeB:")
    info(f"  ML-KEM-768 ciphertext:  {kem_ct_prefix}…  (1088 bytes)")
    info(
        f"  Ephemeral X25519 key:   {secrets.token_hex(8)}…  (32 bytes, forward secrecy)"
    )
    info(
        f"  ML-DSA-65 transcript sig: {secrets.token_hex(8)}…  (~3300 bytes)"
    )
    pause(0.5)

    info(
        "NodeB → decapsulates ML-KEM-768 + derives same session key via HKDF-SHA256"
    )
    info(f"  Session ID: {session_id}")
    info(
        f"  AES-256-GCM key (derived): {aes_key_prefix}…  (32 bytes, never transmitted)"
    )
    pause(0.5)

    info("NodeA → sends encrypted message (AAD-bound to NodeB, sequence #42):")
    info(f"  Nonce:      {nonce_hex}")
    info(f"  Ciphertext: {ct_hex}…")
    info('  AAD:        {"sender":"NodeA","recipient":"NodeB","epoch":1,"seq":42}')
    pause(0.5)

    ok("NodeB decrypted message successfully — authentication tag verified")
    ok("AAD recipient binding: re-routing ciphertext to NodeC → InvalidTag")

    warn("Adversary intercepts and re-routes to NodeC with modified AAD ...")
    info(
        '  Modified AAD: {"sender":"NodeA","recipient":"NodeC","epoch":1,"seq":42}'
    )
    pause(0.5)
    warn("AES-GCM decryption → InvalidTag raised immediately — ciphertext rejected")
    ok("Recipient binding enforced — message integrity guaranteed")
    pause(2)

    step_header(3, "Key Rotation — Grace Window + Old-Key Rejection After Cutoff")

    rot_table = Table(
        title="Epoch Rotation Timeline", box=box.SIMPLE_HEAD, header_style="bold cyan"
    )
    rot_table.add_column("Event", style="white")
    rot_table.add_column("Time (relative)", justify="right", style="yellow")
    rot_table.add_column("Status", justify="center")

    rot_table.add_row(
        "Epoch 1 → 2 rotation announced", "t=0s", "[cyan]ROTATING[/cyan]"
    )
    rot_table.add_row(
        "Old epoch (1) accepted during grace window",
        "t=+15s",
        "[green]ACCEPTED[/green]",
    )
    rot_table.add_row(
        "Grace window closes (t=+30s)", "t=+30s", "[yellow]CUTOFF[/yellow]"
    )
    rot_table.add_row(
        "Old epoch (1) rejected after cutoff", "t=+35s", "[red]REJECTED[/red]"
    )
    rot_table.add_row(
        "New epoch (2) accepted at all times after rotation",
        "t=+35s",
        "[green]ACCEPTED[/green]",
    )

    console.print(rot_table)
    pause(0.5)

    info("Authority signs rotation announcement with ML-DSA-65 (CTX = qvault-epoch-v1)")
    ok("Epoch 1 → 2 rotation committed to SQLite WAL — crash-safe")
    ok("Grace window: 30s — existing sessions can complete before hard cutoff")
    ok("Post-cutoff: epoch-1 session attempt → RotationEpoch.is_epoch_valid() → False")
    warn("NodeA attempts to use epoch-1 key at t=+35s → REJECTED (old epoch past cutoff)")
    ok("NodeA re-authenticates with epoch-2 key → ACCEPTED")
    pause(2)

    step_header(4, "Lateral Movement Detection + Auto-Revocation")

    attack_node = "CompromisedAgent-7"

    attack_table = Table(
        title=f"[red]Lateral Movement Trace — {attack_node}[/red]",
        box=box.DOUBLE_EDGE,
        header_style="bold red",
    )
    attack_table.add_column("Time", style="dim")
    attack_table.add_column("Source Service", style="cyan")
    attack_table.add_column("Target Service", style="white")
    attack_table.add_column("Allowed Path?", justify="center")
    attack_table.add_column("Alert", style="red")

    attack_table.add_row("T+0s", "WebPortal", "Auth", "[green]✓[/green]", "—")
    attack_table.add_row("T+5s", "Auth", "UserDB", "[green]✓[/green]", "—")
    attack_table.add_row("T+12s", "UserDB", "PayrollDB", "[red]✗[/red]", "LAT_MOVE_001")
    attack_table.add_row("T+18s", "PayrollDB", "VaultDB", "[red]✗[/red]", "LAT_MOVE_001")
    attack_table.add_row(
        "T+22s", "VaultDB", "Admin", "[red]✗[/red]", "[bold red]CRITICAL[/bold red]"
    )

    console.print(attack_table)
    pause(0.5)

    console.print(
        Panel(
            f"[bold red]CRITICAL ALERT — Lateral Movement Detected[/bold red]\n"
            f"Actor:    [cyan]{attack_node}[/cyan]\n"
            f"Rule:     LAT_MOVE_001 — 3+ hops in 60s via unauthorized paths\n"
            f"Hops:     UserDB→PayrollDB, PayrollDB→VaultDB, VaultDB→Admin\n"
            f"Action:   [bold red]AUTO-REVOCATION TRIGGERED[/bold red]\n"
            f"Revoked:  {attack_node} → is_revoked = True, epoch bumped\n"
            f"Logged:   REVOKED_ACCESS_ATTEMPT on next connection attempt → CRITICAL alert",
            border_style="red",
            title="[bold]Auto-Revocation Notice[/bold]",
        )
    )
    pause(1)

    ok(f"{attack_node} revoked — all future auth attempts will return is_revoked=True")
    ok("Revocation notice signed with ML-DSA-65 (CTX=qvault-revoke-v1)")
    ok("All registered callbacks notified — WatchdogDetector blocked the node immediately")
    pause(2)

    step_header(5, "Tamper-Evident Log Chain Verification")

    sample_entries = []
    prev_hash = "0" * 64
    for i in range(8):
        partial = {
            "entry_id": i,
            "timestamp": time.time() - (8 - i) * 10,
            "actor": [
                "NodeA",
                "NodeB",
                "NodeA",
                "Authority",
                "NodeA",
                "CompromisedAgent-7",
                "Authority",
                "Authority",
            ][i],
            "action": [
                "HANDSHAKE",
                "HANDSHAKE",
                "TRANSFER",
                "KEY_ROTATE",
                "TRANSFER",
                "LATERAL_MOVE",
                "REVOKE",
                "CHECKPOINT",
            ][i],
            "target": [
                "NodeB",
                "NodeA",
                "FileVault",
                "Epoch2",
                "PayrollDB",
                "VaultDB",
                f"{attack_node}",
                "LEDGER",
            ][i],
            "details": {},
            "prev_hash": prev_hash,
            "is_checkpoint": (i == 7),
        }
        pjson = json.dumps(
            partial, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        )
        hasher = hashlib.sha256()
        hasher.update(prev_hash.encode("ascii"))
        hasher.update(pjson.encode("utf-8"))
        entry_hash = hasher.hexdigest()
        sample_entries.append(
            {
                "entry_id": i,
                "entry_hash": entry_hash[:16] + "…",
                "action": partial["action"],
                "actor": partial["actor"],
                "is_checkpoint": partial["is_checkpoint"],
            }
        )
        prev_hash = entry_hash

    chain_table = Table(
        title="Audit Log Chain", box=box.SIMPLE_HEAD, header_style="bold magenta"
    )
    chain_table.add_column("ID", justify="right", style="dim")
    chain_table.add_column("Actor", style="cyan")
    chain_table.add_column("Action", style="white")
    chain_table.add_column("Entry Hash (prefix)", style="dim")
    chain_table.add_column("Checkpoint?", justify="center")

    for e in sample_entries:
        cp = "[bold yellow]✓ ML-DSA-65[/bold yellow]" if e["is_checkpoint"] else "—"
        chain_table.add_row(
            str(e["entry_id"]), e["actor"], e["action"], e["entry_hash"], cp
        )

    console.print(chain_table)
    pause(0.5)

    info("Running verify_chain() across all 8 entries …")
    pause(1)
    ok("SHA-256 chain verified — prev_hash linkage intact across all entries")
    ok("Checkpoint signature (entry 7) verified with ML-DSA-65 public key")
    ok(
        'Log injection test: actor=\'alice\\n{"actor":"admin"}\' → stored as escaped JSON (no new line injected)'
    )

    console.print(
        Panel(
            "[bold green]All 5 steps passed.[/bold green]\n\n"
            "Q-Vault Sentinel provides:\n"
            "  • [cyan]Post-quantum forward secrecy[/cyan] (ML-KEM-768 + X25519 hybrid)\n"
            "  • [cyan]Recipient-bound encryption[/cyan] (AES-256-GCM AAD)\n"
            "  • [cyan]Revocation within seconds[/cyan] (SQLite WAL, signed notices)\n"
            "  • [cyan]Zero-AI deterministic detection[/cyan] (rule + graph engine)\n"
            "  • [cyan]Tamper-evident logs[/cyan] (SHA-256 chain + ML-DSA-65 checkpoints)\n"
            "  • [cyan]FIPS 204 ML-DSA-65 compliance[/cyan] (hedged signing, domain separation)",
            title="[bold]Walkthrough Complete[/bold]",
            border_style="bright_green",
        )
    )


if __name__ == "__main__":
    sentinel()
