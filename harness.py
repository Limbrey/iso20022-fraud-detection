#!/usr/bin/env python3
"""
harness.py — ISO 20022 pacs.008 Test Harness
Generates realistic interbank payment messages with fraud injection,
streams to Elastic Serverless, and renders a live terminal dashboard.

Usage:
    python harness.py                        # uses config.yaml
    python harness.py --config my.yaml
    python harness.py --rate 60              # override msgs/min
    python harness.py --total 200            # override total messages
    python harness.py --dry-run              # generate + log, no Elastic
"""

import argparse
import json
import os
import sys
import time
import threading
import signal
from collections import deque
from datetime import datetime
from pathlib import Path

import yaml

# Rich imports
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn, MofNCompleteColumn,
)
from rich.layout import Layout
from rich import box

# Local modules
from generator import Pacs008Generator
from elastic_shipper import ElasticShipper, xml_to_dict
from log_writer import LogWriter

console = Console()

FRAUD_COLOURS = {
    "invalid_bic":        "red",
    "sanctioned_country": "bright_red",
    "round_amount":       "yellow",
    "rapid_succession":   "orange3",
    "dormant_account":    "magenta",
    "amount_spike":       "red1",
}


# ── Stats container ────────────────────────────────────────────────────────────

class Stats:
    def __init__(self):
        self.total_sent = 0
        self.total_fraud = 0
        self.elastic_ok = 0
        self.elastic_err = 0
        self.start_time = datetime.utcnow()
        self.recent: deque = deque(maxlen=20)   # last N messages for the live feed
        self.fraud_breakdown: dict = {}
        self._lock = threading.Lock()

    def record(self, msg, elastic_ok: bool):
        with self._lock:
            self.total_sent += 1
            if msg.is_fraud:
                self.total_fraud += 1
                ft = msg.fraud_type or "unknown"
                self.fraud_breakdown[ft] = self.fraud_breakdown.get(ft, 0) + 1
            if elastic_ok:
                self.elastic_ok += 1
            else:
                self.elastic_err += 1
            self.recent.append(msg)

    @property
    def elapsed(self) -> float:
        return (datetime.utcnow() - self.start_time).total_seconds()

    @property
    def rate(self) -> float:
        return self.total_sent / self.elapsed if self.elapsed > 0 else 0.0


# ── Dashboard builder ──────────────────────────────────────────────────────────

def build_dashboard(stats: Stats, config: dict, total_target: int, dry_run: bool) -> Layout:
    elapsed = stats.elapsed
    rate = stats.rate
    fraud_pct = (stats.total_fraud / stats.total_sent * 100) if stats.total_sent else 0

    # ── Header panel ──────────────────────────────────────────────────────────
    bank_name = config.get("bank", {}).get("name", "Test Bank")
    mode_tag = "[dim italic]DRY RUN[/]" if dry_run else "[green]● LIVE[/]"
    header = Panel(
        Text.assemble(
            ("  ISO 20022 pacs.008 Test Harness", "bold white"),
            "   |   ",
            (bank_name, "cyan"),
            "   |   ",
            mode_tag,
        ),
        style="on grey11",
        box=box.HEAVY,
    )

    # ── Key metrics table ──────────────────────────────────────────────────────
    metrics = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
    metrics.add_column("Metric", style="dim")
    metrics.add_column("Value", style="bold")

    metrics.add_row("Messages sent", f"[cyan]{stats.total_sent:,}[/]"
                    + (f" / {total_target:,}" if total_target else ""))
    metrics.add_row("Elapsed",       f"[white]{int(elapsed // 60)}m {int(elapsed % 60)}s[/]")
    metrics.add_row("Rate",          f"[green]{rate:.1f}[/] msg/s  "
                                     f"[dim]({rate * 60:.0f}/min)[/]")
    metrics.add_row("Fraud injected",f"[red]{stats.total_fraud:,}[/]"
                                     f"  [dim]({fraud_pct:.1f}%)[/]")
    metrics.add_row("Elastic OK",    f"[green]{stats.elastic_ok:,}[/]")
    metrics.add_row("Elastic Errors",f"[{'red' if stats.elastic_err else 'dim'}]{stats.elastic_err:,}[/]")

    # ── Fraud breakdown ────────────────────────────────────────────────────────
    fraud_table = Table(title="Fraud Types", box=box.MINIMAL, title_style="bold red")
    fraud_table.add_column("Type", style="dim white")
    fraud_table.add_column("Count", justify="right")
    for ft, count in sorted(stats.fraud_breakdown.items(), key=lambda x: -x[1]):
        colour = FRAUD_COLOURS.get(ft, "yellow")
        fraud_table.add_row(f"[{colour}]{ft}[/]", f"[{colour}]{count}[/]")
    if not stats.fraud_breakdown:
        fraud_table.add_row("[dim]none yet[/]", "")

    # ── Recent messages feed ───────────────────────────────────────────────────
    feed = Table(
        title="Recent Messages",
        box=box.MINIMAL,
        title_style="bold cyan",
        show_lines=False,
    )
    feed.add_column("Time", style="dim", width=12)
    feed.add_column("Msg ID", style="dim cyan", width=14)
    feed.add_column("Amount", justify="right", width=14)
    feed.add_column("Debtor BIC", width=10)
    feed.add_column("Creditor BIC", width=12)
    feed.add_column("Status", width=18)

    for msg in reversed(list(stats.recent)):
        ts = msg.timestamp.strftime("%H:%M:%S")
        short_id = msg.msg_id[:12] + "…"
        amount_str = f"{msg.currency} {msg.amount:>10,.2f}"
        if msg.is_fraud:
            colour = FRAUD_COLOURS.get(msg.fraud_type, "yellow")
            status = f"[{colour}]⚠ {msg.fraud_type or 'fraud'}[/]"
        else:
            status = "[green]✓ clean[/]"
        feed.add_row(ts, short_id, amount_str, msg.debtor_bic, msg.creditor_bic, status)

    # ── Compose layout ─────────────────────────────────────────────────────────
    layout = Layout()
    layout.split_column(
        Layout(header, name="header", size=3),
        Layout(name="body"),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(feed, name="right", ratio=2),
    )
    layout["left"].split_column(
        Layout(metrics, name="metrics"),
        Layout(fraud_table, name="fraud"),
    )
    return layout


# ── Main harness loop ──────────────────────────────────────────────────────────

def run(config: dict, dry_run: bool = False, rate_override: int = None, total_override: int = None):
    cadence = config.get("cadence", {})
    volume = config.get("volume", {})

    msgs_per_min = rate_override or cadence.get("msgs_per_minute", 20)
    total_target = total_override or volume.get("total_messages", 0)
    interval = 60.0 / msgs_per_min

    burst_enabled = cadence.get("burst_enabled", True)
    burst_prob = cadence.get("burst_probability", 0.05)
    burst_size = cadence.get("burst_size", 10)

    generator = Pacs008Generator(config)
    log_writer = LogWriter(config)
    stats = Stats()

    shipper = None
    if not dry_run:
        shipper = ElasticShipper(config)
        ok, detail = shipper.test_connection()
        if ok:
            console.print(f"[green]✓ Elastic:[/] {detail}")
        else:
            console.print(f"[yellow]⚠ Elastic:[/] {detail}")
            console.print("[dim]Continuing in log-only mode.[/]")
            shipper._ok = False

    stop_event = threading.Event()

    def _handle_signal(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    console.print(f"\n[bold]Starting harness[/] — {msgs_per_min} msg/min"
                  + (f", {total_target} total" if total_target else ", indefinite")
                  + (" [dim](dry run)[/]" if dry_run else ""))
    console.print(f"[dim]Log → {log_writer.log_file}[/]\n")

    with Live(console=console, refresh_per_second=4, screen=False) as live:
        while not stop_event.is_set():
            # Check total
            if total_target and stats.total_sent >= total_target:
                break

            # Burst?
            import random
            batch = burst_size if (burst_enabled and random.random() < burst_prob) else 1

            for _ in range(batch):
                if total_target and stats.total_sent >= total_target:
                    break
                if stop_event.is_set():
                    break

                msg = generator.generate()
                xml_dict = xml_to_dict(msg.xml)
                log_writer.write(msg, xml_dict)

                elastic_ok = False
                if shipper and shipper._ok:
                    ok, detail = shipper.ship(msg, xml_dict)
                    elastic_ok = ok

                stats.record(msg, elastic_ok)

            live.update(build_dashboard(stats, config, total_target, dry_run))
            time.sleep(interval)

    log_writer.close()

    # ── Final summary ──────────────────────────────────────────────────────────
    console.rule("[bold cyan]Run Complete")
    console.print(f"  Total messages : [cyan]{stats.total_sent:,}[/]")
    console.print(f"  Fraud injected : [red]{stats.total_fraud:,}[/] ({stats.total_fraud/max(stats.total_sent,1)*100:.1f}%)")
    console.print(f"  Elapsed        : {int(stats.elapsed//60)}m {int(stats.elapsed%60)}s")
    console.print(f"  Avg rate       : {stats.rate:.1f} msg/s")
    lstat = log_writer.stats()
    console.print(f"  Log file       : {lstat['log_file']} ({lstat['size_kb']} KB)")
    if shipper:
        console.print(f"  Elastic OK     : [green]{stats.elastic_ok:,}[/]  Errors: [red]{stats.elastic_err:,}[/]")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ISO 20022 pacs.008 Test Harness")
    parser.add_argument("--config", default="config.yaml", help="Path to config YAML")
    parser.add_argument("--rate",   type=int, help="Override msgs/min from config")
    parser.add_argument("--total",  type=int, help="Override total message count")
    parser.add_argument("--dry-run", action="store_true",
                        help="Generate and log messages without sending to Elastic")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        console.print(f"[red]Config not found:[/] {config_path}")
        sys.exit(1)

    with open(config_path) as f:
        config = yaml.safe_load(f)

    run(
        config,
        dry_run=args.dry_run,
        rate_override=args.rate,
        total_override=args.total,
    )


if __name__ == "__main__":
    main()
