import sys
import json
import shutil
from pathlib import Path
from collections import Counter
import pandas as pd
import numpy as np

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich import box

cols = shutil.get_terminal_size().columns
console = Console(force_terminal=True, legacy_windows=False, width=max(cols, 120))
data_path = Path(__file__).resolve().parent / "benchmark.jsonl"


def load():
    records = []
    with open(data_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    raw = pd.DataFrame(records)
    rows = []

    for r in records:
        cwes = r.get("cwe", [])
        if isinstance(cwes, str):
            cwes = [cwes]
        cwe = ", ".join(cwes)

        v_code = r.get("vulnerable_function_body", "") or ""
        b_code = r.get("non_vulnerable_function_body", "") or ""

        v_loc = len(v_code.splitlines())
        b_loc = len(b_code.splitlines())
        v_chars = len(v_code)
        b_chars = len(b_code)

        v_callers = len(r.get("vulnerable_caller_graph", {}) or {})
        b_callers = len(r.get("non_vulnerable_caller_graph", {}) or {})
        v_callees = len(r.get("vulnerable_callee_graph", {}) or {})
        b_callees = len(r.get("non_vulnerable_callee_graph", {}) or {})
        v_bodies = len(r.get("vulnerable_function_bodies", {}) or {})
        b_bodies = len(r.get("non_vulnerable_function_bodies", {}) or {})

        v_msg = len(r.get("vulnerability_introducing_commit_message", "") or "")
        b_msg = len(r.get("vulnerability_fixing_commit_message", "") or "")

        rows.append({
            "idx": r.get("idx"),
            "cve": r.get("cve"),
            "project": r.get("project"),
            "cwe": cwe,
            "label": 1,
            "name": "Vulnerable",
            "loc": v_loc,
            "chars": v_chars,
            "callers": v_callers,
            "callees": v_callees,
            "bodies": v_bodies,
            "msg": v_msg
        })

        rows.append({
            "idx": r.get("idx"),
            "cve": r.get("cve"),
            "project": r.get("project"),
            "cwe": cwe,
            "label": 0,
            "name": "Benign",
            "loc": b_loc,
            "chars": b_chars,
            "callers": b_callers,
            "callees": b_callees,
            "bodies": b_bodies,
            "msg": b_msg
        })

    return raw, pd.DataFrame(rows)


def overview(raw, df):
    console.print()
    console.print("[bold cyan]DATASET OVERVIEW[/bold cyan]")
    console.rule(style="dim")

    n_rows = len(raw)
    n_cols = len(raw.columns)
    n_null = int(raw.isna().sum().sum())
    n_dup = int(raw["idx"].duplicated().sum())

    t_info = Table(box=box.SIMPLE_HEAD, expand=True, border_style="dim")
    t_info.add_column("Metric", style="bold cyan", ratio=1)
    t_info.add_column("Value", justify="right", style="bold green", ratio=1)

    t_info.add_row("Rows", f"{n_rows:,}")
    t_info.add_row("Columns", f"{n_cols}")
    t_info.add_row("Miss values", f"{n_null}")
    t_info.add_row("Duplicate values", f"{n_dup}")

    console.print(t_info)
    console.print()

    t_cols = Table(title="Features stats", title_style="bold blue", box=box.SIMPLE_HEAD, expand=True, border_style="dim")
    t_cols.add_column("Feature", style="bold white", ratio=2)
    t_cols.add_column("Data type", style="green", ratio=1)
    t_cols.add_column("Missing count", justify="right", style="white", ratio=1)
    t_cols.add_column("Missing percentage", justify="right", style="bold green", ratio=1)

    for col in raw.columns:
        first_val = raw[col].iloc[0]
        dt = type(first_val).__name__
        if dt == "int":
            dt = "int64"
        col_null = int(raw[col].isna().sum())
        col_pct = col_null / len(raw) * 100
        t_cols.add_row(col, dt, f"{col_null}", f"{col_pct:.2f}%")

    console.print(t_cols)
    console.print()


def labels(df):
    console.print("[bold cyan]LABEL DISTRIBUTION[/bold cyan]")
    console.rule(style="dim")

    n_total = len(df)
    counts = df["label"].value_counts()
    n_vul = int(counts.get(1, 0))
    n_ben = int(counts.get(0, 0))
    pct_vul = n_vul / n_total * 100
    pct_ben = n_ben / n_total * 100
    ir = n_ben / n_vul if n_vul != 0 else 0.0

    bar_len = max(25, (console.width - 60) // 2)
    bar_vul = "█" * int(bar_len * (n_vul / n_total))
    bar_ben = "█" * int(bar_len * (n_ben / n_total))

    t = Table(box=box.SIMPLE_HEAD, expand=True, border_style="dim")
    t.add_column("Target", style="bold cyan", ratio=2)
    t.add_column("Bar", style="white", ratio=3)
    t.add_column("Sample", justify="right", style="bold white", ratio=2)
    t.add_column("Percentage", justify="right", style="bold green", ratio=2)

    t.add_row("[red]Vulnerable (Class 1)[/red]", f"[red]{bar_vul}[/red]", f"{n_vul:,}", f"{pct_vul:.2f}%")
    t.add_row("[green]Benign (Class 0)[/green]", f"[green]{bar_ben}[/green]", f"{n_ben:,}", f"{pct_ben:.2f}%")
    console.print(t)

    t_imbalance = Table(box=box.SIMPLE_HEAD, expand=True, border_style="dim")
    t_imbalance.add_column("Metric", style="bold cyan", ratio=2)
    t_imbalance.add_column("Computed Value", justify="right", style="bold green", ratio=2)
    t_imbalance.add_row("Class Imbalance", f"{ir:.4f}")
    t_imbalance.add_row("Class Difference", f"{abs(n_vul - n_ben)} samples")
    console.print(t_imbalance)
    console.print()


def features(raw, df):
    console.print("[bold cyan]FEATURE DISTRIBUTION[/bold cyan]")
    console.rule(style="dim")

    nums = ["loc", "chars", "callers", "callees", "bodies", "msg"]

    t_num = Table(title="Quantiles, Moments & Outliers", title_style="bold blue", box=box.SIMPLE_HEAD, expand=True, border_style="dim")
    t_num.add_column("Feature", style="bold cyan", no_wrap=True)
    t_num.add_column("Min", justify="right", style="dim", no_wrap=True)
    t_num.add_column("Q1: 25%", justify="right", style="white", no_wrap=True)
    t_num.add_column("Median", justify="right", style="bold green", no_wrap=True)
    t_num.add_column("Mean", justify="right", style="white", no_wrap=True)
    t_num.add_column("Mode", justify="right", style="white", no_wrap=True)
    t_num.add_column("Q3: 75%", justify="right", style="white", no_wrap=True)
    t_num.add_column("Max", justify="right", style="red", no_wrap=True)
    t_num.add_column("Std Dev", justify="right", style="dim", no_wrap=True)
    t_num.add_column("IQR", justify="right", style="white", no_wrap=True)
    t_num.add_column("Outliers", justify="right", style="yellow", no_wrap=True)
    t_num.add_column("Outlier %", justify="right", style="yellow", no_wrap=True)

    for col in nums:
        s = df[col]
        q1 = float(s.quantile(0.25))
        med = float(s.median())
        mean = float(s.mean())
        q3 = float(s.quantile(0.75))
        mode_val = float(s.mode().iloc[0]) if not s.mode().empty else np.nan
        std_val = float(s.std())
        iqr = q3 - q1
        out = s[(s < q1 - 1.5 * iqr) | (s > q3 + 1.5 * iqr)]
        out_cnt = len(out)
        out_pct = out_cnt / len(s) * 100

        t_num.add_row(
            col,
            f"{s.min():,}",
            f"{q1:,.1f}",
            f"{med:,.1f}",
            f"{mean:,.2f}",
            f"{mode_val:,.1f}",
            f"{q3:,.1f}",
            f"{s.max():,}",
            f"{std_val:,.2f}",
            f"{iqr:,.1f}",
            f"{out_cnt:,}",
            f"{out_pct:.2f}%"
        )

    console.print(t_num)
    console.print()

    proj_counts = raw["project"].value_counts()
    n_proj = len(proj_counts)
    proj_rare = int((proj_counts < 2).sum())
    proj_rare_pct = proj_rare / n_proj * 100

    cwes_raw = []
    for item in raw["cwe"]:
        if isinstance(item, list):
            cwes_raw.extend(item)
        else:
            cwes_raw.append(str(item))
    cwe_counts = Counter(cwes_raw)
    n_cwe = len(cwe_counts)
    cwe_rare = sum(1 for v in cwe_counts.values() if v < 3)
    cwe_rare_pct = cwe_rare / n_cwe * 100

    t_cat = Table(title="Cardinality & Rare", title_style="bold blue", box=box.SIMPLE_HEAD, expand=True, border_style="dim")
    t_cat.add_column("Feature", style="bold cyan", ratio=2)
    t_cat.add_column("Cardinality", justify="right", style="bold white", ratio=1)
    t_cat.add_column("Max Frequency", justify="right", style="white", ratio=1)
    t_cat.add_column("Min Frequency", justify="right", style="white", ratio=1)
    t_cat.add_column("Rare Count", justify="right", style="yellow", ratio=1)
    t_cat.add_column("Rare Pct", justify="right", style="bold green", ratio=1)

    t_cat.add_row("project", f"{n_proj:,}", f"{proj_counts.max():,}", f"{proj_counts.min():,}", f"{proj_rare:,}", f"{proj_rare_pct:.2f}%")
    t_cat.add_row("cwe", f"{n_cwe:,}", f"{max(cwe_counts.values()):,}", f"{min(cwe_counts.values()):,}", f"{cwe_rare:,}", f"{cwe_rare_pct:.2f}%")
    console.print(t_cat)
    console.print()


def skewness(df):
    console.print("[bold cyan]MEAN VS MEDIAN[/bold cyan]")
    console.rule(style="dim")

    nums = ["loc", "chars", "callers", "callees", "bodies", "msg"]

    t = Table(box=box.SIMPLE_HEAD, expand=True, border_style="dim")
    t.add_column("Feature", style="bold cyan", no_wrap=True)
    t.add_column("Mean", justify="right", style="white", no_wrap=True)
    t.add_column("Median", justify="right", style="bold green", no_wrap=True)
    t.add_column("Delta: Mean - Median", justify="right", style="yellow", no_wrap=True)
    t.add_column("Ratio: Mean / Median", justify="right", style="cyan", no_wrap=True)

    for col in nums:
        s = df[col]
        mean = float(s.mean())
        med = float(s.median())
        diff = mean - med
        ratio = mean / med if med != 0 else 0.0

        t.add_row(col, f"{mean:,.2f}", f"{med:,.2f}", f"{diff:+,.2f}", f"{ratio:.2f}x")

    console.print(t)
    console.print()


def correlate(df):
    console.print("[bold cyan]FEATURE-LABEL CORRELATION[/bold cyan]")
    console.rule(style="dim")

    nums = ["loc", "chars", "callers", "callees", "bodies", "msg"]

    t_corr = Table(title="Correlation & Distribution", title_style="bold blue", box=box.SIMPLE_HEAD, expand=True, border_style="dim")
    t_corr.add_column("Feature", style="bold cyan", no_wrap=True)
    t_corr.add_column("Pearson r", justify="right", style="bold white", no_wrap=True)
    t_corr.add_column("Spearman rho", justify="right", style="bold white", no_wrap=True)
    t_corr.add_column("Benign Mean", justify="right", style="green", no_wrap=True)
    t_corr.add_column("Vuln Mean", justify="right", style="red", no_wrap=True)
    t_corr.add_column("Delta Mean (V-B)", justify="right", style="yellow", no_wrap=True)
    t_corr.add_column("Benign Median", justify="right", style="green", no_wrap=True)
    t_corr.add_column("Vuln Median", justify="right", style="red", no_wrap=True)
    t_corr.add_column("Delta Median (V-B)", justify="right", style="yellow", no_wrap=True)

    for col in nums:
        p = float(df[col].corr(df["label"], method="pearson"))
        s = float(df[col].corr(df["label"], method="spearman"))
        b_s = df[df["label"] == 0][col]
        v_s = df[df["label"] == 1][col]
        diff_mean = v_s.mean() - b_s.mean()
        diff_med = v_s.median() - b_s.median()

        t_corr.add_row(
            col,
            f"{p:+.4f}",
            f"{s:+.4f}",
            f"{b_s.mean():,.2f}",
            f"{v_s.mean():,.2f}",
            f"{diff_mean:+,.2f}",
            f"{b_s.median():,.2f}",
            f"{v_s.median():,.2f}",
            f"{diff_med:+,.2f}"
        )

    console.print(t_corr)
    console.print()


def main():
    if not data_path.exists():
        console.print(f"[bold red]ERROR: File not found: {data_path}[/bold red]")
        return

    raw, df = load()
    overview(raw, df)
    labels(df)
    features(raw, df)
    skewness(df)
    correlate(df)


if __name__ == "__main__":
    main()

