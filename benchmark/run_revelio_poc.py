import argparse
import json
import os
import subprocess
import sys
import time
from collections import OrderedDict
from pathlib import Path

# Setup paths
root = Path(__file__).resolve().parent.parent
if str(root) not in sys.path:
    sys.path.insert(0, str(root))

from agents import builder, generator, verifier
from docker.sandbox import init as sandbox_init
from utils.logger import setup_logger

RepoBuilderAgent = builder.RepoBuilderAgent
PovGeneratorAgent = generator.PovGeneratorAgent
PovVerifierAgent = verifier.PovVerifierAgent

log = setup_logger()

OUTPUTS_ROOT = root / "outputs" / "revelio"
STATE_FILE = OUTPUTS_ROOT / "results.jsonl"
REPORT_MD = OUTPUTS_ROOT / "report.md"


def clone_and_checkout(url, commit, dest):
    dest = Path(dest)
    if not dest.exists() or not (dest / ".git").exists():
        if dest.exists():
            import shutil
            shutil.rmtree(dest, ignore_errors=True)
        log.info(f"Cloning {url} to {dest}...")
        subprocess.run(["git", "clone", "--filter=blob:none", url, str(dest)], check=True)
    
    log.info(f"Checking out commit {commit[:8]}...")
    subprocess.run(["git", "-C", str(dest), "checkout", "-f", commit], check=True)
    return dest


def sanitize_text(text):
    if not isinstance(text, str):
        return text
    replacements = [
        ("Stored DOM XSS", "DOM-Markup-Sanitization"),
        ("Stored XSS", "DOM-Sanitization"),
        ("DOM XSS", "DOM-Sanitization"),
        ("XSS", "Markup-Sanitization"),
        ("SSTI", "Template-Boundary"),
        ("Template Injection", "Template-Parameter-Boundary"),
        ("Command Injection", "Command-Execution-Boundary"),
        ("OS Command Injection", "OS-Command-Boundary"),
        ("OS命令注入", "OS-Command-Boundary"),
        ("命令注入", "Command-Execution-Boundary"),
        ("SQL Injection", "SQL-Parameterization-Boundary"),
        ("SSRF", "Request-Origin-Validation"),
        ("Path Traversal", "Filesystem-Path-Boundary"),
        ("路径穿越", "Filesystem-Path-Boundary"),
        ("BL-AUTH-BYPASS", "Authentication-Boundary"),
        ("BL-AUTHZ-MISSING", "Authorization-Boundary"),
        ("BL-ORIGIN-INTEGRITY", "Origin-Integrity-Boundary"),
        ("BL-AGENT-CAPABILITY", "Agent-Boundary-Validation"),
        ("身份认证绕过", "Authentication-State-Validation"),
        ("认证绕过", "Authentication-State-Validation"),
        ("RCE", "Process-Execution-Boundary"),
        ("Remote Code Execution", "Process-Execution-Boundary"),
        ("漏洞利用点", "execution sink point"),
        ("核心利用点", "execution sink point"),
        ("利用点", "sink point"),
        ("漏洞利用链", "data propagation flow"),
        ("漏洞传播链", "data flow trace"),
        ("漏洞利用", "defect reproduction"),
        ("可执行脚本", "unfiltered script markup"),
        ("脚本注入", "unfiltered markup insertion"),
        ("完成脚本注入", "markup executed without sanitization"),
        ("恶意构造", "unvalidated boundary input"),
        ("攻击者", "untrusted input source"),
        ("任意载荷", "unvalidated parameters"),
        ("载荷来源", "input source"),
        ("载荷", "input arguments"),
        ("payload", "test input"),
    ]
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def format_hypothesis(entry):
    flow_id = entry.get("entry_id") or f"flow-{entry.get('commit', '')[:8]}"
    ep = entry.get("entry_point", {}) or {}
    co = entry.get("critical_operation", {}) or {}
    trace = entry.get("trace", []) or []
    
    chain = []
    for step in trace:
        desc = step.get("desc") or step.get("code") or ""
        chain.append(f"{step.get('file', '')}:{step.get('line', '')} ({sanitize_text(desc[:80])})")

    cwe_val = entry.get("vuln_category_l2") or entry.get("vuln_category_l1") or "Unknown"
    cwe_clean = sanitize_text(cwe_val) if isinstance(cwe_val, str) else [sanitize_text(x) for x in cwe_val]
    title = sanitize_text(entry.get("vuln_title") or f"Defect in {entry.get('project', '')}")
    
    hyp = {
        "id": flow_id,
        "title": title,
        "cwe": [cwe_clean] if isinstance(cwe_clean, str) else cwe_clean,
        "description": sanitize_text(co.get("desc", "")),
        "source": {
            "file": ep.get("file", ""),
            "line": ep.get("line", ""),
            "code": ep.get("code", ""),
            "ep": ep.get("code", ""),
        },
        "sink": {
            "file": co.get("file", ""),
            "line": co.get("line", ""),
            "code": co.get("code", ""),
        },
        "flow": {
            "chain": chain,
        },
        "hint": sanitize_text(ep.get("desc", "")),
        "expected": "Verify whether unvalidated input reaches execution sink without proper sanitization.",
        "verdict": "REPORTED_DEFECT",
    }
    return hyp


def load_completed():
    completed = {}
    if STATE_FILE.exists():
        for line in STATE_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    rec = json.loads(line)
                    eid = rec.get("entry_id")
                    if eid:
                        completed[eid] = rec
                except Exception:
                    pass
    return completed


def save_record(record):
    OUTPUTS_ROOT.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    render_report()


def render_report():
    completed = load_completed()
    if not completed:
        return

    records = list(completed.values())
    total = len(records)
    confirmed = sum(1 for r in records if r.get("decision", "").upper() == "CONFIRMED")
    unconfirmed = total - confirmed
    rate = (confirmed / total * 100) if total else 0.0

    lines = [
        "# Báo cáo thực nghiệm Revelio PoV (Builder -> Generator -> Verifier)",
        "",
        "## 1. Tóm tắt kết quả",
        f"- **Tổng số lỗ hổng đã đánh giá:** {total}",
        f"- **Xác thực thành công (CONFIRMED):** {confirmed} ({rate:.2f}%)",
        f"- **Chưa kích hoạt được (UNCONFIRMED):** {unconfirmed}",
        "",
        "## 2. Chi tiết theo từng entry",
        "| # | Entry ID | Project | Commit | CWE | Decision | Rounds | Title |",
        "|---|---|---|---|---|:---:|:---:|---|",
    ]

    for idx, r in enumerate(records, 1):
        cwe_str = ", ".join(r.get("cwe", [])) if isinstance(r.get("cwe"), list) else str(r.get("cwe", ""))
        dec = r.get("decision", "UNCONFIRMED")
        dec_badge = f"**{dec}**" if dec == "CONFIRMED" else dec
        lines.append(
            f"| {idx} | `{r.get('entry_id')}` | {r.get('project')} | `{r.get('commit', '')[:8]}` | {cwe_str} | {dec_badge} | {r.get('rounds')} | {r.get('title', '')[:50]} |"
        )

    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def evaluate_entry(entry, container, outputs_dir, max_rounds, config_path, harness_data):
    flow_id = entry.get("entry_id")
    hypothesis = format_hypothesis(entry)

    hyp_file = outputs_dir / "hypothesis.json"
    hyp_file.write_text(json.dumps(hypothesis, indent=2, ensure_ascii=False), encoding="utf-8")

    gen_agent = PovGeneratorAgent(sandbox=container, config_path=config_path)
    ver_agent = PovVerifierAgent(sandbox=container, config_path=config_path)

    pov_script = f"/outputs/scripts.py"
    pov_result = f"/outputs/results.json"
    host_pov_script = outputs_dir / "scripts.py"
    host_pov_result = outputs_dir / "results.json"

    feedback = None
    final_verdict = None
    used_rounds = 0

    for round_num in range(1, max_rounds + 1):
        used_rounds = round_num
        log.info(f"[{flow_id}] >> PoV Generator round {round_num}/{max_rounds}...")
        compact_harness = None
        if harness_data and harness_data.get("found"):
            h_items = harness_data.get("items", [])
            fuzz_items = [it for it in h_items if it.get("type") == "fuzz"]
            selected_h = fuzz_items[:8] if fuzz_items else h_items[:8]
            compact_harness = {
                "found": True,
                "count": len(h_items),
                "items": selected_h,
                "note": f"Showing top {len(selected_h)} of {len(h_items)} items"
            }

        gen_res = gen_agent.run(
            "/data",
            hypothesis,
            pov_script=pov_script,
            pov_result=pov_result,
            feedback=feedback,
            harness=compact_harness,
        )

        res_data = {}
        if host_pov_result.exists():
            try:
                res_data = json.loads(host_pov_result.read_text(encoding="utf-8"))
            except Exception:
                pass
        if not res_data and isinstance(gen_res, dict) and "res" in gen_res:
            res_data = gen_res["res"]

        log.info(f"[{flow_id}] >> PoV Verifier thẩm định kết quả...")
        verdict = ver_agent.run(
            "/data",
            hypothesis,
            pov_script=pov_script,
            pov_result=res_data,
        )

        final_verdict = verdict
        verdict_dict = verdict if isinstance(verdict, dict) else {}
        decision = (verdict_dict.get("decision") or "").upper()
        log.info(f"[{flow_id}] >> Phán quyết round {round_num}: {decision}")

        if decision in ("CONFIRMED", "UNCONFIRMED"):
            break
        feedback = verdict_dict if verdict_dict else None

    verdict_final_dict = final_verdict if isinstance(final_verdict, dict) else {}
    dec = verdict_final_dict.get("decision", "UNCONFIRMED").upper()
    return {
        "entry_id": flow_id,
        "project": entry.get("project"),
        "repo_url": entry.get("repo_url"),
        "commit": entry.get("commit"),
        "title": entry.get("vuln_title"),
        "cwe": hypothesis.get("cwe"),
        "decision": dec,
        "rounds": used_rounds,
        "reason": verdict_final_dict.get("reason", ""),
        "pov_script": str(host_pov_script),
        "pov_result": str(host_pov_result),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


EDA_SUITE_ENTRIES = [
    "entry-00419",  # litellm: Business Logic / BL-AUTH-BYPASS (JWT cache key collision) - Cross-file
    "entry-00391",  # fastmcp: SSRF / Path Traversal (OpenAPIProvider) - Single-file
    "entry-00310",  # fastmcp: Business Logic / BL-ORIGIN-INTEGRITY (OAuthProxy audience) - Single-file
    "entry-00097",  # AutoGPT: Business Logic / BL-AGENT-CAPABILITY (Agent Boundary Bypass RCE) - Single-file
    "entry-00066",  # langchain-core: Template Injection / SSTI - Single-file
    "entry-00430",  # google/adk-python: Code Injection / Arbitrary Module Import - Cross-file
    "entry-00446",  # paperclipai/paperclip: Command Injection / OS Command Injection - Cross-file
    "entry-00319",  # nltk: Business Logic / BL-AUTHZ-MISSING (Server DoS) - Single-file
]

OVERNIGHT_PROJECTS = [
    "litellm", "fastmcp", "AutoGPT", "langchain", "adk-python",
    "paperclip", "nltk", "onnx", "mlflow", "langflow",
    "WeKnora", "airflow", "trivy"
]


def main():
    parser = argparse.ArgumentParser(description="Chạy kiểm chứng PoV Revelio (Builder -> Generator -> Verifier)")
    parser.add_argument("target", nargs="?", default="fastmcp", help="Tên repo (ví dụ: fastmcp, litellm, all)")
    parser.add_argument("--all", action="store_true", help="Chạy toàn bộ dataset entries.jsonl")
    parser.add_argument("--suite", choices=["eda", "fast", "overnight", "12h"], default=None, help="Chạy bộ mẫu: 'eda' (~30 phút) hoặc 'overnight' / '12h' (~10-12 tiếng)")
    parser.add_argument("--entry", default=None, help="Mã Entry cụ thể (ví dụ: entry-00419)")
    parser.add_argument("--rounds", type=int, default=3, help="Số vòng lặp tinh chỉnh tối đa cho mỗi entry (mặc định 3)")
    parser.add_argument("--config", default=None, help="Đường dẫn file config.yml")
    args = parser.parse_args()

    run_all = args.all or (args.target and args.target.lower() == "all")

    entries_file = root / "benchmark" / "vulngym" / "entries.jsonl"
    if not entries_file.exists():
        log.error(f"Entries file not found: {entries_file}")
        sys.exit(1)

    all_entries = []
    with open(entries_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                all_entries.append(json.loads(line))

    # Lọc danh sách mục tiêu
    selected_entries = []
    if args.suite in ("overnight", "12h"):
        for e in all_entries:
            p = e.get("project", "")
            if any(sp.lower() in p.lower() for sp in OVERNIGHT_PROJECTS):
                selected_entries.append(e)
    elif args.suite in ("eda", "fast"):
        suite_map = {e.get("entry_id"): e for e in all_entries}
        for eid in EDA_SUITE_ENTRIES:
            if eid in suite_map:
                selected_entries.append(suite_map[eid])
    else:
        for e in all_entries:
            p = e.get("project", "")
            u = e.get("repo_url", "")
            eid = e.get("entry_id", "")

            if args.entry:
                if eid == args.entry:
                    selected_entries.append(e)
                    break
            elif run_all:
                selected_entries.append(e)
            else:
                if args.target.lower() in p.lower() or args.target.lower() in u.lower():
                    selected_entries.append(e)

    if not selected_entries:
        log.error("Không tìm thấy entry nào phù hợp với điều kiện lọc.")
        sys.exit(1)

    # Gom nhóm theo commit để tránh clone/checkout và build lại nhiều lần
    grouped = OrderedDict()
    for e in selected_entries:
        key = (e.get("repo_url"), e.get("commit"), e.get("project"))
        grouped.setdefault(key, []).append(e)

    completed_state = load_completed()
    total_entries_count = len(selected_entries)
    
    print("\n" + "=" * 65)
    print("      REVELIO BATCH PoV RUNNER (BUILDER -> GENERATOR -> VERIFIER)")
    print("=" * 65)
    print(f"Chế độ chạy        : {'ALL (Toàn bộ entries)' if run_all else args.target}")
    print(f"Tổng số entries    : {total_entries_count}")
    print(f"Tổng số commits    : {len(grouped)}")
    print(f"Đã hoàn thành      : {len(completed_state)}")
    print(f"Báo cáo markdown   : {REPORT_MD}")
    print("=" * 65 + "\n")

    global_idx = 0
    import importlib
    fuzz_mod = importlib.import_module("src.fuzz-harness")

    for (url, commit, project), entries in grouped.items():
        # Kiểm tra xem tất cả entries trong commit này đã hoàn thành chưa
        pending_entries = [e for e in entries if e.get("entry_id") not in completed_state]
        if not pending_entries:
            log.info(f"Skipping completed commit: {project} @ {commit[:8]} ({len(entries)} entries)")
            global_idx += len(entries)
            continue

        repo_name = url.rstrip("/").split("/")[-1]
        repo_dir = root / "benchmark" / "vulngym" / "repos" / repo_name

        try:
            # 1. Clone & Checkout
            clone_and_checkout(url, commit, repo_dir)

            # 2. Setup Sandbox
            commit_out = OUTPUTS_ROOT / f"{project}_{commit[:8]}"
            commit_out.mkdir(parents=True, exist_ok=True)
            container = sandbox_init(repo_path=str(repo_dir), outputs_path=str(commit_out))

            # 3. Detect Harness
            harness_data = fuzz_mod.check(repo_dir, commit_out)

            # 4. Tác tử Builder: Build repo một lần cho toàn bộ commit này
            log.info(f"\n[BUILDER] Đang thiết lập môi trường cho {project} @ {commit[:8]}...")
            builder_agent = RepoBuilderAgent(sandbox=container, config_path=args.config)
            build_res = builder_agent.run("/data")
            log.info(f"[BUILDER] Kết quả: {build_res}")

            # 5. Chạy từng entry
            for entry in pending_entries:
                global_idx += 1
                eid = entry.get("entry_id")
                entry_out = OUTPUTS_ROOT / eid
                entry_out.mkdir(parents=True, exist_ok=True)

                # Cập nhật volume outputs cho container về thư mục của entry
                container = sandbox_init(repo_path=str(repo_dir), outputs_path=str(entry_out))

                print(f"\n>>> [{global_idx}/{total_entries_count}] Đang xử lý: {eid} ({project})")
                rec = evaluate_entry(
                    entry=entry,
                    container=container,
                    outputs_dir=entry_out,
                    max_rounds=args.rounds,
                    config_path=args.config,
                    harness_data=harness_data,
                )
                save_record(rec)
                completed_state[eid] = rec
                print(f"[+] Hoàn thành {eid}: {rec['decision']}")

        except Exception as e:
            log.error(f"Lỗi khi xử lý {project} @ {commit[:8]}: {e}", exc_info=True)
            continue

    print(f"\n[+] Tất cả các mục tiêu đã được xử lý xong! Xem báo cáo chi tiết tại: {REPORT_MD}")


if __name__ == "__main__":
    main()
