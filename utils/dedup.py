def dedup(flows):
    clusters = {}
    for f in flows:
        sink = f.get("sink", {}) or {}
        key = f"{sink.get('file')}:{sink.get('func')}:{sink.get('line')}"
        if key not in clusters:
            clusters[key] = f
    return list(clusters.values())


def _parse_line(val):
    if val is None:
        return None
    if isinstance(val, int):
        return val
    s = str(val).strip()
    digits = "".join(c for c in s if c.isdigit())
    return int(digits) if digits else None


def combine(flows):
    flat_flows = []
    for f in flows:
        if "primary_vector" in f and isinstance(f["primary_vector"], dict):
            sink = f.get("sink", {}) or {}
            pv = dict(f["primary_vector"])
            pv["sink"] = sink
            for meta_k in ("verdict", "confidence", "title", "cwe"):
                if meta_k in f and meta_k not in pv:
                    pv[meta_k] = f[meta_k]
            flat_flows.append(pv)
            for av in f.get("alternative_vectors", []):
                if isinstance(av, dict):
                    av_item = dict(av)
                    av_item["sink"] = sink
                    flat_flows.append(av_item)
        else:
            flat_flows.append(f)

    clusters = {}
    for f in flat_flows:
        sink = f.get("sink", {}) or {}
        file_val = str(sink.get("file") or "").strip()
        line_val = _parse_line(sink.get("line"))
        func_val = str(sink.get("func") or "").strip()
        var_val = str(sink.get("variable") or "").strip()

        key = (file_val, line_val, func_val)
        vector = {
            "id": f.get("id", ""),
            "source": f.get("source", {}) or {},
            "chain": f.get("chain", []) or []
        }
        if f.get("transforms"):
            vector["transforms"] = f.get("transforms")
        if f.get("confidence") is not None:
            vector["confidence"] = f.get("confidence")
        if f.get("verdict"):
            vector["verdict"] = f.get("verdict")

        if key not in clusters:
            clusters[key] = {
                "sink": {
                    "file": file_val,
                    "line": line_val,
                    "func": func_val,
                    "variable": var_val
                },
                "vectors": []
            }
        elif not clusters[key]["sink"].get("variable") and var_val:
            clusters[key]["sink"]["variable"] = var_val

        clusters[key]["vectors"].append(vector)

    cluster_list = list(clusters.values())

    combined = []
    for idx, item in enumerate(cluster_list, 1):
        if not item["vectors"]:
            continue
        pv = item["vectors"][0]
        alts = item["vectors"][1:]
        combined.append({
            "id": f"CT{idx:02d}",
            "sink": item["sink"],
            "source": pv.get("source", {}) or {},
            "chain": pv.get("chain", []) or [],
            "verdict": pv.get("verdict", "BENIGN"),
            "confidence": pv.get("confidence", 0.1),
            "primary_vector": pv,
            "alternative_vectors": alts
        })

    return combined


SAFE_FUNCS = {
    "isinstance", "issubclass", "len", "type", "repr", "id", "callable",
    "hasattr", "getattr", "setattr", "sys.version", "format", "strip",
    "split", "join", "replace", "lower", "upper", "startswith", "endswith",
    "int", "float", "bool", "list", "dict", "set", "tuple", "range",
    "enumerate", "zip", "min", "max", "abs", "sum", "round",
    "Exception", "ValueError", "TypeError", "KeyError", "IndexError",
    "RuntimeError", "StopIteration", "super", "super.__setitem__",
    "logging.basicConfig", "logging.getLogger", "logger.debug", "logger.info",
    "print", "sys.exit", "encode", "decode", "items", "keys", "values",
    "append", "extend", "pop", "insert", "clear", "update", "rstrip", "lstrip",
    "sleep", "strftime", "datetime", "now", "utcnow", "basename", "dirname",
    "RawConfigParser", "ConfigParser", "ArgumentParser", "add_argument", "parse_args",
    "sizeof", "strlen", "isdigit", "isalpha", "isalnum", "isspace",
    "isupper", "islower", "toupper", "tolower", "abs", "labs",
    "strcmp", "strncmp", "memcmp", "atoi", "atol", "atof", "strchr",
    "strrchr", "strstr",
    "getClass", "equals", "hashCode", "toString", "valueOf", "length",
    "size", "isEmpty", "contains", "compareTo", "Math.abs", "Math.min",
    "typeof", "Array.isArray", "Object.keys", "Object.values",
    "Object.entries", "console.log", "console.debug", "console.info",
    "Boolean", "Number", "String", "parseInt", "parseFloat", "trim",
    "cap", "make", "new", "strings.EqualFold", "strings.Contains",
    "strings.HasPrefix", "strings.HasSuffix", "strings.TrimSpace",
    "is_array", "is_string", "is_int", "is_numeric", "is_bool", "is_null",
    "empty", "isset", "strtolower", "strtoupper", "strpos",
    "size_of", "align_of", "clone", "to_string", "is_empty", "unwrap",
    "GetType", "Math.Abs", "Math.Min", "Math.Max",
    "is_a?", "kind_of?", "nil?", "empty?", "to_s", "to_i"
}

DANGEROUS_STEMS = (
    "printf", "sprintf", "snprintf", "vsnprintf", "asprintf", "syslog",
    "free", "alloc", "malloc", "realloc", "calloc", "memcpy", "memmove",
    "strcpy", "strcat", "gets", "system", "exec", "popen", "spawn",
    "eval", "sql", "query", "cursor", "open", "read", "write", "unlink",
    "remove", "pickle", "yaml", "unserialize", "readobject"
)


def _clean_prod_paths(paths, is_non_prod_fn, limit=None):
    """Trim leading non-production steps from path chains, dedup, and sort shortest-first."""
    seen = set()
    cleaned = []
    for p in paths or []:
        if not isinstance(p, list) or not p:
            continue
        idx = 0
        while idx < len(p):
            step = str(p[idx])
            if ":" in step and is_non_prod_fn(step.split(":", 1)[0]):
                idx += 1
            else:
                break
        trimmed = p[idx:]
        if not trimmed:
            continue
        if any(":" in str(s) and is_non_prod_fn(str(s).split(":", 1)[0]) for s in trimmed):
            continue
        key = tuple(str(s) for s in trimmed)
        if key not in seen:
            seen.add(key)
            cleaned.append(trimmed)
    cleaned.sort(key=len)
    return cleaned[:limit] if limit is not None else cleaned


def filter(flows):
    import json
    from utils.skip import is_non_prod

    cleaned = []
    seen = {}
    for f in flows:
        if isinstance(f, str):
            try:
                f = json.loads(f)
            except Exception:
                continue
        if not isinstance(f, dict):
            continue

        src = f.get("src", {}) or {}
        dst = f.get("dst", {}) or {}
        func = str(src.get("func") or src.get("id") or "").strip()
        fn_lower = func.lower()
        raw_dst_file = str(dst.get("file") or "")
        dst_file = raw_dst_file.lower()

        if raw_dst_file and is_non_prod(raw_dst_file):
            continue

        orig_paths = f.get("paths") or []
        prod_paths = _clean_prod_paths(orig_paths, is_non_prod)
        if orig_paths and not prod_paths:
            continue
        if isinstance(orig_paths, list):
            f = {**f, "paths": prod_paths}

        is_dangerous = any(s in fn_lower for s in DANGEROUS_STEMS)
        is_internal = any(dst_file.endswith(ext) for ext in (".c", ".cpp", ".cc", ".h")) and (
            func.startswith(("fr_", "rad_", "rlm_", "eap_", "tls_", "pair_"))
            or any(func.endswith(p) for p in ("_exec", "_eval", "_send", "_recv", "_parse", "_alloc", "_free"))
        )

        if not is_dangerous and not is_internal:
            last_part = func.split(".")[-1]
            if func in SAFE_FUNCS or fn_lower in SAFE_FUNCS or last_part in SAFE_FUNCS or last_part.lower() in SAFE_FUNCS:
                continue

        key = (dst.get("file"), dst.get("line"), func)
        if key in seen:
            existing = seen[key]
            merged = _clean_prod_paths(
                list(existing.get("paths") or []) + list(prod_paths),
                is_non_prod,
            )
            existing["paths"] = merged
        else:
            seen[key] = f
            cleaned.append(f)

    return cleaned


def pending_files(flows_path, done_files=None):
    """Group filtered call-flows by file and return pending files."""
    import json
    from pathlib import Path
    from utils.skip import is_non_prod

    path = Path(flows_path)
    if not path.exists():
        return []

    done_norm = {str(f).replace("\\", "/").strip().lstrip("/") for f in (done_files or [])}
    counts = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        dst_f = str(obj.get("dst", {}).get("file") or "").replace("\\", "/").strip().lstrip("/")
        if not dst_f or is_non_prod(dst_f) or dst_f in done_norm:
            continue
        counts[dst_f] = counts.get(dst_f, 0) + 1

    pending = [
        {"file": fpath, "flow_count": cnt}
        for fpath, cnt in counts.items()
    ]
    pending.sort(
        key=lambda item: (
            0 if item["file"].startswith("src/") else 1,
            -item["flow_count"],
            item["file"],
        )
    )
    return pending


__all__ = ["dedup", "pending_files", "combine", "filter"]
