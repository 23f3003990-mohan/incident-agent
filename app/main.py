"""ga5-incident-agent/v2: persistent runs, receipt-driven state machine, OTLP trace from stored state."""
import asyncio, copy, json, logging, os, re, secrets, sqlite3, threading, time
from collections import defaultdict

from fastapi import FastAPI, Request
from fastapi.responses import Response

from .plan import PlannerError, canonical, content_key, plan, sha

logging.basicConfig(level=logging.INFO)
PROFILE = "ga5-incident-agent/v2"
DB_PATH = os.getenv("DB_PATH", "/srv/data/incidents.db")
os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
_db = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
_db.execute("PRAGMA journal_mode=WAL")
_db.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, req_hash TEXT NOT NULL, state TEXT NOT NULL)")
_db.execute("CREATE TABLE IF NOT EXISTS debug (id TEXT PRIMARY KEY, created REAL, body TEXT)")
_db.execute("CREATE TABLE IF NOT EXISTS plans (key TEXT PRIMARY KEY, body TEXT NOT NULL)")
DEBUG_KEY = os.getenv("DEBUG_KEY", "")
_dbl = threading.Lock()
_locks = defaultdict(asyncio.Lock)
TP_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
app = FastAPI(redirect_slashes=False, docs_url=None, redoc_url=None, openapi_url=None)


def load(rid):
    with _dbl:
        r = _db.execute("SELECT req_hash, state FROM runs WHERE id=?", (rid,)).fetchone()
    return (r[0], json.loads(r[1])) if r else (None, None)


def save(rid, req_hash, st):
    with _dbl:
        _db.execute("INSERT INTO runs(id, req_hash, state) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state",
                    (rid, req_hash, json.dumps(st)))


def hexid(n):
    while True:
        h = secrets.token_hex(n)
        if int(h, 16):
            return h


def sid(st, *parts):
    return parts[0] + "_" + sha(st["runId"] + "|" + "|".join(parts))[:20]


def js(body, status=200, scrub=None):
    text = canonical(body)
    for s in scrub or []:
        if isinstance(s, str) and len(s) >= 6 and s in text:
            text = text.replace(s, "[REDACTED]")
    return Response(text, status_code=status, media_type="application/json")


def fail(status, code):
    return js({"error": {"code": code}}, status)


# ---------------- validation ----------------

def valid_create(b):
    if not isinstance(b, dict) or b.get("profile") != PROFILE:
        return False
    inc, cat, pol = b.get("incident"), b.get("toolCatalog"), b.get("policy")
    if not isinstance(b.get("runId"), str) or not b["runId"].strip() or not isinstance(inc, dict):
        return False
    if not isinstance(inc.get("transcript"), str) or not isinstance(inc.get("allowedRootCauses"), list) \
            or not inc["allowedRootCauses"] or not all(isinstance(x, str) for x in inc["allowedRootCauses"]):
        return False
    if not isinstance(cat, list) or not cat or not all(isinstance(t, dict) and isinstance(t.get("name"), str) for t in cat):
        return False
    if len({t["name"] for t in cat}) != len(cat) or not isinstance(pol, dict):
        return False
    if not isinstance(pol.get("effectTools", []), list) or not isinstance(pol.get("approvalRequiredFor", []), list):
        return False
    if "sensitive" in b and not isinstance(b["sensitive"], dict):
        return False
    return True


def secrets_of(b):
    vals = []
    def walk(o):
        if isinstance(o, str):
            vals.append(o)
        elif isinstance(o, dict):
            [walk(v) for v in o.values()]
        elif isinstance(o, list):
            [walk(v) for v in o]
    walk(b.get("sensitive") or {})
    return vals


# ---------------- state machine ----------------

def new_dispatch(st, aid, now):
    a = st["actions"][aid]
    attempt = len(a["attempts"]) + 1
    span = hexid(8)
    d = {"actionId": aid, "callId": a["callId"], "phase": a["phase"], "toolName": a["toolName"],
         "arguments": a["arguments"], "evidence": a["evidence"], "attempt": attempt,
         "traceparent": f"00-{st['trace']['traceId']}-{span}-01"}
    if st["trace"].get("tracestate"):
        d["tracestate"] = st["trace"]["tracestate"]
    if a.get("approvalId"):
        d["approvalId"] = a["approvalId"]
        d["approvalNonce"] = st["approval"]["nonce"]
    a["attempts"].append({"attempt": attempt, "spanId": span, "start": now, "end": None, "receipt": None})
    a["status"] = "pending"
    st["actionLog"].append(d)
    return d


def advance(st, now):
    """After diagnostics resolve: dispatch effect, request approval, or finish."""
    diags = [st["actions"][x] for x in st["diagIds"]]
    if any(a["status"] == "pending" for a in diags):
        return [], []
    eff = st["actions"][st["effectId"]]
    if any(a["status"] == "failed" for a in diags):
        st["status"] = "failed"
        st["suppressed"] = [{"actionId": st["effectId"], "toolName": eff["toolName"], "reason": "prerequisite_failed"}]
        return [], []
    if eff["status"] == "planned":
        if eff["toolName"] in st["approvalRequiredFor"] and not st.get("approval"):
            st["approval"] = {"approvalId": sid(st, "apr", st["effectId"]), "actionId": st["effectId"],
                              "toolName": eff["toolName"], "argumentsDigest": sha(canonical(eff["arguments"])),
                              "state": "pending", "requestedAt": now}
            st["status"] = "waiting"
            return [], [public_approval(st["approval"])]
        if eff["toolName"] in st["approvalRequiredFor"] and st["approval"]["state"] != "approved":
            return [], [public_approval(st["approval"])]
        st["status"] = "waiting"
        return [new_dispatch(st, st["effectId"], now)], []
    if eff["status"] in ("ok", "failed"):
        st["status"] = "completed" if eff["status"] == "ok" else "failed"
    return [], []


def public_approval(a):
    return {k: a[k] for k in ("approvalId", "actionId", "toolName", "argumentsDigest")}


def apply_receipt(st, body, now):
    """Validate the whole receipt first; return (dispatches, approvals) or raise ValueError."""
    outs, apps = body.get("outcomes"), body.get("approvals")
    if (outs is None) == (apps is None):
        raise ValueError("receipt must carry outcomes or approvals")
    rid = body["receiptId"]
    if outs is not None:
        if not isinstance(outs, list) or not outs:
            raise ValueError("outcomes")
        seen = set()
        for o in outs:
            if not isinstance(o, dict):
                raise ValueError("outcome")
            a = st["actions"].get(o.get("actionId"))
            if not a or a["status"] != "pending" or o.get("callId") != a["callId"] \
                    or o.get("attempt") != len(a["attempts"]) or o["actionId"] in seen:
                raise ValueError("outcome does not match a pending call")
            if not isinstance(o.get("status"), int) or isinstance(o.get("status"), bool):
                raise ValueError("status")
            seen.add(o["actionId"])
        dispatches = []
        for o in outs:
            a = st["actions"][o["actionId"]]
            att = a["attempts"][-1]
            rec = {"receiptId": rid, "actionId": o["actionId"], "callId": o["callId"], "attempt": o["attempt"],
                   "status": o["status"]}
            for k in ("resultClass", "errorType", "nonce"):
                if k in o:
                    rec[k] = o[k]
            att["receipt"], att["end"] = rec, now
            st["receiptLog"].append(rec)
            if 200 <= o["status"] < 300:
                a["status"] = "ok"
            elif o["status"] == 503 and att["attempt"] == 1:
                dispatches.append(new_dispatch(st, o["actionId"], now))
            else:
                a["status"] = "failed"
        if dispatches:  # a retry response never carries an approval request
            st["status"] = "waiting"
            return dispatches, []
        if st["actions"][st["effectId"]]["status"] in ("ok", "failed"):
            st["status"] = "completed" if st["actions"][st["effectId"]]["status"] == "ok" else "failed"
            return [], []
        return advance(st, now)
    # approvals
    ap = st.get("approval")
    if not isinstance(apps, list) or len(apps) != 1 or not ap or ap["state"] != "pending":
        raise ValueError("no pending approval")
    a = apps[0]
    if not isinstance(a, dict) or a.get("approvalId") != ap["approvalId"] \
            or a.get("decision") not in ("approved", "denied", "rejected") or not isinstance(a.get("nonce"), str):
        raise ValueError("approval mismatch")
    rec = {"receiptId": rid, "approvalId": a["approvalId"], "decision": a["decision"], "nonce": a["nonce"]}
    st["receiptLog"].append(rec)
    ap.update(state="approved" if a["decision"] == "approved" else "denied", nonce=a["nonce"],
              receiptId=rid, decidedAt=now)
    if ap["state"] != "approved":
        eff = st["actions"][st["effectId"]]
        eff["status"] = "failed"
        st["status"] = "failed"
        st["suppressed"] = [{"actionId": st["effectId"], "toolName": eff["toolName"], "reason": "approval_denied"}]
        return [], []
    st["actions"][st["effectId"]]["approvalId"] = ap["approvalId"]
    st["status"] = "waiting"
    return [new_dispatch(st, st["effectId"], now)], []


# ---------------- OTLP ----------------

def attr(k, v):
    if isinstance(v, bool):
        return {"key": k, "value": {"boolValue": v}}
    if isinstance(v, int):
        return {"key": k, "value": {"intValue": v}}
    return {"key": k, "value": {"stringValue": str(v)}}


def otlp(st):
    t = st["trace"]
    base = [attr("ga5.run.id", st["runId"]), attr("ga5.public.marker", st["marker"])]
    end_all = st.get("finishedAt") or time.time_ns()

    def span(span_id, parent, name, kind, start, end, attrs, status=None, links=None, trace_state=None):
        s = {"traceId": t["traceId"], "spanId": span_id, "name": name, "kind": kind,
             "startTimeUnixNano": str(start), "endTimeUnixNano": str(max(end, start)),
             "attributes": base + attrs, "status": status or {"code": 0}}
        if parent:
            s["parentSpanId"] = parent
        if links:
            s["links"] = links
        if trace_state:
            s["traceState"] = trace_state
        return s

    spans = [
        span(t["serverSpanId"], t.get("parentSpanId"), "POST /v2/incidents", 2, st["createdAt"], st["respondedAt"],
             [attr("http.request.method", "POST"), attr("http.route", "/v2/incidents"), attr("http.response.status_code", 200)],
             trace_state=t.get("tracestate")),
        span(t["agentSpanId"], t["serverSpanId"], f"invoke_agent {st['agentName']}", 1, st["createdAt"], end_all,
             [attr("gen_ai.operation.name", "invoke_agent"), attr("gen_ai.agent.name", st["agentName"])]),
    ]
    ch = st["chat"]
    chat_attrs = [attr("gen_ai.operation.name", "chat"), attr("gen_ai.request.model", ch["model"])]
    if ch.get("responseModel"):
        chat_attrs.append(attr("gen_ai.response.model", ch["responseModel"]))
    if isinstance(ch.get("inTokens"), int):
        chat_attrs.append(attr("gen_ai.usage.input_tokens", ch["inTokens"]))
    if isinstance(ch.get("outTokens"), int):
        chat_attrs.append(attr("gen_ai.usage.output_tokens", ch["outTokens"]))
    chat_status = {"code": 0}
    if ch.get("error"):
        chat_attrs.append(attr("error.type", ch["error"]))
        chat_status = {"code": 2}
    spans.append(span(t["chatSpanId"], t["agentSpanId"], "chat incident-plan", 3, ch["start"], ch["end"], chat_attrs,
                      status=chat_status))

    links = []
    for aid in st["diagIds"] + [st["effectId"]]:
        a = st["actions"][aid]
        if not a["attempts"]:
            continue
        a_end = max((x["end"] or end_all) for x in a["attempts"])
        spans.append(span(a["execSpanId"], t["agentSpanId"], f"execute_tool {a['toolName']}", 1, a["attempts"][0]["start"],
                          a_end, [attr("ga5.action.id", aid), attr("gen_ai.tool.name", a["toolName"]),
                                  attr("gen_ai.tool.call.id", a["callId"]), attr("gen_ai.operation.name", "execute_tool")],
                          status={"code": 2} if a["status"] == "failed" else {"code": 0}))
        if aid in st["diagIds"]:
            links.append({"traceId": t["traceId"], "spanId": a["execSpanId"]})
        for x in a["attempts"]:
            r = x["receipt"] or {}
            at = [attr("ga5.action.id", aid), attr("ga5.attempt", x["attempt"]), attr("http.request.method", "POST"),
                  attr("http.request.resend_count", x["attempt"] - 1), attr("gen_ai.tool.call.id", a["callId"])]
            if r:
                at += [attr("ga5.receipt.id", r["receiptId"]), attr("ga5.receipt.nonce", r.get("nonce", ""))]
            stt = {"code": 0}
            code = r.get("status")
            if isinstance(code, int) and code > 0:
                at.append(attr("http.response.status_code", code))
                if not 200 <= code < 300:
                    at.append(attr("error.type", str(code)))
                    stt = {"code": 2}
            elif r:
                at.append(attr("error.type", r.get("errorType") or "timeout"))
                stt = {"code": 2}
            spans.append(span(x["spanId"], a["execSpanId"], f"POST tool/{a['toolName']}", 3, x["start"],
                              x["end"] or end_all, at, status=stt))
    if len(st["diagIds"]) > 1:
        d_end = max(((x["end"] or end_all) for aid in st["diagIds"] for x in st["actions"][aid]["attempts"]), default=end_all)
        spans.append(span(t["joinSpanId"], t["agentSpanId"], "incident.join", 1, d_end, d_end,
                          [attr("ga5.join.count", len(st["diagIds"]))], links=links))
    ap = st.get("approval")
    if ap:
        at = [attr("ga5.approval.id", ap["approvalId"]), attr("ga5.action.id", ap["actionId"]),
              attr("gen_ai.tool.name", ap["toolName"])]
        if ap.get("nonce"):
            at += [attr("ga5.approval.nonce", ap["nonce"]), attr("ga5.receipt.nonce", ap["nonce"]),
                   attr("ga5.receipt.id", ap["receiptId"]), attr("ga5.approval.decision", ap["state"])]
        spans.append(span(t["gateSpanId"], t["agentSpanId"], "approval_gate", 1, ap["requestedAt"],
                          ap.get("decidedAt") or end_all, at))
    return {"resourceSpans": [{"resource": {"attributes": [attr("service.name", "incident-agent"),
                                                            attr("ga5.run.id", st["runId"])]},
                               "scopeSpans": [{"scope": {"name": "ga5-incident-agent", "version": "1.0.0"},
                                               "spans": spans}]}]}


def view(st, dispatches=None, approvals=None):
    out = {"runId": st["runId"], "status": st["status"], "diagnosis": st["diagnosis"]}
    if st["status"] == "waiting":
        if dispatches is None:  # GET: show what is currently pending
            dispatches = [st["actionLog"][i] for i in range(len(st["actionLog"]))
                          if st["actions"][st["actionLog"][i]["actionId"]]["status"] == "pending"
                          and st["actionLog"][i]["attempt"] == len(st["actions"][st["actionLog"][i]["actionId"]]["attempts"])]
            ap = st.get("approval")
            approvals = [public_approval(ap)] if ap and ap["state"] == "pending" else []
        out.update(dispatches=dispatches, approvals=approvals or [],
                   actionLog=st["actionLog"], receiptLog=st["receiptLog"])
    else:
        out.update(chosenEffect=st["actions"][st["effectId"]]["toolName"], suppressed=st.get("suppressed", []),
                   actionLog=st["actionLog"], receiptLog=st["receiptLog"], dispatches=[], approvals=[], otlp=otlp(st))
    return out


# ---------------- routes ----------------

def strip(p):
    return "/" + p.strip("/")


@app.api_route("/{path:path}", methods=["GET", "HEAD", "POST"])
async def route(path: str, request: Request):
    p = strip(path)
    if request.method == "GET" and p == "/_selftest":
        return await selftest()
    if request.method == "GET" and p.startswith("/_debug"):
        return debug_view(p, request)
    if request.method in ("GET", "HEAD"):
        m = re.fullmatch(r"/v2/incidents/([^/]+)", p)
        if not m:
            return js({"status": "ok", "profile": PROFILE})
        _, st = load(m.group(1))
        if not st:
            return fail(404, "RUN_NOT_FOUND")
        return js(st["lastView"], scrub=st.get("scrub"))
    raw = await request.body()
    if len(raw) > 4 * 1024 * 1024:
        return fail(413, "BODY_TOO_LARGE")
    try:
        body = json.loads(raw)
    except Exception:
        return fail(400, "INVALID_JSON")
    if p == "/v2/incidents":
        return await create(body, request)
    m = re.fullmatch(r"/v2/incidents/([^/]+)/receipts", p)
    if m:
        return await receipt(m.group(1), body)
    return fail(404, "NOT_FOUND")


async def create(b, request):
    if not valid_create(b):
        return fail(422 if isinstance(b, dict) and b.get("profile") == PROFILE else 400, "INVALID_REQUEST")
    rid, req_hash = b["runId"], sha(canonical(b))
    scrub = secrets_of(b)
    async with _locks[rid]:
        h, st = load(rid)
        if st:
            if h != req_hash:
                return fail(409, "RUN_CONFLICT")
            return js(st["createResponse"], scrub=scrub)
        now = time.time_ns()
        tp, ts = request.headers.get("traceparent", "").strip().lower(), request.headers.get("tracestate", "").strip()
        m = TP_RE.match(tp)
        trace = {"traceId": hexid(16), "parentSpanId": None, "tracestate": None}
        if m and int(m.group(1), 16) and int(m.group(2), 16) and m.group(3) != "ff":
            trace = {"traceId": m.group(1), "parentSpanId": m.group(2), "tracestate": ts or None}
        trace.update(serverSpanId=hexid(8), agentSpanId=hexid(8), chatSpanId=hexid(8), joinSpanId=hexid(8),
                     gateSpanId=hexid(8))
        inc = b["incident"]
        ckey = content_key(inc, b["toolCatalog"], b["policy"])
        try:
            pl, tele = await plan({k: inc[k] for k in inc}, b["toolCatalog"], b["policy"])
            with _dbl:
                _db.execute("INSERT OR REPLACE INTO plans(key, body) VALUES(?,?)", (ckey, json.dumps(pl)))
        except Exception as e:
            reason = str(e) if isinstance(e, PlannerError) else type(e).__name__
            with _dbl:
                row = _db.execute("SELECT body FROM plans WHERE key=?", (ckey,)).fetchone()
            if not row:
                logging.error("planning failed, no cached plan: %s", reason)
                return js({"error": {"code": "PLANNER_UNAVAILABLE", "reason": reason}}, 503)
            logging.warning("planning failed (%s); using cached plan for identical incident content", reason)
            pl = json.loads(row[0])
            tele = dict(getattr(e, "tele", None) or {"model": os.getenv("LLM_MODEL", "gpt-4.1-mini"),
                                                     "start": now, "end": time.time_ns()})
            tele.pop("_raw", None)
            tele["error"] = reason.split(":")[0]
        raw_model = tele.pop("_raw", None)
        if DEBUG_KEY:  # synthetic exam data only; sensitive object is never stored
            with _dbl:
                _db.execute("INSERT OR REPLACE INTO debug(id, created, body) VALUES(?,?,?)", (rid, time.time(), json.dumps(
                    {"incident": inc, "toolCatalog": b["toolCatalog"], "policy": {k: v for k, v in b["policy"].items() if k != "doNotExport"},
                     "modelOutput": raw_model, "plan": pl})))
        st = {"runId": rid, "marker": str(b.get("publicMarker", "")), "agentName": str(b.get("agentName") or "incident-response"),
              "trace": trace, "createdAt": now, "chat": tele, "scrub": scrub,
              "approvalRequiredFor": b["policy"].get("approvalRequiredFor", []),
              "diagnosis": {"rootCause": pl["rootCause"], "evidence": pl["evidence"]},
              "actions": {}, "diagIds": [], "actionLog": [], "receiptLog": [], "receipts": {}, "status": "waiting"}
        for i, d in enumerate(pl["diagnostics"]):
            aid = sid(st, "act", "diag", str(i))
            st["actions"][aid] = {"phase": "diagnostic", "callId": sid(st, "call", "diag", str(i)), "toolName": d["toolName"],
                                  "arguments": d["arguments"], "evidence": d["evidence"], "execSpanId": hexid(8),
                                  "attempts": [], "status": "planned"}
            st["diagIds"].append(aid)
        st["effectId"] = sid(st, "act", "effect")
        e = pl["effect"]
        st["actions"][st["effectId"]] = {"phase": "effect", "callId": sid(st, "call", "effect"), "toolName": e["toolName"],
                                         "arguments": e["arguments"], "evidence": e["evidence"], "execSpanId": hexid(8),
                                         "attempts": [], "status": "planned"}
        t = time.time_ns()
        dispatches = [new_dispatch(st, aid, t) for aid in st["diagIds"]]
        st["respondedAt"] = time.time_ns()
        v = view(st, dispatches, [])
        st["createResponse"] = v
        st["lastView"] = v
        save(rid, req_hash, st)
        return js(v, scrub=scrub)


async def receipt(rid, b):
    if not isinstance(b, dict) or not isinstance(b.get("receiptId"), str) or not b["receiptId"].strip():
        return fail(422, "INVALID_RECEIPT")
    async with _locks[rid]:
        h, st = load(rid)
        if not st:
            return fail(404, "RUN_NOT_FOUND")
        rh = sha(canonical(b))
        prev = st["receipts"].get(b["receiptId"])
        if prev:
            if prev["hash"] != rh:
                return fail(409, "RECEIPT_CONFLICT")
            return js(prev["response"], scrub=st.get("scrub"))
        if st["status"] != "waiting":
            return fail(409, "RUN_NOT_WAITING")
        work = copy.deepcopy(st)
        now = time.time_ns()
        try:
            dispatches, approvals = apply_receipt(work, b, now)
        except ValueError:
            return fail(422, "INVALID_STATE_CHANGE")
        if work["status"] != "waiting":
            work["finishedAt"] = time.time_ns()
        v = view(work, dispatches, approvals)
        work["receipts"][b["receiptId"]] = {"hash": rh, "response": v}
        work["lastView"] = v
        save(rid, h, work)
        return js(v, scrub=work.get("scrub"))


async def selftest():
    """Runs the planner on a tiny synthetic incident (no state stored) to check model access."""
    inc = {"incidentId": "selftest", "title": "Checkout errors", "service": "checkout", "severity": "SEV-2",
           "transcript": "[ev_1] 10:02 checkout 5xx rate jumped to 40%\n[ev_2] 10:01 deployment dep-77 rolled out to "
                         "checkout\n[ev_3] lunch menu updated\n[ev_4] errors only on pods running dep-77",
           "allowedRootCauses": ["bad_deployment", "capacity_exhaustion", "dependency_outage"]}
    cat = [{"name": "get_deployment", "description": "Details of a deployment", "inputSchema": {"type": "object",
            "properties": {"deploymentId": {"type": "string"}}, "required": ["deploymentId"]}},
           {"name": "rollback_deployment", "description": "Roll back a deployment", "inputSchema": {"type": "object",
            "properties": {"service": {"type": "string"}, "deploymentId": {"type": "string"}}, "required": ["service", "deploymentId"]}},
           {"name": "page_owner", "description": "Page the owner", "inputSchema": {"type": "object",
            "properties": {"service": {"type": "string"}}, "required": ["service"]}}]
    pol = {"maximumDiagnostics": 3, "effectTools": ["rollback_deployment", "page_owner"], "approvalRequiredFor": ["rollback_deployment"]}
    t = time.time()
    try:
        pl, tele = await plan(inc, cat, pol)
        return js({"ok": True, "seconds": round(time.time() - t, 2), "model": tele["model"], "plan": pl})
    except Exception as e:
        return js({"ok": False, "seconds": round(time.time() - t, 2), "reason": str(e) or type(e).__name__}, 503)


def debug_view(p, request):
    if not DEBUG_KEY or request.query_params.get("key") != DEBUG_KEY:
        return fail(404, "NOT_FOUND")
    rid = p[len("/_debug"):].strip("/")
    with _dbl:
        if not rid:
            rows = _db.execute("SELECT id, created, body FROM debug ORDER BY created DESC LIMIT 30").fetchall()
            return js({"runs": [{"runId": r[0], "title": json.loads(r[2])["incident"].get("title"),
                                 "plan": json.loads(r[2])["plan"]} for r in rows]})
        r = _db.execute("SELECT body FROM debug WHERE id=?", (rid,)).fetchone()
    return js(json.loads(r[0])) if r else fail(404, "NOT_FOUND")
