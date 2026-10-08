"""Summarise HAR captures: one line per (method, normalized path) with statuses, content types, query names."""
import json, re, sys, collections
from urllib.parse import urlsplit, parse_qsl

GT = "C:/Users/User/Documents/pengent_web_gt_schema_student_v1/vocechat_gt/"
HARS = ["auth.har", "localhost.har"]

def norm(path):
    segs = []
    for s in path.split("/"):
        if re.fullmatch(r"\d+", s):
            segs.append("{n}")
        elif re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", s):
            segs.append("{uuid}")
        else:
            segs.append(s)
    return "/".join(segs)

agg = collections.OrderedDict()
entries_out = []
for har in HARS:
    d = json.load(open(GT + har, encoding="utf-8"))
    for i, e in enumerate(d["log"]["entries"]):
        rq, rs = e["request"], e["response"]
        u = urlsplit(rq["url"])
        origin = f"{u.scheme}://{u.netloc}"
        key = (origin, rq["method"], norm(u.path))
        a = agg.setdefault(key, {"statuses": set(), "ct": set(), "q": set(), "n": 0, "files": set(),
                                 "rtypes": set(), "refs": set(), "first": None})
        a["statuses"].add(rs["status"])
        a["ct"].add((rs.get("content") or {}).get("mimeType", "").split(";")[0])
        a["q"].update(k for k, _ in parse_qsl(u.query, keep_blank_values=True))
        a["n"] += 1
        a["files"].add(har)
        a["rtypes"].add(e.get("_resourceType", ""))
        for h in rq["headers"]:
            if h["name"].lower() == "referer":
                a["refs"].add(h["value"])
        if a["first"] is None:
            a["first"] = (har, i)
        entries_out.append({
            "har": har, "idx": i, "method": rq["method"], "url": rq["url"], "status": rs["status"],
            "req_headers": {h["name"]: h["value"] for h in rq["headers"]},
            "req_body": (rq.get("postData") or {}).get("text"),
            "req_mime": (rq.get("postData") or {}).get("mimeType"),
            "resp_mime": (rs.get("content") or {}).get("mimeType"),
            "resp_body": ((rs.get("content") or {}).get("text") or "")[:4000],
            "resp_enc": (rs.get("content") or {}).get("encoding"),
            "rtype": e.get("_resourceType", ""),
            "started": e.get("startedDateTime"),
        })

for (origin, m, p), a in agg.items():
    print(f"{origin} {m:6} {p:60} st={sorted(a['statuses'])} ct={sorted(a['ct'])} q={sorted(a['q'])} n={a['n']} "
          f"files={sorted(a['files'])} rt={sorted(a['rtypes'])}")
json.dump(entries_out, open(sys.argv[1] if len(sys.argv) > 1 else "har_entries.json", "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
