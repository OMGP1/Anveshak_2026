from __future__ import annotations

import hashlib
import json
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
WORDS_FILE = os.path.join(HERE, "english_words.txt")
OUT_FILE = os.path.join(HERE, "domain_bigrams.json")

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-^$"
START = "^"
END = "$"

DOMAIN_LABELS = [
    "www", "mail", "smtp", "imap", "pop", "ftp", "sftp", "ssh", "vpn", "proxy", "gateway",
    "router", "firewall", "dns", "ns1", "ns2", "resolver", "ntp", "time", "clock",
    "cdn", "edge", "static", "assets", "media", "img", "images", "video", "audio", "stream",
    "download", "downloads", "upload", "uploads", "files", "storage", "bucket", "archive",
    "api", "apis", "rest", "graphql", "rpc", "grpc", "webhook", "callback", "endpoint",
    "auth", "login", "signin", "signup", "account", "accounts", "identity", "sso", "oauth",
    "admin", "console", "dashboard", "portal", "panel", "manage", "control", "settings",
    "app", "apps", "web", "site", "sites", "page", "pages", "home", "index", "main",
    "blog", "news", "press", "media", "forum", "community", "support", "help", "docs",
    "documentation", "wiki", "kb", "faq", "guide", "tutorial", "learn", "training", "academy",
    "shop", "store", "cart", "checkout", "payment", "payments", "billing", "invoice", "order",
    "orders", "catalog", "product", "products", "pricing", "plans", "subscribe", "renew",
    "search", "find", "query", "lookup", "browse", "explore", "discover", "results",
    "chat", "message", "messages", "inbox", "notify", "notification", "alerts", "events",
    "calendar", "schedule", "booking", "reserve", "meeting", "conference", "webinar",
    "cloud", "compute", "server", "servers", "host", "hosting", "node", "cluster", "region",
    "zone", "datacenter", "rack", "metal", "container", "docker", "kube", "kubernetes",
    "registry", "repo", "repository", "git", "source", "build", "ci", "deploy", "release",
    "staging", "preview", "beta", "alpha", "canary", "test", "testing", "sandbox", "demo",
    "dev", "devel", "prod", "production", "live", "public", "private", "internal", "external",
    "secure", "safe", "trust", "verify", "validate", "certificate", "cert", "key", "keys",
    "vault", "secret", "secrets", "token", "session", "cookie", "cache", "redis", "queue",
    "broker", "stream", "kafka", "pipeline", "worker", "job", "jobs", "task", "tasks", "cron",
    "metrics", "monitor", "monitoring", "status", "health", "uptime", "trace", "tracing",
    "log", "logs", "logging", "audit", "report", "reports", "analytics", "insight", "insights",
    "data", "dataset", "warehouse", "lake", "table", "record", "records", "index", "backup",
    "restore", "snapshot", "mirror", "replica", "sync", "syncing", "transfer", "relay",
    "update", "updates", "patch", "upgrade", "install", "installer", "setup", "package",
    "packages", "module", "modules", "library", "plugin", "extension", "addon", "theme",
    "north", "south", "east", "west", "central", "global", "worldwide", "international",
    "europe", "america", "asia", "pacific", "atlantic", "nordic", "alpine", "coastal",
    "london", "paris", "berlin", "madrid", "dublin", "boston", "denver", "austin", "seattle",
    "portland", "phoenix", "dallas", "atlanta", "chicago", "toronto", "sydney", "tokyo",
    "delhi", "mumbai", "chennai", "bangalore", "pune", "hyderabad", "kolkata", "jaipur",
    "wind", "windy", "storm", "thunder", "lightning", "rain", "snow", "frost", "sunrise",
    "sunset", "dawn", "dusk", "twilight", "horizon", "summit", "peak", "valley", "canyon",
    "river", "creek", "brook", "lake", "ocean", "harbor", "haven", "bay", "cove", "shore",
    "stone", "rock", "granite", "marble", "slate", "quartz", "flint", "iron", "steel",
    "copper", "bronze", "silver", "golden", "platinum", "titanium", "cobalt", "nickel",
    "oak", "pine", "cedar", "maple", "birch", "aspen", "willow", "elm", "ash", "walnut",
    "grove", "forest", "woodland", "meadow", "prairie", "orchard", "garden", "field",
    "compass", "beacon", "lighthouse", "anchor", "sail", "voyage", "journey", "quest",
    "bridge", "arch", "tower", "spire", "keystone", "cornerstone", "foundation", "pillar",
    "vector", "matrix", "tensor", "scalar", "linear", "quantum", "atomic", "digital",
    "cyber", "crypto", "hash", "cipher", "signal", "channel", "spectrum", "bandwidth",
    "fiber", "optic", "copperline", "wireless", "mobile", "cellular", "satellite", "radar",
    "sensor", "device", "gadget", "widget", "circuit", "board", "chip", "silicon", "wafer",
    "swift", "rapid", "instant", "prime", "apex", "vertex", "nexus", "matrix", "core",
    "kernel", "shell", "stack", "heap", "buffer", "frame", "packet", "socket", "port",
    "trust", "shield", "guard", "sentinel", "warden", "custody", "escrow", "ledger",
    "clarity", "insight", "vision", "focus", "lens", "prism", "spectrum", "palette",
    "canvas", "sketch", "draft", "blueprint", "schema", "pattern", "template", "layout",
    "studio", "works", "labs", "forge", "foundry", "workshop", "atelier", "guild",
    "group", "team", "crew", "collective", "alliance", "partners", "ventures", "capital",
    "holdings", "systems", "solutions", "services", "consulting", "advisory", "agency",
    "digitalworks", "cloudworks", "dataworks", "netlabs", "codeforge", "bytestack",
    "northwind", "southridge", "eastgate", "westport", "highpoint", "brightline",
    "clearwater", "stonebridge", "ironwood", "silverleaf", "goldenpath", "bluesky",
    "greenfield", "redwood", "whitecliff", "blackstone", "graystone", "amberlight",
]


def normalise(label: str) -> str:
    body = "".join(c if c in ALPHABET and c not in (START, END) else "-" for c in label.lower())
    return START + body + END


def load_corpus() -> tuple[list[str], list[str]]:
    with open(WORDS_FILE, "r", encoding="ascii") as fh:
        words = [line.strip().lower() for line in fh if line.strip()]
    return words, [label.lower() for label in DOMAIN_LABELS]


def build() -> dict:
    words, labels = load_corpus()
    n = len(ALPHABET)
    index = {c: i for i, c in enumerate(ALPHABET)}
    counts = [[1.0] * n for _ in range(n)]
    observed = 0
    for text in words + labels:
        s = normalise(text)
        for a, b in zip(s, s[1:]):
            counts[index[a]][index[b]] += 1.0
            observed += 1
    logp = []
    for row in counts:
        total = sum(row)
        logp.append([round(math.log(v / total), 5) for v in row])
    with open(WORDS_FILE, "rb") as fh:
        words_hash = hashlib.sha256(fh.read()).hexdigest()
    labels_hash = hashlib.sha256("\n".join(labels).encode("ascii")).hexdigest()
    return {
        "version": "1.0.0",
        "alphabet": ALPHABET,
        "start_symbol": START,
        "end_symbol": END,
        "order": 2,
        "smoothing": "laplace add-one over the full 39x39 transition matrix",
        "score": "mean natural-log transition probability per bigram, including start and end",
        "corpus": {
            "english_words": {
                "file": "english_words.txt",
                "count": len(words),
                "sha256": words_hash,
                "origin": "bip-39 english wordlist, copied from the locally installed eth_account "
                          "package, public domain, no network access used",
            },
            "domain_labels": {
                "count": len(labels),
                "sha256": labels_hash,
                "origin": "enumerated by hand in build_bigrams.py from common hostname, service "
                          "and brand-shaped labels, no external corpus",
            },
            "bigrams_observed": observed,
        },
        "honesty_note": "this is not Tranco top-1M. it is a small locally generated corpus and it "
                        "separates algorithmic dga cleanly but not dictionary dga, see the dga "
                        "detector for how dictionary families are actually caught",
        "logp": logp,
    }


def main() -> None:
    model = build()
    with open(OUT_FILE, "w", encoding="ascii") as fh:
        json.dump(model, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote", OUT_FILE, "bigrams", model["corpus"]["bigrams_observed"])


if __name__ == "__main__":
    main()
