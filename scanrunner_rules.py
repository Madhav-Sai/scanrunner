"""Versioned protocol evidence contracts and conservative interpretation."""
from datetime import datetime, timezone
import re

VERSION = "1"
SPECS = {
    "rdp-enum-encryption": ("SR-RDP-NLA", "RDP accepts a security layer without NLA", {3389}, "tcp"),
    "ssl-enum-ciphers": ("SR-TLS-LEGACY", "Legacy TLS protocol or cipher requires review", {443, 465, 636, 993, 995, 8443}, "tcp"),
    "ssl-cert": ("SR-TLS-VALIDITY", "TLS certificate validity requires review", {443, 465, 636, 993, 995, 8443}, "tcp"),
    "ssh2-enum-algos": ("SR-SSH-ALGORITHMS", "Legacy SSH algorithms are offered", {22}, "tcp"),
    "ftp-anon": ("SR-FTP-ANONYMOUS", "Anonymous FTP authentication requires review", {21}, "tcp"),
    "dns-recursion": ("SR-DNS-RECURSION", "DNS recursion indication requires verification", {53}, "udp"),
    "sr-dns-recursion": ("SR-DNS-CONTROLLED", "Verified DNS recursion requires policy review", {53}, "udp"),
    "management-exposure": ("SR-MANAGEMENT-EXPOSURE", "Open management-associated port", {22, 23, 3389, 5985, 5986, 5900}, "tcp"),
}
RULES = {check: {"id": spec[0], "title": spec[1], "ports": spec[2], "transport": spec[3],
    "reference": "https://nmap.org/nsedoc/scripts/" + check + ".html",
    "version": VERSION, "compatibility": "Nmap structured XML and documented script output",
    "prerequisites": ["unique endpoint", "host up", "service open", "completed scan", "associated check output"],
    "counterexamples": ["open port alone", "missing check output", "failed negotiation", "contradictory evidence"],
    "limitations": "Time-bound control observation requiring analyst impact and applicability review"}
    for check, spec in SPECS.items()}
RULES["management-exposure"]["reference"] = "https://nmap.org/book/man-port-scanning-basics.html"
RULES["sr-dns-recursion"]["reference"] = "https://www.rfc-editor.org/rfc/rfc1035"
RULES["sr-dns-recursion"]["compatibility"] = "ScanRunner controlled DNS wire transcript schema 1"


def elements(node):
    return [child.get("text", "").strip() for child in node.get("children", []) if child.get("tag") == "elem"]


def assess(observation):
    check = observation["check_id"]
    output = observation.get("output", "").strip()
    children = observation.get("structured", {}).get("children", [])
    if not output or re.search(r"\b(error|timeout|timed out|inconclusive)\b", output, re.I):
        return "Inconclusive", "Missing successful protocol evidence"
    if check == "management-exposure":
        return "Exposure", "Observed open management-associated port, with applicability undetermined"
    if check == "rdp-enum-encryption":
        states = {}
        for line in output.splitlines():
            match = re.fullmatch(r"\s*(Native RDP|SSL|CredSSP \(NLA\)):\s*(SUCCESS|FAILED \(HYBRID_REQUIRED_BY_SERVER\))\s*", line)
            if match:
                states.setdefault(match[1], set()).add(match[2])
        if any(len(value) != 1 for value in states.values()):
            return "Inconclusive", "Contradictory RDP negotiation evidence"
        if any(states.get(layer) == {"SUCCESS"} for layer in ("Native RDP", "SSL")):
            return "Potential", "A non-NLA security layer was explicitly accepted"
        if (states.get("CredSSP (NLA)") == {"SUCCESS"} and all(states.get(layer) == {"FAILED (HYBRID_REQUIRED_BY_SERVER)"}
                for layer in ("Native RDP", "SSL"))):
            return "Not observed", "Both non-NLA layers explicitly rejected with NLA required"
        return "Inconclusive", "NLA support alone does not establish that NLA is required"
    if check == "ftp-anon":
        allowed = output.splitlines()[0] == "Anonymous FTP login allowed (FTP code 230)"
        denied = output == "Anonymous FTP login rejected (FTP code 530)"
        if allowed and "530" not in output:
            return "Potential", "Explicit successful anonymous authentication"
        if denied:
            return "Not observed", "Explicit anonymous authentication rejection"
        return "Inconclusive", "Authentication outcome is ambiguous"
    if check == "dns-recursion":
        return "Inconclusive", "NSE recursion flags require independent answer and nonrecursive control verification"
    if check == "sr-dns-recursion":
        if output == "Controlled recursion verified with matching canary answer and nonrecursive control":
            return "Potential", "Known canary resolved only with recursion requested"
        if output == "Controlled recursion rejected (DNS REFUSED)":
            return "Not observed", "The server explicitly refused both controlled queries"
        return "Inconclusive", "Controlled query evidence is insufficient"
    if check == "ssl-cert":
        validity = [node for node in children if node.get("key") == "validity"]
        if len(validity) != 1:
            return "Inconclusive", "A unique certificate validity interval is required"
        entries = validity[0].get("children", [])
        if len(entries) != 2 or {entry.get("key") for entry in entries} != {"notBefore", "notAfter"}:
            return "Inconclusive", "Malformed certificate validity interval"
        values = {entry["key"]: entry.get("text", "").strip() for entry in entries}
        try:
            times = [datetime.fromisoformat(values[key].replace("Z", "+00:00")) for key in ("notBefore", "notAfter")]
            before, after = [value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
                             for value in times]
            observed = datetime.fromisoformat(observation["observed_at"].replace("Z", "+00:00"))
            if observed.tzinfo is None or before >= after or any(value not in output for value in values.values()):
                raise ValueError("Invalid validity evidence")
        except (KeyError, TypeError, ValueError):
            return "Inconclusive", "Certificate times or observation time are missing or inconsistent"
        return ("Potential", "Certificate outside its validity interval at observation time") if not before <= observed <= after else (
            "Not observed", "Certificate within its validity interval, with chain and hostname validation unassessed")
    if check == "ssl-enum-ciphers":
        protocols = [node for node in children if (node.get("key") or "").startswith(("TLS", "SSL"))]
        if len({node["key"] for node in protocols}) != len(protocols):
            return "Inconclusive", "Duplicate TLS protocol evidence requires review"
        names = []
        for protocol in protocols:
            tables = [node for node in protocol.get("children", []) if node.get("key") == "ciphers"]
            if protocol.get("key") not in {"SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"} or len(tables) != 1:
                return "Inconclusive", "Unsupported TLS protocol structure"
            ciphers = [item for node in tables[0].get("children", []) for item in node.get("children", []) if item.get("key") == "name"]
            if not ciphers or protocol["key"] not in output:
                return "Inconclusive", "Missing negotiated cipher evidence"
            names.extend(item.get("text", "").strip() for item in ciphers)
        if not names or any(not re.fullmatch(r"TLS_[A-Z0-9_]+", name) or name not in output for name in names):
            return "Inconclusive", "Structured and displayed cipher evidence disagree"
        legacy = any(node["key"] in {"SSLv3", "TLSv1.0", "TLSv1.1"} for node in protocols)
        weak = any(re.search(r"_(RC4|3DES|DES|NULL|EXPORT)(?:_|$)", name) for name in names)
        return ("Potential", "A legacy protocol or selected weak cipher was accepted") if legacy or weak else (
            "Not observed", "Selected legacy protocols and cipher patterns absent from enumerated negotiations")
    groups = {node.get("key"): elements(node) for node in children if node.get("tag") == "table"}
    known_groups = {"kex_algorithms", "server_host_key_algorithms", "encryption_algorithms", "mac_algorithms", "compression_algorithms"}
    if any(key not in known_groups for key in groups):
        return "Inconclusive", "Unsupported SSH algorithm group"
    if len(groups) != len(children) or any(not values or any(value not in output for value in values) for values in groups.values()):
        return "Inconclusive", "Missing or inconsistent SSH algorithm lists"
    weak = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
            "ssh-dss", "arcfour", "arcfour128", "arcfour256", "3des-cbc", "hmac-md5", "hmac-md5-96"}
    if any(value in weak for values in groups.values() for value in values):
        return "Potential", "Explicitly offered algorithm is in the reviewed legacy policy"
    required = {"kex_algorithms", "server_host_key_algorithms", "encryption_algorithms", "mac_algorithms"}
    if not required <= groups.keys():
        return "Inconclusive", "A complete combined SSH policy listing is required for a negative assessment"
    strong = r"(?:curve25519-sha256(?:@libssh.org)?|ecdh-sha2-nistp(?:256|384|521)|diffie-hellman-group(?:14|16|18)-sha(?:256|512)|ssh-ed25519|rsa-sha2-(?:256|512)|ecdsa-sha2-nistp(?:256|384|521)|aes(?:128|192|256)-(?:ctr|gcm@openssh.com)|chacha20-poly1305@openssh.com|hmac-sha2-(?:256|512)(?:-etm@openssh.com)?|none|zlib@openssh.com)"
    if any(not re.fullmatch(strong, value) for values in groups.values() for value in values):
        return "Inconclusive", "Unreviewed SSH algorithm requires policy review"
    return "Not observed", "Reviewed legacy algorithms absent from the complete listed groups"
