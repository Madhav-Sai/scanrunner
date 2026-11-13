"""Offline scoring of production checks against supplied ground-truth labels."""
import argparse
import hashlib
import json
import math
import ipaddress
from pathlib import Path

import scanrunner_assessment as assessment
from scanrunner_findings import evaluate, RULE_VERSION


def ratio(numerator, denominator):
    if not denominator:
        return {"value": None, "denominator": 0, "wilson_95": None}
    probability = numerator / denominator
    z_squared = 1.96 ** 2
    center = (probability + z_squared / (2 * denominator)) / (1 + z_squared / denominator)
    width = 1.96 * math.sqrt(probability * (1 - probability) / denominator + z_squared / (4 * denominator ** 2)) / (1 + z_squared / denominator)
    return {"value": probability, "numerator": numerator, "denominator": denominator,
            "wilson_95": [max(0, center - width), min(1, center + width)]}


def counts_summary(counts):
    positive = counts["true_positive"] + counts["false_negative"] + counts["abstained_positive"]
    negative = counts["true_negative"] + counts["false_positive"] + counts["abstained_negative"]
    determinate = sum(counts[key] for key in ("true_positive", "false_positive", "true_negative", "false_negative"))
    return {**counts,
            "precision": ratio(counts["true_positive"], counts["true_positive"] + counts["false_positive"]),
            "operational_recall": ratio(counts["true_positive"], positive),
            "false_positive_rate": ratio(counts["false_positive"], counts["false_positive"] + counts["true_negative"]),
            "operational_false_positive_rate": ratio(counts["false_positive"], negative),
            "determinate_accuracy": ratio(counts["true_positive"] + counts["true_negative"], determinate),
            "correct_assessment_rate": ratio(counts["true_positive"] + counts["true_negative"], positive + negative),
            "negative_abstention_rate": ratio(counts["abstained_negative"], negative),
            "coverage": ratio(determinate, positive + negative)}


def benchmark(manifest_path, backend, destination=None):
    path = Path(manifest_path).resolve()
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("Benchmark manifest exceeds 32 MiB")
    manifest_bytes = path.read_bytes()
    dataset = json.loads(manifest_bytes)
    if not isinstance(dataset, dict) or dataset.get("schema_version") != 1 or dataset.get("dataset_kind") not in {"synthetic", "controlled-lab", "verified-outputs"}:
        raise ValueError("Dataset needs schema_version 1 and an explicit dataset_kind")
    cases = dataset.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 10000:
        raise ValueError("Benchmark needs between 1 and 10000 labeled cases")
    identifiers, subjects, results, counts = set(), set(), [], {}
    protected = {path}
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Each benchmark case must be a record")
        identifier = case.get("id")
        expected = case.get("expected")
        check_id = case.get("check_id")
        if not isinstance(check_id, str) or not check_id:
            raise ValueError("Each benchmark case needs a check_id")
        if not isinstance(case.get("artifact"), str) or not case["artifact"] or not isinstance(case.get("sha256"), str):
            raise ValueError("Each benchmark case needs an artifact path and SHA-256")
        ipaddress.ip_address(case.get("address", ""))
        if type(case.get("port")) is not int or not 0 <= case["port"] <= 65535 or case.get("transport") not in {"tcp", "udp", "sctp", "ip"}:
            raise ValueError("Each benchmark case needs an exact endpoint")
        if not isinstance(identifier, str) or not identifier.strip() or identifier in identifiers:
            raise ValueError("Case identifiers must be nonempty and unique")
        if expected not in {"positive", "negative"}:
            raise ValueError("Every case needs an independently determined positive or negative label")
        identifiers.add(identifier)
        proof = case.get("ground_truth", {})
        if not isinstance(proof, dict) or not all(isinstance(proof.get(field), str) and proof[field].strip() for field in ("reviewer", "method", "verified_at")):
            raise ValueError("Each ground-truth label needs a reviewer, verification method and time")
        assessment.parse_timestamp(proof["verified_at"])
        if dataset["dataset_kind"] != "synthetic":
            proof_path = path.parent / proof.get("artifact", "")
            protected.add(proof_path.resolve())
            if not proof.get("sha256") or backend.file_sha256(proof_path) != proof["sha256"]:
                raise ValueError("Ground-truth proof artifact hash is missing or incorrect")
        artifact = path.parent / case["artifact"]
        protected.add(artifact.resolve())
        digest = backend.file_sha256(artifact)
        if digest != case.get("sha256"):
            raise ValueError("Scanner artifact hash does not match the labeled case")
        subject = (digest, case.get("address"), case.get("port"), case.get("transport"), check_id)
        if subject in subjects:
            raise ValueError("Duplicate evidence/endpoint/check cases would inflate the sample count")
        subjects.add(subject)
        outcome, reason = "Inconclusive", "No associated supported observation"
        tool_versions = []
        try:
            hosts = assessment.normalize_artifact(backend, artifact, [case["address"]],
                                             {"id": "benchmark", "run_id": "benchmark"})
            tool_versions = sorted({host["tool_version"] for host in hosts})
            observations = [{**script, "addresses": [item["address"] for item in host["addresses"]],
                             "host_state": host["host_state"], "execution_outcome": host["execution_outcome"],
                             "source_tool": host["source_tool"],
                             "scan_completion": host["scan_completion"],
                             "service_state": next((service["state"] for service in host["services"]
                                                    if service["port"] == script["port"] and service["transport"] == script["transport"]), "Not determined")}
                            for host in hosts if any(item["address"] == case["address"] for item in host["addresses"])
                            for script in host["scripts"] if script["check_id"] == check_id
                            and script["port"] == case.get("port") and script["transport"] == case.get("transport")]
            if len(observations) == 1:
                evaluation = evaluate(observations[0])
                outcome, reason = evaluation["outcome"], evaluation["reason"]
        except (OSError, ValueError, backend.ET.ParseError) as error:
            reason = "Parser could not assess case: " + str(error)
        classifications = {
            "Potential": {"positive": "true_positive", "negative": "false_positive"},
            "Not observed": {"positive": "false_negative", "negative": "true_negative"},
            "Inconclusive": {"positive": "abstained_positive", "negative": "abstained_negative"},
        }
        category = classifications.get(outcome, classifications["Inconclusive"])[expected]
        rule_counts = counts.setdefault(check_id, {name: 0 for name in (
            "true_positive", "false_positive", "true_negative", "false_negative", "abstained_positive", "abstained_negative")})
        rule_counts[category] += 1
        results.append({"id": identifier, "check_id": check_id, "expected": expected, "actual": outcome,
                        "category": category, "reason": reason, "artifact_sha256": digest,
                        "scanner_versions_in_artifact": tool_versions})
        if backend.file_sha256(artifact) != digest:
            raise ValueError("Scanner artifact changed during measurement")
    if destination is not None:
        assessment.ensure_export_destination(destination)
        if Path(destination).resolve() in protected:
            raise ValueError("Benchmark output cannot replace its labeled dataset or evidence")
    return {"schema_version": 1, "dataset_kind": dataset["dataset_kind"], "dataset_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "parser_version": assessment.PARSER_VERSION, "cases": results,
            "rule_version": RULE_VERSION,
            "implementation_sha256": {name: backend.file_sha256(Path(__file__).with_name(name))
                                      for name in ("scanrunner.py", "scanrunner_assessment.py", "scanrunner_findings.py", "scanrunner_benchmark.py")},
            "per_check": {check_id: counts_summary(value) for check_id, value in counts.items()},
            "limitations": "Metrics describe the supplied labeled dataset. Ground-truth provenance is supplied by its reviewer. Tool execution coverage and environment representativeness require independent review. Positive abstentions count against operational recall."}


def cli(argv, backend):
    parser = argparse.ArgumentParser(prog="scanrunner benchmark")
    parser.add_argument("dataset")
    parser.add_argument("--destination", required=True)
    args = parser.parse_args(argv)
    result = benchmark(args.dataset, backend, args.destination)
    with backend.atomic_text(args.destination) as file:
        json.dump(result, file, indent=2)
    print(json.dumps(result, indent=2))
    return 0
