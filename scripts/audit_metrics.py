"""Collect reproducible test counts and limited in-process line coverage offline."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import dis
import hashlib
import io
import json
from pathlib import Path
import sys
import time
import trace
import types
import unittest


def executable_lines(code):
    lines = {number for _, number in dis.findlinestarts(code) if number > 0}
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            lines.update(executable_lines(value))
    return lines


def metrics(repository, measure_coverage=False):
    sys.path.insert(0, str(repository))
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=0)
    def run_suite():
        suite = unittest.defaultTestLoader.discover(str(repository / "tests"))
        return runner.run(suite)
    started = time.monotonic()
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        if measure_coverage:
            tracer = trace.Trace(count=True, trace=False, ignoredirs=[sys.base_prefix])
            result = tracer.runfunc(run_suite)
        else:
            tracer = None
            result = run_suite()
    passed = result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped) - len(result.expectedFailures)
    measured = {"scheduled": result.testsRun, "passed": passed, "failures": len(result.failures),
                "errors": len(result.errors), "skipped": len(result.skipped),
                "skip_reasons": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
                "expected_failures": len(result.expectedFailures), "elapsed_seconds": round(time.monotonic() - started, 3),
                "failure_details": [{"test": test.id(), "traceback": detail} for test, detail in result.failures + result.errors]}
    measured["source_sha256"] = {name: hashlib.sha256((repository / name).read_bytes()).hexdigest()
                                for name in ("scanrunner.py", "scanrunner_lib/scanrunner_assessment.py", "scanrunner_lib/scanrunner_findings.py", "scanrunner_lib/scanrunner_benchmark.py", "install.py")
                                if (repository / name).is_file()}
    if tracer:
        coverage = {}
        for name in ("scanrunner.py", "scanrunner_lib/scanrunner_assessment.py", "install.py"):
            path = repository / name
            if not path.is_file():
                continue
            executable = executable_lines(compile(path.read_text(encoding="utf-8-sig"), str(path), "exec"))
            observed = {number for (filename, number), count in tracer.counts.items()
                        if count and Path(filename).resolve() == path.resolve()}
            coverage[name] = {"executed_lines": len(observed & executable), "executable_lines": len(executable),
                              "percent": round(100 * len(observed & executable) / len(executable), 2)}
        measured["in_process_line_coverage"] = coverage
        measured["coverage_limitations"] = "Stdlib trace counts the test process only. Scanner CLI subprocesses are tested but their line coverage is excluded. This is not full-suite branch coverage."
    return measured


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--coverage", action="store_true")
    args = parser.parse_args()
    result = metrics(args.repo.resolve(), args.coverage)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    raise SystemExit(1 if result["failures"] or result["errors"] else 0)
