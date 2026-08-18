from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from lxml import etree

_XSD_PATH = Path(__file__).resolve().parent.parent / 'schemas' / 'junit.xsd'
_SAFE_PARSER = etree.XMLParser(resolve_entities=False, no_network=True)


class ResultValidationError(Exception):
    pass


@dataclass
class MergeResult:
    total_tests: int
    failures: int
    errors: int
    skipped: int
    time: float


def _load_xsd() -> etree.XMLSchema:
    return etree.XMLSchema(etree.parse(str(_XSD_PATH)))


def _parse_and_validate(path: str, schema: etree.XMLSchema) -> etree._ElementTree:
    try:
        doc = etree.parse(path, parser=_SAFE_PARSER)
    except etree.XMLSyntaxError as exc:
        raise ResultValidationError(f"Malformed XML in {path}: {exc}") from exc

    if not schema.validate(doc):
        errors = "; ".join(str(e) for e in schema.error_log)
        raise ResultValidationError(f"XSD validation failed for {path}: {errors}")

    return doc


def validate_junit_xml(path: str) -> None:
    _parse_and_validate(path, _load_xsd())


def merge_results(
    result_paths: list[str],
    output_path: str,
    instance_labels: list[str] | None = None,
) -> MergeResult:
    if instance_labels is not None and len(instance_labels) != len(result_paths):
        raise ValueError("instance_labels must match the length of result_paths")

    schema = _load_xsd()
    merged_root = etree.Element("testsuites")
    total_tests = 0
    total_failures = 0
    total_errors = 0
    total_skipped = 0
    total_time = 0.0

    for i, path in enumerate(result_paths):
        doc = _parse_and_validate(path, schema)
        root = doc.getroot()
        label = instance_labels[i] if instance_labels is not None else None

        if root.tag == "testsuites":
            suites = root.findall("testsuite")
        elif root.tag == "testsuite":
            suites = [root]
        else:
            raise ResultValidationError(
                f"Unexpected root element <{root.tag}> in {path}"
            )

        for suite in suites:
            if label:
                original_name = suite.get("name", "")
                suite.set("name", f"{label}.{original_name}")

            total_tests += int(suite.get("tests", 0))
            total_failures += int(suite.get("failures", 0))
            total_errors += int(suite.get("errors", 0))
            total_skipped += int(suite.get("skipped", 0))
            total_time += float(suite.get("time", 0.0))

            merged_root.append(suite)

    tree = etree.ElementTree(merged_root)
    tree.write(output_path, xml_declaration=True, encoding="utf-8", pretty_print=True)

    return MergeResult(
        total_tests=total_tests,
        failures=total_failures,
        errors=total_errors,
        skipped=total_skipped,
        time=round(total_time, 3),
    )


def get_exit_code(merge_result: MergeResult) -> int:
    if merge_result.errors > 0:
        return 2
    if merge_result.failures > 0:
        return 1
    return 0
