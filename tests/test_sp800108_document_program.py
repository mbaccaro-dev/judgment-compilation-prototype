import pytest

from judgment_compilation.document_programs import ReviewedDocumentProgramError, ReviewedDocumentPrograms
from judgment_compilation.nist import build_pack

PACKAGE_ID = "nist-sp-800-108-counter-mode-capacity-guard"


@pytest.fixture(scope="module")
def programs():
    return ReviewedDocumentPrograms(build_pack()["semantic_pack"])


def request(*, mode=True, n=2, r=2, omit=(), unknowns=None, conflict=None):
    values = {
        "mode": ("counter_mode_established", mode),
        "n": ("counter_mode_iteration_count", n),
        "r": ("counter_width_bits", r),
    }
    facts = [
        {"id": key, "predicate": predicate,
         "arguments": {"invocation": "invocation-a"}, "value": value}
        for key, (predicate, value) in values.items() if key not in omit
    ]
    if conflict:
        predicate, value = values[conflict]
        facts.append({"id": conflict + "-conflict", "predicate": predicate,
                      "arguments": {"invocation": "invocation-a"},
                      "value": (not value) if type(value) is bool else value + 1})
    payload = {
        "request_id": "sp800108-request-001",
        "scenario_id": "sp800108-scenario-001",
        "entities": {"invocation-a": "system"},
        "facts": facts,
        "bindings": {"strict-capacity-boundary": {"invocation": ["invocation-a"]}},
    }
    if unknowns is not None:
        payload["unknowns"] = unknowns
    return payload


def execution(programs, payload):
    return programs.execute(PACKAGE_ID, payload)["execution"]["execution"]["execution"]


def test_exact_three_source_citations_and_boundary(programs):
    inspected = programs.inspect(PACKAGE_ID)
    citations = inspected["source_citations"]
    assert {c["citation"]["provenance"]["physical_pdf_page_number"] for c in citations} == {13, 14, 15}
    assert all(not c["citation"]["claim"]["text"][-1].isspace() for c in citations)
    assert execution(programs, request(n=2, r=2))["outputs"][0]["value"] is False
    assert execution(programs, request(n=3, r=2))["outputs"][0]["value"] is False
    assert execution(programs, request(n=4, r=2))["outputs"][0]["value"] is True


@pytest.mark.parametrize("payload", [
    request(omit=("mode",)), request(omit=("n",)), request(omit=("r",)),
    request(conflict="mode"), request(conflict="n"), request(conflict="r"),
    request(mode=False, n=4, r=2), request(n=2, r=0), request(n=2, r=33),
    request(omit=("r",), unknowns=[{"id": "unknown-r", "text": "r unavailable",
        "predicate": "counter_width_bits", "arguments": {"invocation": "invocation-a"}}]),
])
def test_material_gap_or_out_of_scope_input_remains_unresolved(programs, payload):
    result = execution(programs, payload)
    assert result["status"] == "UNRESOLVED"
    assert result["outputs"] == []


@pytest.mark.parametrize("field,value", [
    ("n", True), ("n", -1), ("n", 2**64),
    ("r", True), ("r", -1), ("r", 2**64),
])
def test_invalid_unsigned_values_are_rejected(programs, field, value):
    kwargs = {"n": 2, "r": 2}
    kwargs[field] = value
    with pytest.raises(ReviewedDocumentProgramError):
        programs.execute(PACKAGE_ID, request(**kwargs))
