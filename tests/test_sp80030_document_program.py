from judgment_compilation.document_programs import ReviewedDocumentPrograms
from judgment_compilation.nist import build_pack


PACKAGE_ID = "nist-sp-800-30r1-table-g5"


def request(initiation="High", impact="Moderate"):
    return {
        "request_id": "sp80030-request-001",
        "scenario_id": "sp80030-scenario-001",
        "entities": {"subject-1": "assessment_subject"},
        "facts": [
            {"id": "initiation", "predicate": "likelihood_of_threat_event_initiation_or_occurrence",
             "arguments": {"assessment_subject": "subject-1"}, "value": initiation},
            {"id": "impact", "predicate": "likelihood_threat_events_result_in_adverse_impacts",
             "arguments": {"assessment_subject": "subject-1"}, "value": impact},
        ],
        "bindings": {"lookup": {"assessment_subject": ["subject-1"]}},
    }


def test_sp80030_public_inspect_and_all_25_table_cells():
    programs = ReviewedDocumentPrograms(build_pack()["semantic_pack"])
    inspected = programs.inspect(PACKAGE_ID)
    citation = inspected["source_citations"][0]["citation"]
    assert citation["provenance"]["physical_pdf_page_number"] == 82
    assert citation["provenance"]["character_span"] == [2216, 2623]
    assert not citation["claim"]["text"][-1].isspace()
    table = {
        "Very High": ["Very High", "Very High", "High", "Moderate", "Low"],
        "High": ["Very High", "High", "Moderate", "Moderate", "Low"],
        "Moderate": ["High", "Moderate", "Moderate", "Low", "Low"],
        "Low": ["Moderate", "Moderate", "Low", "Low", "Very Low"],
        "Very Low": ["Low", "Low", "Low", "Very Low", "Very Low"],
    }
    labels = ["Very High", "High", "Moderate", "Low", "Very Low"]
    for initiation, row in table.items():
        for impact, expected in zip(labels, row):
            first = programs.execute(PACKAGE_ID, request(initiation, impact))
            assert first == programs.execute(PACKAGE_ID, request(initiation, impact))
            execution = first["execution"]["execution"]["execution"]
            assert execution["status"] == "COMPLETE"
            assert execution["outputs"][0]["predicate"] == "overall_likelihood_label"
            assert execution["outputs"][0]["value"] == expected
            assert execution["compliance_verdict"] is None
            assert execution["responsibility_determination"] is None
            assert execution["external_effects"] == []


def test_sp80030_unknown_label_does_not_select_a_table_cell():
    programs = ReviewedDocumentPrograms(build_pack()["semantic_pack"])
    result = programs.execute(PACKAGE_ID, request("Unknown", "Moderate"))
    execution = result["execution"]["execution"]["execution"]
    assert execution["status"] == "UNRESOLVED"
    assert execution["outputs"] == []
