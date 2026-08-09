from autofde.integrations import admitted_integrations, integration_receipt


def test_integrations_are_identity_pinned_and_authority_partitioned() -> None:
    integrations = admitted_integrations()
    assert {item.name for item in integrations} == {
        "substrate",
        "fastmcp",
        "dspy",
        "autofde-lab",
        "ggen",
        "gymact",
    }
    assert all(item.identity for item in integrations)
    assert all(item.authority != "DO" for item in integrations)

    by_name = {item.name: item for item in integrations}
    assert by_name["gymact"].authority == "DO_BRCE_ONLY"
    assert by_name["gymact"].runtime_resident is True
    assert by_name["fastmcp"].runtime_resident is True
    assert by_name["autofde-lab"].runtime_resident is False
    assert by_name["ggen"].runtime_resident is False
    assert by_name["dspy"].runtime_resident is False
    assert by_name["autofde-lab"].identity == "582277151fd07ea831f6217e43ddf764f61b723f"
    assert by_name["ggen"].identity == "37daece2a026efc6168c6ea715a1747bb934a898"
    assert by_name["gymact"].identity == "24bd68a8c9e59ee42a4a2eeea9fc12d79fe75f5b"


def test_receipt_is_not_execution_standing() -> None:
    receipt = integration_receipt()
    assert receipt["standing"] == "PARTIAL_ALIVE"
    assert receipt["production_rule"] == "EXPLOIT_ONLY_COMPILED_PROFILE_TO_GYMACT_BRCE"
    assert len(receipt["integrations"]) == 6
