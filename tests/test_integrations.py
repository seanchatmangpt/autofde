from autofde.integrations import admitted_integrations, integration_receipt


def test_integrations_are_identity_pinned() -> None:
    integrations = admitted_integrations()
    assert {item.name for item in integrations} == {"substrate", "fastmcp", "dspy", "autofde-lab"}
    assert all(item.identity for item in integrations)
    assert all(item.authority != "DO" for item in integrations)


def test_receipt_is_not_execution_standing() -> None:
    receipt = integration_receipt()
    assert receipt["standing"] == "PARTIAL_ALIVE"
    assert len(receipt["integrations"]) == 4
