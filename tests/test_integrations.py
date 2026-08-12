from autofde.integrations import (
    admitted_integrations,
    integration_manifest_digest,
    integration_receipt,
    observe_runtime_integrations,
)


def test_integrations_are_identity_pinned_and_powerless() -> None:
    integrations = admitted_integrations()
    assert {item.name for item in integrations} == {"substrate", "fastmcp", "dspy", "autofde-lab"}
    assert all(item.identity for item in integrations)
    assert all(item.authority != "DO" for item in integrations)
    assert next(item for item in integrations if item.name == "autofde-lab").runtime_required is False


def test_manifest_receipt_binds_identity_without_self_asserting_standing() -> None:
    receipt = integration_receipt()
    assert receipt["schema"] == "autofde.integration-manifest/1"
    assert receipt["kind"] == "MANIFEST"
    assert receipt["authority_ceiling"] == "CONSTRUCT"
    assert receipt["manifest_digest"] == integration_manifest_digest()
    assert len(receipt["integrations"]) == 4
    assert "standing" not in receipt


def test_runtime_observation_is_separate_from_manifest_and_never_promotes_standing() -> None:
    observations = observe_runtime_integrations()
    assert {item.name for item in observations} == {"substrate", "fastmcp", "dspy", "autofde-lab"}
    assert all(not hasattr(item, "standing") for item in observations)
    source_only = {item.name for item in observations if not item.observed and not item.coordinate.startswith("PyPI:")}
    assert source_only == {"substrate", "autofde-lab"}
