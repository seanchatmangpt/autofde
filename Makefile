.PHONY: generate generate-reference verify vacuity test crown-ontology

generate:
	ggen sync run

generate-reference:
	python3 scripts/render_reference.py --write

verify:
	python3 scripts/verify_ontology.py

vacuity:
	python3 scripts/audit_vacuity.py --ref HEAD --fail-on-findings

test:
	python3 -m unittest discover -s tests -v

crown-ontology: generate-reference verify vacuity test
	@echo "AUTOFDE_ONTOLOGY_ALIVE"
