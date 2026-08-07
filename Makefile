.PHONY: generate generate-reference verify test crown-ontology

generate:
	ggen sync run

generate-reference:
	python3 scripts/render_reference.py --write

verify:
	python3 scripts/verify_ontology.py
	python3 scripts/verify_ecosystem.py
	python3 scripts/verify_private_census.py

test:
	python3 -m unittest discover -s tests -v

crown-ontology: generate-reference verify test
	@echo "AUTOFDE_ONTOLOGY_ALIVE"
