.PHONY: help install demo test verify clean tree

help:
	@printf '%s\n' \
	  'install  Install the Python reference package in editable mode' \
	  'demo     Run the proof-gated evolution demo' \
	  'test     Run the standard-library test suite' \
	  'verify   Run repository integrity checks and tests' \
	  'clean    Remove generated runtime state and caches' \
	  'tree     Print the repository tree'

install:
	python3 -m pip install -e .

demo:
	PYTHONPATH=src python3 -m variaxiom.cli demo --reset

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

verify:
	bash scripts/verify.sh

clean:
	rm -rf .variaxiom __pycache__ src/variaxiom/__pycache__ tests/__pycache__

tree:
	find . -path './.git' -prune -o -path './.variaxiom' -prune -o -print | sort
