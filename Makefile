.PHONY: test quiet_test devbuild clean docs

all: devbuild quiet_test

test:
	python3 -m pytest

quiet_test:
	python3 -m pytest -q

devbuild:
	python3 pylibressl/build.py

# Drop .pyc and compiled module
clean:
	rm pylibressl/__pycache__/* || true
	rm pylibressl/*/__pycache__/* || true
	rm pylibressl/_libressl* || true
	rm tests/__pycache__/* || true

# Generate documentation
docs:
	sphinx-apidoc -f -e -M -o docs/ . setup.py
	make -C docs/ html
