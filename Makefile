all: devbuild quiet_test

test:
	python3 -m pytest

quiet_test:
	python3 -m pytest -q

devbuild:
	python3 cryptomodule/build.py

# Drop .pyc and compiled module
clean:
	rm cryptomodule/__pycache__/*
	rm cryptomodule/*/__pycache__/*
	rm cryptomodule/_cryptomodule*
