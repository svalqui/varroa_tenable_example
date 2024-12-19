# PYTHON ENVIRONMENT
venv_create:
	python3 -m venv ./venv; \
	. ./venv/bin/activate && \
	pip3 install -r requirements.txt && \

venv_create_dev:
	python3 -m venv ./venv; \
	. ./venv/bin/activate && \
	pip3 install -r requirements-dev.txt

update_packages:
	python3 -m venv ./venv; \
	. ./venv/bin/activate && \
	pip3 install -r requirements-dev.txt && \
	echo "[*] Checking: requirements.txt" && \
	pur -r requirements.txt && \
	echo "[*] Checking: requirements-dev.txt" && \
	pur -r requirements-dev.txt && \
	deactivate;

# LINTING
lint: \
	venv_create_dev \
	lint_python

lint_python:
	. ./venv/bin/activate && \
	echo "[*] Linting Python..." && \
	ruff check
