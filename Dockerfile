FROM python:3.12-slim

COPY requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

USER appuser
RUN mkdir -p ~/.kube
COPY gitlab2rbac.py .

ENTRYPOINT python gitlab2rbac.py
