FROM python:3.6 as build-stage

RUN mkdir /install
WORKDIR /install
COPY requirements.txt /requirements.txt
RUN pip install --install-option="--prefix=/install" -r /requirements.txt


FROM python:3.6-alpine

RUN addgroup -g 1000 appuser
RUN adduser -D -u 1000 -G appuser appuser
USER appuser
RUN mkdir -p ~/.kube
COPY --from=build-stage /install /usr/local
COPY gitlab2rbac.py .

ENTRYPOINT python gitlab2rbac.py
