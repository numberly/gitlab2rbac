FROM python:3.6 as build-stage

RUN mkdir /install
WORKDIR /install
COPY requirements.txt /requirements.txt
RUN pip install --install-option="--prefix=/install" -r /requirements.txt

FROM python:3.6-alpine
RUN mkdir /app
COPY --from=build-stage /install /usr/local
COPY gitlab2rbac.py /app
RUN mkdir -p ~/.kube
WORKDIR /app

ENTRYPOINT python gitlab2rbac.py
