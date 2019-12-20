FROM python:3.6-slim

COPY requirements.txt .
RUN pip install -r requirements.txt
COPY gitlab2rbac.py .

CMD ["python", "gitlab2rbac.py"]
