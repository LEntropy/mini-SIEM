FROM python:3.12-slim
WORKDIR /app
COPY . /app
# Pure standard library; no pip install needed to run.
CMD ["python", "demo.py"]
