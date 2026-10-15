FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml requirements.txt README.md ./
COPY secheader/ ./secheader/

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["secheader"]
CMD ["--help"]
