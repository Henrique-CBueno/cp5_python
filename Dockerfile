FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
COPY app ./app
RUN pip install --no-cache-dir .
RUN useradd --create-home vigilia
USER vigilia
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
