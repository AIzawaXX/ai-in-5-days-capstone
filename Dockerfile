FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /code

COPY ./pyproject.toml ./README.md ./

COPY ./app ./app

RUN uv sync --no-dev

ARG AGENT_VERSION=0.0.0
ENV AGENT_VERSION=${AGENT_VERSION}

EXPOSE 8080

CMD ["uv", "run", "--no-dev", "uvicorn", "app.fast_api_app:app", "--host", "0.0.0.0", "--port", "8080"]
