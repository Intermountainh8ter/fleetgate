# Small image with the CLI and the bundled scenarios. No network access needed at run time.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 FLEETGATE_SCENARIO_DIR=/app/scenarios
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY scenarios ./scenarios
RUN pip install --no-cache-dir . \
 && useradd --create-home fleetgate
USER fleetgate

ENTRYPOINT ["fleetgate"]
CMD ["scenarios"]
