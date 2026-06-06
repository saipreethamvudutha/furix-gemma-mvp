# One image, seven roles. The role is chosen at runtime by run_container.py,
# so all Furix-built containers (C3,C4,C6,C8,C11,C14,C15) share this build.
FROM python:3.11-slim

WORKDIR /app

# System deps kept minimal (psycopg2-binary needs no toolchain).
COPY requirements.txt requirements-rag.txt requirements-deploy.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-rag.txt -r requirements-deploy.txt

COPY furix_mvp ./furix_mvp
COPY static ./static
COPY scripts ./scripts

# Default role is the dashboard; compose overrides `command` per container.
ENV CONTAINER=dashboard
EXPOSE 8080
CMD ["python", "-m", "furix_mvp.run_container", "dashboard"]
