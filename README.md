# daas-auth

The OAuth2 authentication and authorization service for DESIGN DaaS, written in Python (FastAPI). It replaces the PHP backend (`design-daas-application-backend`): users, groups, desktops, permissions and the OAuth2 token flow. It is a drop-in with the same HTTP API on `127.0.0.1:5003`, so the Quart orchestrator and the React frontend work unchanged.

Bachelor's thesis project: **Konzeption und Implementierung eines OAuth2-Authentifizierungs- und Autorisierungsdienstes in Python zur Ablösung einer PHP-Legacy-Komponente in einer Desktop-as-a-Service-Plattform**.

## Development

```bash
uv sync          # install the dependencies into .venv/
make check       # the gates: mypy, ruff, ruff format, import-linter, pytest
make fmt         # format the code and apply ruff's safe fixes
```
