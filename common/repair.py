"""Budowniczowie promptów: generacja początkowa (schema SQL + main.py) oraz naprawa CEGIS."""
from __future__ import annotations

from .llm import est_tokens

SYSTEM = (
    "You are a senior Python engineer (FastAPI 0.11x, Pydantic v2, SQLAlchemy 2.x). You reproduce a black-box REST API "
    "from observed traffic. You output only what is asked, in the requested XML tag, and never explain."
)

CONTRACT = """RUNTIME CONTRACT (file twin_runtime.py already exists – do NOT rewrite it):
  from twin_runtime import Base, SessionLocal, engine, get_db, init_twin
  - Base: SQLAlchemy 2.x declarative base. Every ORM model uses __tablename__ EXACTLY as in schema.sql (case-sensitive).
  - get_db: FastAPI dependency yielding a Session.  - init_twin(app): call ONCE as the LAST statement of main.py
    (creates tables, loads seed.json, installs header middleware and the validation-error handler).
RULES:
 1. app = FastAPI(redirect_slashes=False, docs_url=None, redoc_url=None, openapi_url=None). Paths must match the OpenAPI paths
    character-for-character, including trailing slashes.
 2. Pydantic v2 ONLY: response schemas use model_config = ConfigDict(from_attributes=True); use model_validate / model_dump.
    Never use orm_mode, class Config, .dict(), .from_orm(), @validator.
 3. Nullable/optional fields => Optional[T] = None. JSON columns => sqlalchemy.JSON and typing.Any. Nested objects => nested
    Pydantic models (from_attributes) fed from relationship() or JSON columns. Timestamps stay str unless the DB column is DateTime.
 4. Wrap list/item responses in the observed envelope exactly (see list_envelope / item_envelope in RESOURCES).
 5. Return JSONResponse(status_code=..., content=...) whenever status/body differs from FastAPI defaults. Empty collections
    => 200 + empty list (never 404). Unknown ids => the observed 404 behaviour. Creation => the observed status (often 201).
 6. If auth is 'bearer' and operations are marked auth-required: missing/invalid Authorization header => observed 401 body.
    The login endpoint returns the observed token shape (any JWT-looking string is fine).
 7. Foreign keys: ForeignKey + relationship(). Child creation with a nonexistent parent => observed status, else 404.
 8. Query parameters from the spec must be accepted (Optional[str] = Query(None)); apply them as filters only if the model has
    that column (hasattr/getattr), otherwise ignore. Unknown query params must never cause 500.
 9. SQLAlchemy 2.x style only (select(), db.scalars()). No raw f-string SQL. Seed data comes from seed.json – do NOT hardcode seeds.
10. Output ONE complete Python file inside <python></python>. No prose, no markdown fences outside the tag."""


def schema_prompt(digest: str, heuristic_ddl: str) -> str:
    return f"""Below is a compact contract digest inferred from captured HTTP traffic and a HEURISTIC SQLite schema derived from it.
Review and complete the schema: add missing foreign keys (columns named <x>_id / <x>Id referencing known resources), nested-resource
tables implied by routes like /parent/{{id}}/children, sensible NOT NULL on primary keys only, keep column names EXACTLY as seen in JSON.
Use only SQLite types (INTEGER, REAL, TEXT, BOOLEAN, JSON). Do not drop any table or column from the heuristic schema.

DIGEST:
{digest}

HEURISTIC SCHEMA:
{heuristic_ddl}

Return ONLY the final DDL (CREATE TABLE statements) inside <sql></sql>."""


def codegen_prompt(digest: str, ddl: str, route_list: str) -> str:
    return f"""{CONTRACT}

Implement main.py for the API described below.

REQUIRED ROUTES (METHOD path) – implement ALL of them:
{route_list}

SCHEMA (schema.sql):
{ddl}

CONTRACT DIGEST (observed traffic):
{digest}

<python>
...complete main.py...
</python>"""


def repair_prompt(code: str, ddl: str, analysis_text: str, logs: str, digest: str, budget_tokens: int,
                  extra: str = "", regress_note: str = "") -> str:
    """Składa prompt naprawczy i przycina sekcje tak, by zmieścić się w budżecie kontekstu."""
    fixed = f"""{CONTRACT}

You are repairing main.py. Fix EVERY issue below; keep everything that already works unchanged.
Return the COMPLETE file (first import to last line, ending with init_twin(app)) inside <python></python>.
"""
    sections = [
        ("CURRENT main.py", f"<current>\n{code}\n</current>", 0),
        ("SCHEMA", ddl, 1),
        ("DIFFERENTIAL TEST ANALYSIS (original vs twin)", analysis_text, 0),
        ("TWIN RUNTIME LOG / TRACEBACK", logs[-2500:], 2),
        ("STATIC CHECKS", extra, 1),
        ("REGRESSION NOTE", regress_note, 1),
        ("CONTRACT DIGEST (reference)", digest, 3),
    ]
    used = est_tokens(fixed) + 200
    body = []
    for title, text, prio in sorted(sections, key=lambda s: s[2]):
        if not text.strip():
            continue
        room = budget_tokens - used
        if room < 300:
            break
        if est_tokens(text) > room:
            text = text[: int(room * 3.2)] + "\n...[truncated to fit context]"
        used += est_tokens(text)
        body.append((title, text))
    order = [s[0] for s in sections]
    body.sort(key=lambda b: order.index(b[0]))
    return fixed + "\n" + "\n\n".join(f"### {t}\n{x}" for t, x in body) + "\n\n<python>\n...complete fixed main.py...\n</python>"
