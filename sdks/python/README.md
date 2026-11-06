# DBShield Python SDK

**Safety-first database guardrail, SQL AST firewall & sandboxing wire proxy for autonomous AI coding agents in Python.**

Protect your databases from accidental bulk deletes, catastrophic drops, locks, and PII leaks when paired with LangChain, CrewAI, LlamaIndex, SQLAlchemy, Cursor, and Claude Code.

---

## 📦 Installation

```bash
pip install dbshield-defense
```

*(In Python code, import as standard `import dbshield` or `from dbshield import DBShieldGuard`)*

---

## ⚡ Quickstart

### 1. Standalone Query Guardrail
Validate raw SQL queries before execution without any external server dependencies:

```python
from dbshield import DBShieldGuard

guard = DBShieldGuard(safety_tier="BALANCED")

# 1. Blocks dangerous tautology mutations
result = guard.validate_query("DELETE FROM users WHERE 1=1;")
if not result.allowed:
    print(f"Blocked: {result.violations[0].message}")
    # Output: Blocked: Unconstrained mutation: WHERE clause contains tautology '1=1'

# 2. Blocks destructive DDL drops
result = guard.validate_query("DROP TABLE accounts;")
assert not result.allowed

# 3. Allows safe targeted queries
result = guard.validate_query("SELECT id, name FROM users WHERE id = 42;")
assert result.allowed
```

---

### 2. Automatic SQLAlchemy Middleware
Hook DBShield directly into your SQLAlchemy engine to protect against rogue agent mutations:

```python
from sqlalchemy import create_engine
from dbshield.middleware import attach_dbshield

engine = create_engine("sqlite:///production.db")
attach_dbshield(engine, safety_tier="BALANCED")

# Any agent query executed through this engine is automatically validated!
with engine.connect() as conn:
    conn.execute("SELECT * FROM users WHERE id = 1;") # Safe
    conn.execute("DELETE FROM users;") # Raises DBShieldSecurityViolation!
```

---

### 3. Dynamic Zero-Leak PII Masking
Redact SSNs, credit cards, emails, and API keys from tabular results before feeding into LLM context:

```python
from dbshield.pii import PiiRedactor

redactor = PiiRedactor()

rows = [
    {"id": 1, "email": "alice@example.com", "ssn": "123-45-6789", "token": "sk-proj-xyz"}
]

clean_rows = redactor.redact_rows(rows)
print(clean_rows)
# Output: [{'id': 1, 'email': 'a***e@e****e.com', 'ssn': '[REDACTED:SSN:39a1]', 'token': '[REDACTED:SECRET:9b1a]'}]
```

---

### 4. LangChain Integration
```python
from langchain_community.utilities import SQLDatabase
from dbshield.integrations.langchain import DBShieldSQLDatabase

db = SQLDatabase.from_uri("sqlite:///app.db")
safe_db = DBShieldSQLDatabase(db, safety_tier="BALANCED")

# Executes safely with AST guardrails and PII masking
res = safe_db.run("SELECT * FROM users LIMIT 5;")
```

---

### 5. CrewAI Database Tool
```python
from dbshield.integrations.crewai import DBShieldDatabaseTool

tool = DBShieldDatabaseTool(database_url="sqlite:///company.db")
# Pass 'tool' to your CrewAI agent
```

---

## 🏛️ Enterprise Compliance
* 100% Air-Gapped and Local-First
* Zero External Telemetry
* India DPDP Act 2023 & EU GDPR Ready
* Verifiable SOC 2 Type II Controls
