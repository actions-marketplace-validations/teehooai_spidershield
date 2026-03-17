"""Static security scanning for MCP servers.

Detection uses a hybrid strategy:
- If Semgrep is installed: AST-aware Semgrep rules handle the highest-FP
  categories (dangerous_eval, command_injection, sql_injection and their TS
  equivalents).  Regex is disabled for those categories to avoid duplicates.
- If Semgrep is absent: pure regex for all categories (existing behaviour).
"""

from __future__ import annotations

import re
from pathlib import Path

from spidershield.models import SecurityIssue

from .semgrep_scan import (
    SEMGREP_AVAILABLE,
    SEMGREP_COVERED_CATEGORIES,
    run_semgrep,
)

# Patterns that indicate security risks
DANGEROUS_PATTERNS = {
    "path_traversal": {
        "patterns": [
            r"os\.path\.join\([^)]*\.\.",
            r"open\([^)]*\+",
            r'Path\([^)]*\+',
            # MCP tool handler: file ops on parameter-named variables without validation
            # Matches open(path), open(file_path), open(filepath), Path(directory).read_text()
            r"open\(\s*(?:path|file_path|filepath|file_name|filename|directory|dir_path)\s*[,\)]",
            r"Path\(\s*(?:path|file_path|filepath|file_name|filename|directory|dir_path)\s*\)",
            # os.listdir / os.walk with user-controlled variable
            r"os\.(?:listdir|walk|scandir)\(\s*(?:path|directory|dir_path|folder)\s*\)",
        ],
        "severity": "high",
        "description": "Potential path traversal -- user input may escape intended directory",
        "fix": "Validate and resolve paths against an allowed base directory",
    },
    "command_injection": {
        "patterns": [
            # os.system() with variable (not just string literal)
            r"os\.system\(\s*(?![\"'])",
            r"os\.system\(\s*f[\"']",
            r"os\.popen\(\s*(?![\"'])",
            r"os\.popen\(\s*f[\"']",
            # shell=True with variable/f-string command (not hardcoded)
            # [\s\S] crosses newlines for multi-line calls.
            # Reject matches that cross into another subprocess call.
            r"subprocess\.(?:call|run|Popen)\(\s*f[\"'](?:(?!subprocess\.).[\s\S]){0,200}shell\s*=\s*True",
            r"subprocess\.(?:call|run|Popen)\(\s*\w+(?:(?!subprocess\.).[\s\S]){0,200}shell\s*=\s*True",
        ],
        "severity": "critical",
        "description": "Potential command injection -- user input may be executed as shell command",
        "fix": "Use subprocess with shell=False and explicit argument lists",
    },
    "dangerous_eval": {
        "patterns": [
            # exec/eval with variable input (not string literals)
            # Word boundary (?<!\w) prevents matching run_eval(), etc.
            # Negative lookbehind (?<!\.) excludes method calls like RegExp.exec(),
            # cursor.execute(), db.execute() — only flags bare exec()/eval() calls.
            r"(?<!\w)(?<!\.)exec\(\s*(?![\"\'])",
            r"(?<!\w)(?<!\.)eval\(\s*(?![\"\'])",
        ],
        "severity": "critical",
        "description": "Dynamic code execution -- user input may be executed as code",
        "fix": "Use ast.literal_eval for data parsing, or avoid eval/exec entirely",
    },
    "sql_injection": {
        "patterns": [
            # f-string with full SQL statement pattern (keyword + SQL target)
            (
                r'f"[^"]*(?:SELECT\s+[\w*].*?FROM'
                r"|INSERT\s+INTO"
                r"|UPDATE\s+\w+\s+SET"
                r"|DELETE\s+FROM"
                r"|DROP\s+(?:TABLE|INDEX|VIEW|DATABASE)"
                r"|CREATE\s+(?:TABLE|INDEX|VIEW|DATABASE))"
            ),
            (
                r"f'[^']*(?:SELECT\s+[\w*].*?FROM"
                r"|INSERT\s+INTO"
                r"|UPDATE\s+\w+\s+SET"
                r"|DELETE\s+FROM"
                r"|DROP\s+(?:TABLE|INDEX|VIEW|DATABASE)"
                r"|CREATE\s+(?:TABLE|INDEX|VIEW|DATABASE))"
            ),
            r'\.execute\(\s*f"',
            r"\.execute\(\s*f'",
            r'\.execute\([^)]*%\s',
            r'\.execute\([^)]*\+',
        ],
        "severity": "critical",
        "description": "Potential SQL injection -- query built with string interpolation",
        "fix": "Use parameterized queries with placeholder syntax",
    },
    "hardcoded_credential": {
        "patterns": [
            # Only flag hardcoded secrets outside docstrings/comments.
            # Exclude obvious placeholder/example values (common in README,
            # .env.example, and docstrings): values containing "example",
            # "placeholder", "your_", "changeme", "xxxx", "<", or all-same char.
            r'^[^#\n]*(?:api_key|token|secret|password)\s*=\s*["\'](?!.*(?:example|placeholder|your_|changeme|xxxxxx|<[A-Z_]+>))[^"\']{8,}',
        ],
        "severity": "high",
        "description": "Hardcoded credential -- secret value embedded in source code",
        "fix": "Move secrets to environment variables or a secret manager",
    },
    "unsafe_deserialization": {
        "patterns": [
            r"pickle\.loads?\(",
            r"yaml\.load\(\s*(?!.*Loader\s*=\s*yaml\.SafeLoader)",
            r"yaml\.unsafe_load\(",
            r"marshal\.loads?\(",
            r"shelve\.open\(",
        ],
        "severity": "critical",
        "description": "Unsafe deserialization -- untrusted data may execute arbitrary code",
        "fix": "Use yaml.safe_load, json.loads, or other safe deserialization methods",
    },
    "ssrf": {
        "patterns": [
            r"requests\.(?:get|post|put|delete)\([^)]*(?:url|endpoint)",
            r"httpx\.(?:get|post|put|delete)\([^)]*(?:url|endpoint)",
            # fetch() is too broad — it's a standard API in JS/TS. Only flag Python
            # urllib/requests patterns. JS/TS fetch() is covered by manual review
            # since agent frameworks legitimately fetch user-provided URLs.
        ],
        "severity": "medium",
        "description": "Potential SSRF -- unrestricted network requests with user-controlled URLs",
        "fix": "Validate URLs against an allowlist of permitted domains",
    },
    "no_input_validation": {
        "patterns": [
            # Only flag MCP tool handler functions that take raw string params
            # (functions decorated with @tool, @server.tool, or named call_tool/handle)
            # Use [\s\S]{0,300} to match multi-line function signatures
            r"@(?:mcp|server|app)\.tool\b[\s\S]{0,300}?:\s*str\s*[,\)=]",
            r"@tool\b[\s\S]{0,300}?:\s*str\s*[,\)=]",
        ],
        "severity": "low",
        "description": "MCP tool handler accepts raw string input without validation",
        "fix": "Add input validation (length limits, allowlists, sanitization)",
    },
    "unsafe_path_resolution": {
        "patterns": [
            # Path(user_input).read_text() without prior resolve()/is_relative_to()
            # Only flag when the Path constructor wraps a variable (not a literal)
            r"Path\(\s*(?![\"\'/])\w+\s*\)\.(?:read_text|read_bytes|write_text|write_bytes|open|unlink|rmdir)\(",
            # open(f"...{var}...") without os.path.realpath / resolve
            r"open\(\s*f[\"'][^\"']*\{[^}]+\}",
        ],
        "severity": "high",
        "description": "File operation on user-controlled path without validation or sandboxing",
        "fix": "Resolve paths with Path.resolve() and verify with is_relative_to(base_dir)",
    },
    "async_shell_injection": {
        "patterns": [
            # asyncio.create_subprocess_shell with f-string or variable
            r"create_subprocess_shell\(\s*f[\"']",
            r"create_subprocess_shell\(\s*(?![\"'])\w+",
            # asyncio.subprocess via shell=True
            r"asyncio\.subprocess.*shell\s*=\s*True",
        ],
        "severity": "critical",
        "description": "Async shell command with user-controlled input -- command injection risk",
        "fix": "Use asyncio.create_subprocess_exec with explicit argument lists",
    },
    "basic_auth_in_url": {
        "patterns": [
            # http://user:password@host pattern in source code (not comments)
            r'^[^#\n]*["\']https?://[^/\s"\']*:[^/\s@"\']+@[^/\s"\']+',
        ],
        "severity": "high",
        "description": "Credentials embedded in URL -- basic auth in URL exposes secrets in logs and history",
        "fix": "Pass credentials via headers, environment variables, or a secret manager",
    },
    "timing_attack_comparison": {
        "patterns": [
            # Direct string comparison of secrets (== with password/token/secret variable)
            # Exclude comparisons to None, True, False, empty string
            r"(?:password|token|secret|api_key)\s*==\s*(?!(?:None|True|False|\"\")\b)\w",
            r"==\s*(?:password|token|secret|api_key)\b",
        ],
        "severity": "medium",
        "description": "Secret compared with == operator -- timing side-channel may leak value length",
        "fix": "Use hmac.compare_digest() or secrets.compare_digest() for constant-time comparison",
    },
    "input_reflection": {
        "patterns": [
            # User input directly in return f-string (prompt injection via reflection)
            # MCP tool that returns user input without sanitization
            r"return\s+f[\"'].*\{(?:text|input|query|message|content|user_input|prompt)\}",
            # Direct string concatenation in return
            r"return\s+.*\+\s*(?:text|input|query|message|content|user_input|prompt)\b",
        ],
        "severity": "medium",
        "description": "User input reflected directly in tool output -- may enable prompt injection via reflection",
        "fix": "Sanitize user input before including in tool output; strip control characters and XML tags",
    },
    "excessive_permissions": {
        "patterns": [
            # Tool handler that opens ANY path without is_relative_to/startswith check
            # within 15 lines — detect @tool decorated functions doing unrestricted file I/O
            r"@(?:mcp|server|app|tool)\.tool[\s\S]{0,500}?open\(\s*(?:path|file|filepath|file_path)\s*[,\)](?:(?!is_relative_to|startswith|resolve|ALLOWED|BASE_DIR|WORKSPACE).){0,300}$",
        ],
        "severity": "medium",
        "description": "MCP tool performs file operations without restricting scope to a safe directory",
        "fix": "Use Path.resolve() + is_relative_to(allowed_dir) to enforce directory boundaries",
    },
    "tool_description_poison": {
        "patterns": [
            # Hidden instruction tags in tool descriptions (MCP-specific attack)
            # These inject directives into LLM context via tool metadata
            r"<IMPORTANT>",
            r"<HIDDEN>",
            r"<SECRET>",
            r"<SYSTEM>",
            # Instruction override patterns embedded in description strings
            r'(?:description|__doc__)\s*=.*(?:ignore previous|disregard|forget your|override your)',
            # Dynamic description mutation (rug pull preparation)
            r"__doc__\s*=\s*(?!None)",
        ],
        "severity": "critical",
        "description": "Tool description contains hidden directives that may manipulate LLM behavior",
        "fix": "Remove hidden XML tags and instruction-override text from tool descriptions",
    },
    "token_leakage": {
        "patterns": [
            # Secrets/tokens included in error messages or exceptions
            r"raise\s+\w+(?:Error|Exception)\(.*(?:token|secret|password|api_key|credential)",
            # Secrets in f-string error/return messages
            r'(?:return|raise|print|log)\s*.*f["\'].*\{.*(?:token|secret|password|api_key|key|credential)',
            # Logging secrets directly
            r"(?:logger?\.(?:info|debug|warning|error|critical)|print)\s*\(.*(?:token|secret|password|api_key|credential)\b",
            # Including auth headers in responses or error output
            r'(?:Authorization|Bearer|X-API-Key).*(?:return|raise|print|log)',
        ],
        "severity": "high",
        "description": "Secret or token may be leaked through error messages, logs, or return values",
        "fix": "Never include raw credentials in error messages or logs; use masked/redacted values",
    },
    "metadata_secret_leak": {
        "patterns": [
            # AWS Access Key ID (always starts with AKIA)
            r"\bAKIA[0-9A-Z]{16}\b",
            # OpenAI API key
            r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
            # Anthropic API key
            r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
            # GitHub tokens (PAT, OAuth, App, Actions)
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b",
            # Stripe API keys
            r"\b(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}\b",
            # Slack tokens
            r"\bxox[bpors]-[A-Za-z0-9-]{10,}\b",
            # Private keys embedded in source
            r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
            # API keys in URL query strings
            r"""(?:api_key|apikey|access_token|token|key)=[A-Za-z0-9_-]{16,}""",
        ],
        "severity": "critical",
        "description": "Hardcoded secret or API key found in source code — may leak via MCP tool metadata",
        "fix": "Move secrets to environment variables; never embed credentials in source or tool descriptions",
    },
}

# TypeScript / JavaScript specific patterns (checked only for .ts/.js files)
TS_DANGEROUS_PATTERNS = {
    "prototype_pollution": {
        "patterns": [
            # Object.assign to existing object (not safe shallow-copy to {})
            r"Object\.assign\(\s*(?!\{\s*\})\w+\s*,",
            # Only flag dynamic property assignment from raw user input
            # (not this.map[id]=value which is controlled)
            r"(?<!\w)\w+\[(?:input|params|args|body|query|req)\[\w+\]\]\s*=",
            r"(?:lodash|_)\.merge\(",
        ],
        "severity": "high",
        "description": (
            "Potential prototype pollution -- user-controlled keys"
            " may modify Object.prototype"
        ),
        "fix": (
            "Use Map instead of plain objects, or validate keys"
            " against a denylist (__proto__, constructor, prototype)"
        ),
    },
    "child_process_injection": {
        "patterns": [
            # Only flag when command includes variable/template interpolation
            r"child_process\.exec\(\s*(?![\"'])",
            r"child_process\.exec\(\s*`[^`]*\$\{",
            r"child_process\.execSync\(\s*(?![\"'])",
            r"child_process\.execSync\(\s*`[^`]*\$\{",
            r"(?<!\w)execSync\(\s*(?![\"'])",
            r"(?<!\w)execSync\(\s*`[^`]*\$\{",
            r"(?<!\w)exec\(\s*`[^`]*\$\{",
        ],
        "severity": "critical",
        "description": (
            "Potential command injection via child_process"
            " -- user input may be executed as shell command"
        ),
        "fix": "Use child_process.execFile or spawn with explicit argument arrays",
    },
    "ts_unsafe_eval": {
        "patterns": [
            r"new\s+Function\(",
            # eval( — exclude method calls like RegExp.exec(), cursor.execute(),
            # and exclude word boundaries (e.g. retrieval, interval)
            r"(?<!\w)(?<!\.)eval\(\s*(?!['\"])",
            r"vm\.runInNewContext\(",
            r"vm\.runInThisContext\(",
        ],
        "severity": "critical",
        "description": (
            "Dynamic code execution via eval/Function/vm"
            " -- user input may run arbitrary code"
        ),
        "fix": "Avoid eval and new Function; use structured data parsing instead",
    },
    "ts_sql_injection": {
        "patterns": [
            r"\.query\(\s*`[^`]*\$\{",   # template literal with interpolation in query()
            r"\.execute\(\s*`[^`]*\$\{",  # template literal with interpolation in execute()
        ],
        "severity": "critical",
        "description": "Potential SQL injection -- query built with template literal interpolation",
        "fix": "Use parameterized queries ($1, $2) instead of template literal interpolation",
    },
    "ts_async_injection": {
        "patterns": [
            # Bun.spawn / Deno.run with template literal
            r"Bun\.spawn\(\s*`[^`]*\$\{",
            r"Deno\.run\(\s*\{[^}]*cmd\s*:\s*`[^`]*\$\{",
            # Node child_process.spawn with shell: true + template
            r"spawn\([^)]*\{[^}]*shell\s*:\s*true",
        ],
        "severity": "critical",
        "description": "Async process spawn with user-controlled command -- injection risk",
        "fix": "Use explicit argument arrays instead of shell strings",
    },
    "ts_path_traversal": {
        "patterns": [
            # Only flag path.join with HTTP request inputs (req.params, req.query,
            # req.body) — not generic function params. which are usually safe internal
            # parameters in TS codebases. Also exclude test helper files.
            r"path\.join\([^)]*(?:req\.(?:params|query|body|path)|ctx\.(?:params|query))",
            r"fs\.(?:readFile|writeFile|unlink|rmdir|mkdir)(?:Sync)?\([^)]*\+",
            # MCP tool handler: fs ops on parameter-named variables
            r"fs\.(?:readFile|writeFile|readdir|unlink)(?:Sync)?\(\s*(?:path|filePath|fileName|directory)\s*[,\)]",
            r"Deno\.readTextFile\(\s*(?:path|filePath)\s*\)",
            r"Bun\.file\(\s*(?:path|filePath)\s*\)",
        ],
        "severity": "high",
        "description": "Potential path traversal -- user input used in file system operations",
        "fix": (
            "Validate and resolve paths against an allowed base"
            " directory using path.resolve + startsWith check"
        ),
    },
    "ts_tool_description_poison": {
        "patterns": [
            # Hidden instruction tags in tool descriptions (MCP-specific attack)
            r"<IMPORTANT>",
            r"<HIDDEN>",
            r"<SECRET>",
            r"<SYSTEM>",
            # Instruction override in description strings
            r'description\s*[:=].*(?:ignore previous|disregard|forget your|override your)',
        ],
        "severity": "critical",
        "description": "Tool description contains hidden directives that may manipulate LLM behavior",
        "fix": "Remove hidden XML tags and instruction-override text from tool descriptions",
    },
    "ts_token_leakage": {
        "patterns": [
            # Secrets in template literal error/return
            r'(?:throw|return|console\.(?:log|error|warn))\s*.*`[^`]*\$\{.*(?:token|secret|password|apiKey|credential)',
            # Including auth headers in responses
            r'(?:Authorization|Bearer|X-API-Key).*(?:return|throw|console\.)',
        ],
        "severity": "high",
        "description": "Secret or token may be leaked through error messages, logs, or return values",
        "fix": "Never include raw credentials in error messages or logs; use masked/redacted values",
    },
    "ts_input_reflection": {
        "patterns": [
            # User input directly in return template literal
            r"return\s+`[^`]*\$\{(?:text|input|query|message|content|userInput|prompt)\}",
        ],
        "severity": "medium",
        "description": "User input reflected directly in tool output -- may enable prompt injection via reflection",
        "fix": "Sanitize user input before including in tool output; strip control characters and XML tags",
    },
    "ts_metadata_secret_leak": {
        "patterns": [
            # AWS Access Key ID
            r"\bAKIA[0-9A-Z]{16}\b",
            # OpenAI API key
            r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
            # GitHub tokens
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b",
            # Stripe API keys
            r"\b(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}\b",
            # Slack tokens
            r"\bxox[bpors]-[A-Za-z0-9-]{10,}\b",
            # Private keys
            r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        ],
        "severity": "critical",
        "description": "Hardcoded secret or API key found in source code — may leak via MCP tool metadata",
        "fix": "Move secrets to environment variables; never embed credentials in source or tool descriptions",
    },
}


def _scope_to_mcp_dir(root: Path, files: list[Path]) -> list[Path]:
    """Limit scanning scope to MCP-related directories in monorepos.

    If the repo has a clear MCP subdirectory (e.g. packages/mcp-server/,
    src/mcp/, server/), prefer files from that subtree. This prevents
    scanning unrelated SDKs, frameworks, or platform code that happen to
    live in the same repo.
    """
    if len(files) <= 50:
        return files  # Small repo, no need to scope

    # Look for MCP-indicator directories
    mcp_keywords = {"mcp", "server", "tool", "plugin", "agent-toolkit"}
    mcp_dirs: list[Path] = []

    for f in files:
        rel_parts = f.relative_to(root).parts
        for part in rel_parts[:-1]:  # skip filename
            if any(kw in part.lower() for kw in mcp_keywords):
                # Get the directory up to and including this part
                idx = rel_parts.index(part)
                mcp_dir = root / Path(*rel_parts[: idx + 1])
                if mcp_dir not in mcp_dirs:
                    mcp_dirs.append(mcp_dir)

    if not mcp_dirs:
        return files  # No MCP subdirectory detected

    # Filter to files under MCP directories
    scoped = [
        f for f in files
        if any(_is_under(f, d) for d in mcp_dirs)
    ]

    # Only apply scoping if it meaningfully reduces the set
    # (if >80% of files would remain, scoping isn't useful)
    if len(scoped) >= len(files) * 0.8 or len(scoped) == 0:
        return files

    return scoped


def _is_under(file_path: Path, dir_path: Path) -> bool:
    """Check if file_path is under dir_path."""
    try:
        file_path.relative_to(dir_path)
        return True
    except ValueError:
        return False


_EXCLUDE_DIRS = frozenset({
    "node_modules", "__pycache__", "__tests__", "tests", "test",
    ".git", "dist", "build", ".venv", "venv", ".tox",
    ".mypy_cache", "examples", "example",
    # S3 scope limiting: exclude benchmarks, fixtures, vendor, docs
    "benchmarks", "benchmark", "fixtures", "fixture",
    "vendor", "third_party", "third-party", "external",
    "docs", "doc", "documentation",
    "spec", "e2e", "integration_tests",
    ".next", ".nuxt", ".cache", "coverage",
    # Dev tooling: setup/migration/seed scripts are not MCP tool code
    "scripts", "migrations", "migration", "seeds", "seed",
    # Build/CLI/platform tooling: not MCP runtime paths
    "ingest", "electron",
})


def _is_excluded_file(rel_path: str) -> bool:
    """Check if a relative path should be excluded from security scanning."""
    parts = Path(rel_path).parts
    if any(part in _EXCLUDE_DIRS for part in parts):
        return True
    name = Path(rel_path).name
    return (
        name.startswith("test_")
        or name.endswith(".test.ts")
        or name.endswith(".test.js")
        or name.endswith(".spec.ts")
        or name.endswith(".spec.js")
        or name.endswith(".d.ts")
        or name.endswith(".min.js")
        or name.startswith("_test.")
        or name.endswith("_test.go")
    )


def _classify_file_context(rel_path: str) -> str:
    """Classify a file's context: runtime, test, build, benchmark, or cli.

    Used by downstream consumers (A4 Bug Hunter) to filter false positives.
    Scanner still reports all issues but tags them with context for filtering.
    """
    normalized = rel_path.replace("\\", "/").lower()
    parts = Path(rel_path).parts

    # Test code
    if any(p in {"tests", "test", "spec", "__tests__", "e2e", "integration_tests"} for p in parts):
        return "test"
    name = Path(rel_path).name.lower()
    if name.startswith("test_") or name.endswith((".test.ts", ".test.js", ".spec.ts", ".spec.js")):
        return "test"

    # Build/scripts
    if any(p in {"scripts", "script"} for p in parts):
        return "build"
    if name in {"release.ts", "release.js", "release.mjs"}:
        return "build"
    if name.startswith("download-") or name.startswith("download_"):
        return "build"

    # Benchmark/evaluation
    if any(p in {"benchmarks", "benchmark", "eval", "evaluation", "synthesis"} for p in parts):
        return "benchmark"

    # Intentionally vulnerable / CTF
    if any(p in {"challenges", "vulnerable"} for p in parts):
        return "ctf"
    if "damn-vulnerable" in normalized or "damn_vulnerable" in normalized:
        return "ctf"

    # Migrations / ingest / ETL
    if any(p in {"migrations", "migration", "ingest", "seeds", "seed"} for p in parts):
        return "migration"

    # CLI / platform tooling
    if any(p in {"electron"} for p in parts):
        return "platform"
    if name in {"cli.ts", "cli.js", "cli.py", "start.js", "start.ts"}:
        return "cli"

    return "runtime"


def _get_function_body(content: str, start: int, max_lines: int = 30) -> str:
    """Extract the body of a Python function starting after the def line.

    *start* points just past the regex match (end of ``def f(x: str)``).
    We skip the remainder of the signature, any docstring, then collect
    up to *max_lines* of the indented body.
    """
    lines = content[start:].split("\n")
    body_lines: list[str] = []
    body_indent = 0
    in_docstring = False
    past_preamble = False  # True once we've passed docstring / def tail

    for line in lines:
        stripped = line.lstrip()

        # --- skip inside multi-line docstring ---
        if in_docstring:
            if '"""' in stripped or "'''" in stripped:
                in_docstring = False
            continue

        # --- skip blank / comment / trailing def lines before body ---
        if not past_preamble:
            if not stripped or stripped.startswith("#"):
                continue
            # Detect docstring start
            for quote in ('"""', "'''"):
                if stripped.startswith(quote):
                    # Single-line docstring: opening and closing on same line
                    if stripped.count(quote) >= 2:
                        # e.g. """Some doc."""  — skip entire line
                        pass
                    else:
                        in_docstring = True
                    break
            else:
                # First real code line — start collecting body
                past_preamble = True
                body_indent = len(line) - len(stripped)
            if not past_preamble:
                continue

        # --- collect body lines ---
        if stripped == "":
            body_lines.append("")
            continue
        current_indent = len(line) - len(stripped)
        if current_indent < body_indent:
            break  # dedent = end of function
        body_lines.append(stripped)
        if len(body_lines) >= max_lines:
            break

    return "\n".join(body_lines)


_VALIDATION_INDICATORS = re.compile(
    r"(?:"
    r"validate|sanitize|check_|_check\b|_valid"
    r"|raise\s+(?:ValueError|TypeError)"
    r"|isinstance\s*\("
    r"|len\s*\(.*[<>]"  # length checks like len(x) > N
    r"|not\s+\w+\s+or\s+len\s*\("  # guard clauses like `not x or len(x)`
    r")",
    re.IGNORECASE,
)


def _has_validation(func_body: str) -> bool:
    """Check if a function body contains input validation indicators."""
    return bool(_VALIDATION_INDICATORS.search(func_body))


def scan_security(path: Path) -> tuple[float, list[SecurityIssue]]:
    """Scan for security issues in Python and TypeScript files.

    Returns (security_score, list_of_issues).

    When Semgrep is installed, AST-aware rules replace regex for the highest-FP
    categories so duplicate findings are not emitted.
    """
    issues: list[SecurityIssue] = []

    # --- Semgrep pass (AST-aware, higher precision) ---
    # Semgrep results are collected here but added to issues AFTER scoping,
    # so they respect the same exclusion and monorepo rules as regex.
    semgrep_issues: list[SecurityIssue] = []
    if SEMGREP_AVAILABLE:
        semgrep_issues = run_semgrep(path)
        semgrep_issues = [i for i in semgrep_issues if not _is_excluded_file(i.file)]

    source_files = list(path.rglob("*.py")) + list(path.rglob("*.ts")) + list(path.rglob("*.js"))
    source_files = [
        f for f in source_files
        if not any(part in _EXCLUDE_DIRS for part in f.relative_to(path).parts)
        and not f.name.startswith("test_")
        and not f.name.endswith(".test.ts")
        and not f.name.endswith(".test.js")
        and not f.name.endswith(".spec.ts")
        and not f.name.endswith(".spec.js")
        and not f.name.endswith(".d.ts")  # type definitions, not source
        and not f.name.endswith(".min.js")  # minified bundles
        and not f.name.startswith("_test.")  # Go test files
        and not f.name.endswith("_test.go")  # Go test files
    ]

    # S3: Monorepo scope limiting — if we can identify the MCP-specific subdir,
    # limit scanning to only that directory to avoid false positives from
    # unrelated framework code (e.g. entire Stripe SDK, Vercel AI SDK)
    source_files = _scope_to_mcp_dir(path, source_files)

    # Apply monorepo scoping to Semgrep results as well
    if semgrep_issues and source_files:
        scoped_dirs = {f.relative_to(path).parts[0] for f in source_files if f.relative_to(path).parts}
        semgrep_issues = [
            i for i in semgrep_issues
            if not Path(i.file).parts or Path(i.file).parts[0] in scoped_dirs
        ]
    # Tag Semgrep issues with file_context
    for issue in semgrep_issues:
        issue.file_context = _classify_file_context(issue.file)
    issues.extend(semgrep_issues)

    for source_file in source_files:
        try:
            content = source_file.read_text(errors="ignore")
        except OSError:
            continue

        rel_path = str(source_file.relative_to(path))
        is_ts_js = source_file.suffix in (".ts", ".js")

        # Check universal patterns (Python-oriented; skip Python-only
        # rules like dangerous_eval and sql_injection on TS/JS files
        # to avoid false positives from RegExp.exec(), cursor.execute(), etc.)
        # Also skip categories already covered by Semgrep to avoid duplicates.
        _py_only_rules = {"dangerous_eval", "sql_injection", "unsafe_deserialization"}
        for category, config in DANGEROUS_PATTERNS.items():
            if is_ts_js and category in _py_only_rules:
                continue
            if SEMGREP_AVAILABLE and category in SEMGREP_COVERED_CATEGORIES:
                continue  # Semgrep handles this category with higher precision
            flags = re.IGNORECASE
            for pattern in config["patterns"]:
                # Patterns using ^ need MULTILINE to match per-line
                pat_flags = flags | re.MULTILINE if pattern.startswith("^") else flags
                for match in re.finditer(pattern, content, pat_flags):
                    line_num = content[:match.start()].count("\n") + 1
                    # For no_input_validation: suppress if function body
                    # contains validation (len check, validate call, raise,
                    # or isinstance).  This avoids flagging functions that
                    # *do* validate their str inputs.
                    if category == "no_input_validation":
                        func_body = _get_function_body(content, match.end())
                        if _has_validation(func_body):
                            continue
                    issues.append(
                        SecurityIssue(
                            severity=config["severity"],
                            category=category,
                            file=rel_path,
                            line=line_num,
                            description=config["description"],
                            fix_suggestion=config["fix"],
                            file_context=_classify_file_context(rel_path),
                        )
                    )

        # Check TS/JS-specific patterns (skip Semgrep-covered categories)
        if is_ts_js:
            for category, config in TS_DANGEROUS_PATTERNS.items():
                if SEMGREP_AVAILABLE and category in SEMGREP_COVERED_CATEGORIES:
                    continue  # Semgrep handles this category
                for pattern in config["patterns"]:
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count("\n") + 1
                        issues.append(
                            SecurityIssue(
                                severity=config["severity"],
                                category=category,
                                file=rel_path,
                                line=line_num,
                                description=config["description"],
                                fix_suggestion=config["fix"],
                                file_context=_classify_file_context(rel_path),
                            )
                        )

    # Calculate score
    if not source_files:
        return 5.0, issues

    severity_weights = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.25, "info": 0.1}
    total_penalty = sum(severity_weights.get(i.severity, 0.25) for i in issues)
    score = max(0.0, 10.0 - total_penalty)

    return round(score, 1), issues
