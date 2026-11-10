#!/usr/bin/env python3
"""Run every test suite for one language and report PASS / FAIL / MISSING / BROKEN per system.

LIFESPAN: permanent -- this is the CI entry point (see .github/workflows/ci.yml).

How it works
  * A "suite" is one system in one language: saas_templates/<lang>/<system>_<lang>.<ext> (the
    implementation) plus <system>_<lang>_tests.<ext> (its tests).
  * Each suite runs in a throwaway temp directory using that language's standard toolchain.
    Third-party packages are installed ONCE per run into `.deps/<lang>/` (pip, npm, go modules,
    Maven, Composer, NuGet, crates.io). Nothing is vendored; the runner only needs network access.
  * Results are compared with a baseline of KNOWN-FAILING suites (ci/baseline.json). Only a
    REGRESSION fails the run: a suite that is not in the baseline and does not pass. Suites that
    pass but are still listed in the baseline are reported as "newly passing" so the list can shrink.
  * Some things no baseline can excuse, because people copy these files (2026-11-05, session
    f3daac6e; AIR record finding:2026-11-05:3a00300d16: one empty file, six cut-off files and a
    missing test file sat here unnoticed):
      MISSING  the implementation or the tests file does not exist.
      BROKEN   a file does not parse: every template is parsed first, with the language's own parser.
    Either one fails the run even when the suite is listed in the baseline. A suite that exits
    cleanly without running a single test is a plain FAIL, not a PASS.

Usage
  python tools/run_suites.py --lang python                     # all systems, one language
  python tools/run_suites.py --lang go --systems webhooks      # a subset
  python tools/run_suites.py --lang rust --baseline ci/baseline.json --json out.json --summary out.md
  python tools/run_suites.py --lang python --update-baseline ci/baseline.json   # rewrite baseline
  python tools/run_suites.py --lang java --parse-only          # only parse every template

Exit code: 0 = no regressions, 1 = at least one regression, 2 = usage / setup error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "saas_templates"
DEPS = ROOT / ".deps"
EXT = {"python": "py", "javascript": "js", "typescript": "ts", "go": "go", "php": "php",
       "java": "java", "csharp": "cs", "rust": "rs"}
TIMEOUT = 300
BUDGET_SECONDS = 75 * 60   # stop starting new suites after this, so the summary and JSON are always written
NEVER_EXCUSED = {"MISSING", "BROKEN"}   # these fail the run even for a suite listed in the baseline

# One test = one function the contract names (test*/Test*), used when a framework gives no count.
TEST_FN = {
    "python": r"^\s*(?:async\s+)?def test\w*\s*\(",
    "javascript": r"\b(?:it|test)\s*\(\s*['\"`]",
    "typescript": r"\b(?:it|test)\s*\(\s*['\"`]",
    "go": r"^func Test\w*\s*\(",
    "php": r"\bfunction\s+test\w*\s*\(",
    "java": r"@Test\b|\bstatic\s+void\s+test\w*\s*\(",
    "csharp": r"\[(?:Fact|Theory|Test|TestMethod)\b|\bstatic\s+(?:async\s+Task|void)\s+Test\w*\s*\(",
    "rust": r"#\[(?:tokio::)?test\]",
}


def count_tests(lang: str, code: str) -> int:
    return len(re.findall(TEST_FN[lang], code, re.M))


def sh(cmd: list[str], cwd: Path, timeout: int = TIMEOUT, env: dict | None = None) -> tuple[int, str]:
    """Run a command; return (exit code, combined output). 124 = timeout, 127 = tool missing.

    [2026-11-03, session c6ee9a72] On Windows the first word is looked up through PATH and PATHEXT
    before running: npm, mvn and composer, and the shims in node_modules/.bin, are .cmd/.bat files
    there, which subprocess cannot start by their bare name. cmd.exe then runs those files and reads
    ^ & | < > ( ) in a bare argument as its own syntax (phpunit:^11 lost its caret and resolved to the
    advisory-blocked 11.0.0; jest's "(js|ts)" became a pipe), so such arguments are double-quoted.
    Linux (CI) is unchanged."""
    full_env = dict(os.environ, NO_COLOR="1", FORCE_COLOR="0", PYTHONDONTWRITEBYTECODE="1",
                    DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1", DOTNET_CLI_USE_MSBUILD_SERVER="0",
                    MSBUILDDISABLENODEREUSE="1", **(env or {}))
    if os.name == "nt":
        exe = shutil.which(cmd[0], path=full_env.get("PATH"))
        if exe:
            cmd = [exe, *cmd[1:]]
            if exe.lower().endswith((".bat", ".cmd")):
                cmd = " ".join([subprocess.list2cmdline([exe])] + [
                    '"' + a.replace('"', '""') + '"' if re.search(r'[\s^&|<>()%!"]', a) else a
                    for a in cmd[1:]])
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                           env=full_env, encoding="utf-8", errors="replace")
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        return 124, out + f"\n[timeout after {timeout}s]"
    except FileNotFoundError as e:
        return 127, f"[tool not found: {e}]"


def tail(out: str, scrub: list[Path], n: int = 40) -> str:
    """Last n non-empty lines, with temp-dir paths removed so reports are machine independent."""
    for p in scrub:
        out = out.replace(str(p) + "/", "").replace(str(p), ".")
    out = out.replace(str(ROOT) + "/", "")
    lines = [l for l in out.splitlines() if l.strip()]
    return "\n".join(lines[-n:])


def result(status: str, tests: int, detail: str = "") -> dict:
    return {"status": status, "tests": tests, "detail": detail}


def from_exit(rc: int, out: str, n: int, scrub: list[Path]) -> dict:
    if rc == 0:
        return result("PASS", n)
    return result("FAIL", n, f"exit {rc}\n" + tail(out, scrub))


# ------------------------------------------------------------------------------------ python
PY_REQ = ["pytest", "bcrypt", "PyJWT", "pyotp", "SQLAlchemy>=2.0,<2.1", "fastapi", "httpx", "redis",
          "fakeredis", "boto3", "moto>=4,<5", "stripe", "pydantic"]


def setup_python() -> Path:
    venv = DEPS / "python" / "venv"
    # [2026-11-03, session c6ee9a72] a Windows venv keeps its interpreter in Scripts\, not bin/
    py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not py.exists():
        (DEPS / "python").mkdir(parents=True, exist_ok=True)
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        subprocess.run([str(py), "-m", "pip", "install", "-q", *PY_REQ], check=True)
    return py


def run_python(impl: Path, tests: Path, tmp: Path, ctx: Path) -> dict:
    shutil.copy(impl, tmp / impl.name)
    shutil.copy(tests, tmp / tests.name)
    n = count_tests("python", tests.read_text(encoding="utf-8", errors="replace"))
    rc, out = sh([str(ctx), "-m", "pytest", "-q", "-p", "no:cacheprovider", tests.name], tmp)
    if rc == 5:
        return result("FAIL", n, "pytest collected no tests\n" + tail(out, [tmp]))
    return from_exit(rc, out, n, [tmp])


# ----------------------------------------------------------------------- javascript / typescript
NODE_PKGS = {
    "express": "^4.19.2", "express-rate-limit": "^7.4.1", "body-parser": "^1.20.2", "cookie-parser": "^1.4.6", "csurf": "^1.11.0",
    "supertest": "^7.0.0", "stripe": "^16.0.0", "sqlite3": "^5.1.7", "sqlite": "^5.1.1",
    "better-sqlite3": "^11.0.0", "knex": "^3.1.0", "nodemailer": "^6.9.13",
    "@aws-sdk/client-s3": "^3.588.0", "@aws-sdk/s3-request-presigner": "^3.588.0", "uuid": "^9.0.1",
    "speakeasy": "^2.0.0", "sinon": "^18.0.0", "moment": "^2.30.1", "jsonwebtoken": "^9.0.2",
    "bcrypt": "^5.1.1", "bcryptjs": "^2.4.3", "jest": "^29.7.0", "@jest/globals": "^29.7.0",
    "pg": "^8.12.0", "ioredis": "^5.4.1", "zod": "^3.23.8", "twilio": "^5.1.1", "date-fns": "^3.6.0",
    "mysql2": "^3.10.0", "vitest": "^1.6.0", "tsx": "^4.11.0", "@babel/core": "^7.24.6",
    "@babel/preset-env": "^7.24.6", "@babel/preset-typescript": "^7.24.6", "babel-jest": "^29.7.0",
}


def setup_node() -> Path:
    d = DEPS / "node"
    if not (d / "node_modules").exists():
        d.mkdir(parents=True, exist_ok=True)
        (d / "package.json").write_text(json.dumps(
            {"name": "aoi-deps", "version": "1.0.0", "private": True, "dependencies": NODE_PKGS}, indent=2))
        rc, out = sh(["npm", "install", "--no-audit", "--no-fund"], d, 1200)
        if rc != 0:
            raise RuntimeError("npm install failed:\n" + tail(out, [], 30))
    (d / "run").mkdir(exist_ok=True)
    return d


def run_node(lang: str):
    def _run(impl: Path, tests: Path, tmp: Path, ctx: Path) -> dict:
        # stage inside .deps/node/run so node resolves ../../node_modules
        stage = Path(tempfile.mkdtemp(dir=ctx / "run", prefix=f"{lang}_"))
        try:
            shutil.copy(impl, stage / impl.name)
            shutil.copy(tests, stage / tests.name)
            code = tests.read_text(encoding="utf-8", errors="replace")
            bin_ = ctx / "node_modules" / ".bin"
            if "vitest" in code:
                (stage / "vitest.config.mjs").write_text(
                    "import { defineConfig } from 'vitest/config';\n"
                    "export default defineConfig({ test: { include: ['*_tests.{js,ts}'], globals: true } });\n")
                cmd = [str(bin_ / "vitest"), "run", "--reporter=json", "--outputFile=r.json"]
            elif ("@jest/globals" in code or "jest." in code or "expect(" in code
                  or re.search(r"\b(describe|it)\s*\(", code)) and "node:test" not in code:
                (stage / "babel.config.cjs").write_text(
                    "module.exports = { presets: [['@babel/preset-env', { targets: { node: 'current' } }],"
                    " '@babel/preset-typescript'] };\n")
                cmd = [str(bin_ / "jest"), "--rootDir", ".", "--testRegex", r"_tests\.(js|ts)$",
                       "--json", "--outputFile", "r.json"]
            else:  # plain node:test / assert script
                runner = [str(bin_ / "tsx")] if lang == "typescript" else ["node"]
                rc, out = sh(runner + [tests.name], stage)
                return from_exit(rc, out, count_tests(lang, code), [stage])
            rc, out = sh(cmd, stage)
            rj = stage / "r.json"
            if rj.exists():
                data = json.loads(rj.read_text(encoding="utf-8", errors="replace") or "{}")
                n = int(data.get("numTotalTests", 0))
                if rc == 0 and n > 0 and int(data.get("numFailedTests", 0)) == 0:
                    return result("PASS", n)
                return result("FAIL", n, f"exit {rc}\n" + tail(out, [stage]))
            return result("FAIL", count_tests(lang, code), f"exit {rc}\n" + tail(out, [stage]))
        finally:
            shutil.rmtree(stage, ignore_errors=True)
    return _run


# ---------------------------------------------------------------------------------------- go
def setup_go() -> Path:
    d = DEPS / "go"
    d.mkdir(parents=True, exist_ok=True)
    return d


def run_go(impl: Path, tests: Path, tmp: Path, ctx: Path) -> dict:
    (tmp / "go.mod").write_text("module aoirun\n\ngo 1.22\n")
    shutil.copy(impl, tmp / impl.name)
    shutil.copy(tests, tmp / (tests.stem[:-len("_tests")] + "_test.go"))
    n = count_tests("go", tests.read_text(encoding="utf-8", errors="replace"))
    env = {"GOPATH": str(ctx / "gopath"), "GOCACHE": str(ctx / "gocache"), "GOFLAGS": "-mod=mod",
           "GOWORK": "off", "GOTOOLCHAIN": "auto", "GOTELEMETRY": "off", "CGO_ENABLED": "1"}
    rc, out = sh(["go", "mod", "tidy"], tmp, 600, env)
    if rc != 0:
        return result("FAIL", n, "go mod tidy failed\n" + tail(out, [tmp]))
    rc, out = sh(["go", "test", "-count=1", "."], tmp, TIMEOUT, env)
    return from_exit(rc, out, n, [tmp])


# --------------------------------------------------------------------------------------- php
def setup_php() -> Path:
    d = DEPS / "php"
    if not (d / "vendor" / "autoload.php").exists():
        d.mkdir(parents=True, exist_ok=True)
        rc, out = sh(["composer", "require", "--no-interaction", "--quiet", "phpunit/phpunit:^11",
                      "stripe/stripe-php"], d, 900)
        if rc != 0:
            raise RuntimeError("composer require failed:\n" + tail(out, [], 30))
    return d


def run_php(impl: Path, tests: Path, tmp: Path, ctx: Path) -> dict:
    shutil.copy(impl, tmp / impl.name)
    code = tests.read_text(encoding="utf-8", errors="replace")
    # A self-running script has no test functions: each check is one $runner->assert...() call (2026-11-05, session f3daac6e).
    n = count_tests("php", code) or len(re.findall(r"->assert\w*\(", code))
    m = re.search(r"^\s*(?:final\s+)?class\s+(\w+)\s+extends\s+\\?(?:PHPUnit\\Framework\\)?TestCase", code, re.M)
    if m:  # PHPUnit style
        shutil.copy(tests, tmp / f"{m.group(1)}.php")
        (tmp / "bootstrap.php").write_text(f"<?php require '{ctx / 'vendor' / 'autoload.php'}';\n")
        rc, out = sh(["php", str(ctx / "vendor" / "bin" / "phpunit"), "--bootstrap", "bootstrap.php",
                      f"{m.group(1)}.php"], tmp)
    else:  # self-running script: exits non-zero on failure
        shutil.copy(tests, tmp / tests.name)
        rc, out = sh(["php", tests.name], tmp)
    return from_exit(rc, out, n, [tmp])


# -------------------------------------------------------------------------------------- java
POM = """<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>aoi</groupId><artifactId>deps</artifactId><version>1.0-SNAPSHOT</version>
<dependencies>
%s
</dependencies></project>"""
JAVA_DEPS = [
    ("org.junit.platform", "junit-platform-console-standalone", "1.11.3"),
    ("org.junit.vintage", "junit-vintage-engine", "5.11.3"), ("junit", "junit", "4.13.2"),
    ("org.hamcrest", "hamcrest", "2.2"), ("org.mockito", "mockito-core", "5.14.2"),
    ("org.mockito", "mockito-junit-jupiter", "5.14.2"),
    ("com.fasterxml.jackson.core", "jackson-databind", "2.18.1"),
    ("com.google.code.gson", "gson", "2.11.0"), ("com.stripe", "stripe-java", "28.1.0"),
    # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] json-path (from spring-boot-starter-test) pulls slf4j-api 1.7.36,
    # which wins over the 2.x that logback 1.4 needs, and Spring Boot then stops with "LoggerFactory is not a Logback
    # LoggerContext" (java admin_system). Naming 2.0.11 directly makes Maven pick it.
    ("org.slf4j", "slf4j-api", "2.0.11"),
    ("com.auth0", "java-jwt", "4.4.0"), ("org.mindrot", "jbcrypt", "0.4"),
    ("com.h2database", "h2", "2.3.232"),
    ("org.springframework.boot", "spring-boot-starter-web", "3.2.2"),
    ("org.springframework.boot", "spring-boot-starter-test", "3.2.2"),
    ("org.springframework.boot", "spring-boot-starter-jdbc", "3.2.2"),
]


def setup_java() -> Path:
    d = DEPS / "java"
    if not list((d / "lib").glob("*.jar")):
        d.mkdir(parents=True, exist_ok=True)
        deps = "\n".join(f"<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>"
                         f"<version>{v}</version></dependency>" for g, a, v in JAVA_DEPS)
        (d / "pom.xml").write_text(POM % deps)
        rc, out = sh(["mvn", "-q", "-B", "dependency:copy-dependencies", "-DoutputDirectory=lib"], d, 1500)
        if rc != 0:
            raise RuntimeError("mvn dependency:copy-dependencies failed:\n" + tail(out, [], 30))
    return d


def run_java(impl: Path, tests: Path, tmp: Path, ctx: Path) -> dict:
    ic, tc = impl.read_text(encoding="utf-8", errors="replace"), tests.read_text(encoding="utf-8", errors="replace")
    n = count_tests("java", tc)
    # javac requires the file be named after its public type
    files = []
    for name, code in ((impl.name, ic), (tests.name, tc)):
        t = re.search(r"^public\s+(?:final\s+|abstract\s+|sealed\s+)*(?:class|interface|record|enum)\s+(\w+)", code, re.M)
        p = tmp / (f"{t.group(1)}.java" if t else name)
        p.write_text(code, encoding="utf-8")
        files.append(p.name)
    cp = os.pathsep.join(str(j) for j in sorted((ctx / "lib").glob("*.jar")))
    rc, out = sh(["javac", "-encoding", "UTF-8", "-proc:none", "-cp", cp, "-d", "out", *files], tmp)
    if rc != 0:
        return result("FAIL", n, f"compile error (exit {rc})\n" + tail(out, [tmp]))
    if re.search(r"org\.junit\.(jupiter|Test)", tc):
        jar = next((ctx / "lib").glob("junit-platform-console-standalone-*.jar"))
        rc, out = sh(["java", "-jar", str(jar), "execute", "--class-path", f"out{os.pathsep}{cp}",
                      "--scan-class-path", "out", "--disable-banner", "--details=summary",
                      "--reports-dir", "rep"], tmp)
        total = 0
        for x in (tmp / "rep").glob("TEST-*.xml"):
            try:
                total += int(ET.parse(x).getroot().attrib.get("tests", 0))
            except ET.ParseError:
                pass
        if rc == 0 and total == 0:
            return result("FAIL", 0, "JUnit ran but discovered no tests")
        return from_exit(rc, out, total or n, [tmp])
    main = re.search(r"public\s+static\s+void\s+main\s*\(", tc)
    cls = re.search(r"^public\s+(?:final\s+)?class\s+(\w+)", tc, re.M)
    if not (main and cls):
        return result("FAIL", n, "tests file has neither JUnit tests nor a public static void main")
    pkg = re.search(r"^\s*package\s+([\w.]+)\s*;", tc, re.M)
    rc, out = sh(["java", "-cp", f"out{os.pathsep}{cp}", f"{pkg.group(1)}.{cls.group(1)}" if pkg else cls.group(1)], tmp)
    return from_exit(rc, out, n, [tmp])


# -------------------------------------------------------------------------------------- C#
CS_PKGS = {
    "Microsoft.NET.Test.Sdk": "17.11.1", "xunit": "2.9.0", "xunit.runner.visualstudio": "2.8.2",
    "Moq": "4.20.72", "BCrypt.Net-Next": "4.0.3", "Microsoft.EntityFrameworkCore": "8.0.8",
    "Microsoft.EntityFrameworkCore.InMemory": "8.0.8", "Microsoft.EntityFrameworkCore.Sqlite": "8.0.8",
    "Microsoft.Extensions.Caching.Memory": "8.0.0", "Microsoft.Extensions.Configuration": "8.0.0",
    "Microsoft.Extensions.Configuration.Json": "8.0.0", "Microsoft.Extensions.DependencyInjection": "8.0.0",
    "Microsoft.Extensions.Hosting": "8.0.0", "Microsoft.Extensions.Logging": "8.0.0",
    "Microsoft.Extensions.Logging.Console": "8.0.0", "Microsoft.AspNetCore.Mvc.Testing": "8.0.8",
    "Stripe.net": "44.13.0", "StackExchange.Redis": "2.8.16", "Otp.NET": "1.4.0",
    "Newtonsoft.Json": "13.0.3", "Microsoft.Data.Sqlite": "8.0.8", "Dapper": "2.1.35",
    "System.IdentityModel.Tokens.Jwt": "7.6.2", "Microsoft.IdentityModel.Tokens": "7.6.2",
    "Microsoft.Data.SqlClient": "5.2.2",
}


def csproj(test_sdk: bool, has_main: bool) -> str:
    refs = "\n".join(f'<PackageReference Include="{k}" Version="{v}" />' for k, v in CS_PKGS.items())
    out_type = "" if test_sdk else "<OutputType>Exe</OutputType><AssemblyName>run</AssemblyName>"
    return ('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework>'
            f'{out_type}<IsPackable>false</IsPackable><ImplicitUsings>enable</ImplicitUsings>'
            "<Nullable>disable</Nullable><LangVersion>latest</LangVersion>"
            "<EnableDefaultCompileItems>false</EnableDefaultCompileItems>"
            f"{'<GenerateProgramFile>false</GenerateProgramFile>' if has_main else ''}<TreatWarningsAsErrors>false</TreatWarningsAsErrors>"
            '</PropertyGroup><ItemGroup><Compile Include="Impl.cs;Tests.cs" /></ItemGroup>'
            f'<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" />{refs}</ItemGroup></Project>')


def setup_csharp() -> Path:
    d = DEPS / "csharp"
    d.mkdir(parents=True, exist_ok=True)
    return d


def run_csharp(impl: Path, tests: Path, tmp: Path, ctx: Path) -> dict:
    ic, tc = impl.read_text(encoding="utf-8", errors="replace"), tests.read_text(encoding="utf-8", errors="replace")
    n = count_tests("csharp", tc)
    xunit = bool(re.search(r"\[(Fact|Theory)\b", tc))
    has_main = bool(re.search(r"static\s+(?:async\s+)?(?:Task|void|int)\s+Main\s*\(", ic + tc))
    (tmp / "run.csproj").write_text(csproj(xunit, has_main))
    (tmp / "Impl.cs").write_text(ic, encoding="utf-8")
    (tmp / "Tests.cs").write_text(tc, encoding="utf-8")
    env = {"NUGET_PACKAGES": str(ctx / "packages"), "DOTNET_CLI_HOME": str(ctx / "home")}
    if xunit:
        rc, out = sh(["dotnet", "test", "-nologo", "-v:q"], tmp, 900, env)
        return from_exit(rc, out, n, [tmp])
    rc, out = sh(["dotnet", "build", "-nologo", "-v:q", "-o", "bin"], tmp, 900, env)
    if rc != 0:
        errs = "\n".join(dict.fromkeys(l for l in out.splitlines() if " error " in l)) or out
        return result("FAIL", n, f"build error (exit {rc})\n" + tail(errs, [tmp]).replace("Impl.cs", impl.name).replace("Tests.cs", tests.name))
    rc, out = sh(["dotnet", "bin/run.dll"], tmp, TIMEOUT, env)
    return from_exit(rc, out, n, [tmp])


# ------------------------------------------------------------------------------------- Rust
CRATES = {
    "serde": 'serde = { version = "1", features = ["derive"] }', "serde_json": 'serde_json = "1"',
    "chrono": 'chrono = { version = "0.4", features = ["serde"] }',
    "uuid": 'uuid = { version = "1", features = ["v4", "serde"] }',
    "tokio": 'tokio = { version = "1", features = ["full"] }',
    "sqlx": 'sqlx = { version = "0.7", features = ["runtime-tokio-native-tls", "postgres", "sqlite"] }',
    "rusqlite": 'rusqlite = { version = "0.31", features = ["bundled"] }',
    "diesel": 'diesel = { version = "2.1", features = ["sqlite", "r2d2"] }', "mockall": 'mockall = "0.12"',
    "rand": 'rand = "0.8"', "base64": 'base64 = "0.21"', "bcrypt": 'bcrypt = "0.15"',
    "jsonwebtoken": 'jsonwebtoken = "9"', "redis": 'redis = "0.24"', "r2d2": 'r2d2 = "0.8"',
    "r2d2_sqlite": 'r2d2_sqlite = "0.24"', "totp_rs": 'totp-rs = "5"', "hmac": 'hmac = "0.12"',
    "sha2": 'sha2 = "0.10"', "thiserror": 'thiserror = "1"', "regex": 'regex = "1"',
    "async_trait": 'async-trait = "0.1"', "stripe": 'stripe = { package = "async-stripe", version = "0.41", features = ["runtime-tokio-hyper"] }',
    "aws_config": 'aws-config = "1"', "aws_sdk_s3": 'aws-sdk-s3 = "1"', "lettre": 'lettre = "0.11"',
}


def setup_rust() -> Path:
    d = DEPS / "rust"
    d.mkdir(parents=True, exist_ok=True)
    return d


def run_rust(impl: Path, tests: Path, tmp: Path, ctx: Path) -> dict:
    ic, tc = impl.read_text(encoding="utf-8", errors="replace"), tests.read_text(encoding="utf-8", errors="replace")
    n = count_tests("rust", tc)
    words = set(re.findall(r"\b\w+\b", ic + "\n" + tc))
    deps = "\n".join(v for k, v in CRATES.items() if k in words)
    stem = impl.stem
    (tmp / "src").mkdir()
    # How the tests reach the implementation: `use super::*` (child module), `use <stem>` (integration
    # test against a lib crate), or `mod <stem>;` (tests are the crate root).
    if re.search(rf"\bmod\s+{stem}\s*;", tc):
        (tmp / "src" / "lib.rs").write_text(tc, encoding="utf-8")
        (tmp / "src" / f"{stem}.rs").write_text(ic, encoding="utf-8")
        lib = ""
    elif re.search(rf"\buse\s+{stem}\b|\b{stem}::", tc):
        (tmp / "tests").mkdir()
        (tmp / "src" / "lib.rs").write_text(ic, encoding="utf-8")
        (tmp / "tests" / "it.rs").write_text(tc, encoding="utf-8")
        lib = f'\n[lib]\nname = "{stem}"\npath = "src/lib.rs"\n'
    else:
        (tmp / "src" / "lib.rs").write_text(ic + '\n\n#[cfg(test)]\n#[path = "tests.rs"]\nmod aoi_tests;\n', encoding="utf-8")
        (tmp / "src" / "tests.rs").write_text(tc, encoding="utf-8")
        lib = ""
    (tmp / "Cargo.toml").write_text(
        f'[package]\nname = "aoi_test_run"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n{deps}\n{lib}')
    env = {"CARGO_TARGET_DIR": str(ctx / "target")}
    rc, out = sh(["cargo", "test", "--quiet"], tmp, 900, env)
    return from_exit(rc, out, n, [tmp])


LANGS = {
    "python": (setup_python, run_python), "javascript": (setup_node, run_node("javascript")),
    "typescript": (setup_node, run_node("typescript")), "go": (setup_go, run_go),
    "php": (setup_php, run_php), "java": (setup_java, run_java), "csharp": (setup_csharp, run_csharp),
    "rust": (setup_rust, run_rust),
}


# ------------------------------------------------------------------------------ parsing
JAVA_PARSE_ONLY = """
import com.sun.source.util.JavacTask;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.tools.*;

public class ParseOnly {
    public static void main(String[] files) throws Exception {
        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        DiagnosticCollector<JavaFileObject> found = new DiagnosticCollector<>();
        try (StandardJavaFileManager fm = javac.getStandardFileManager(found, null, StandardCharsets.UTF_8)) {
            ((JavacTask) javac.getTask(null, fm, found, List.of("-proc:none"), null, fm.getJavaFileObjects(files))).parse();
        }
        for (Diagnostic<? extends JavaFileObject> d : found.getDiagnostics()) {
            if (d.getKind() == Diagnostic.Kind.ERROR) {
                System.out.println(d.getSource().getName() + "\\t" + d.getLineNumber() + ": " + d.getMessage(null));
            }
        }
    }
}
"""
TS_PARSE_ONLY = """
const esbuild = require(process.argv[2]);
const fs = require('fs');
for (const f of process.argv.slice(3)) {
  try {
    esbuild.transformSync(fs.readFileSync(f, 'utf8'), { loader: 'ts', logLevel: 'silent' });
  } catch (e) {
    const m = e.errors && e.errors[0];
    console.log(f + '\\t' + (m ? `${m.location ? m.location.line : '?'}: ${m.text}` : String(e)));
  }
}
"""


def first_line(text: str) -> str:
    """The first non-empty line of a tool's output, kept short for a report."""
    return next((l.strip() for l in text.splitlines() if l.strip()), "no message")[:200]


def need_tool(rc: int, out: str, tool: str) -> None:
    """Stop the run when a parser is not installed: a check that cannot run must never read as a pass."""
    if rc == 127:
        raise RuntimeError(f"{tool} is needed to parse the templates: {out}")


def csharp_compiler() -> Path:
    """The Roslyn compiler inside the newest installed .NET SDK. Raises RuntimeError when there is none."""
    rc, out = sh(["dotnet", "--list-sdks"], ROOT)
    need_tool(rc, out, "dotnet")
    sdks = re.findall(r"^(\S+) \[(.+)\]\s*$", out, re.M)
    if not sdks:
        raise RuntimeError(f"no .NET SDK found: {out}")
    version, root = sdks[-1]
    return Path(root) / version / "Roslyn" / "bincore" / "csc.dll"


def parse_failures(lang: str, files: list[Path], ctx: Path) -> dict[str, str]:
    """Parse each file with the language's own parser, without compiling or running it.

    Why: a cut-off file can hide behind a suite that already fails for another reason, and a suite
    in the baseline is never looked at. Reading each file's last line found six such files on
    2026-11-05; this finds them every run. Session f3daac6e, AIR record finding:2026-11-05:3a00300d16.
    In: the language, the files, the language's .deps folder (TypeScript's parser lives there).
    Out: {file name: first error}, empty when all of them parse. Raises RuntimeError when the
    parser is not installed. Touches: temp files only; runs the parsers, never the code.
    """
    bad: dict[str, str] = {}
    tmp = Path(tempfile.mkdtemp(prefix=f"aoi_parse_{lang}_"))
    try:
        if lang == "python":
            for f in files:
                try:
                    compile(f.read_bytes(), f.name, "exec", dont_inherit=True)
                except (SyntaxError, ValueError) as e:
                    bad[f.name] = f"{getattr(e, 'lineno', '?')}: {getattr(e, 'msg', e)}"
        elif lang == "javascript":
            for f in files:
                rc, out = sh(["node", "--check", str(f)], tmp)
                need_tool(rc, out, "node")
                if rc != 0:
                    bad[f.name] = next((l.strip() for l in out.splitlines() if "Error" in l), first_line(out))[:200]
        elif lang == "typescript":
            script = tmp / "parse_only.cjs"
            script.write_text(TS_PARSE_ONLY, encoding="utf-8")
            rc, out = sh(["node", str(script), str(ctx / "node_modules" / "esbuild"), *map(str, files)], tmp)
            need_tool(rc, out, "node")
            if rc != 0:
                raise RuntimeError("the TypeScript parser did not run:\n" + tail(out, [tmp], 10))
            for line in out.splitlines():
                if "\t" in line:
                    name, message = line.split("\t", 1)
                    bad.setdefault(Path(name).name, message[:200])
        elif lang == "go":
            for f in files:
                rc, out = sh(["gofmt", "-e", "-l", str(f)], tmp)
                need_tool(rc, out, "gofmt")
                if rc != 0:
                    bad[f.name] = first_line(out.replace(str(f) + ":", ""))
        elif lang == "php":
            for f in files:
                rc, out = sh(["php", "-l", str(f)], tmp)
                need_tool(rc, out, "php")
                if rc != 0:
                    bad[f.name] = first_line(out.replace(str(f), f.name))
        elif lang == "java":
            script = tmp / "ParseOnly.java"
            script.write_text(JAVA_PARSE_ONLY, encoding="utf-8")
            rc, out = sh(["java", str(script), *map(str, files)], tmp)
            need_tool(rc, out, "java")
            if rc != 0:
                raise RuntimeError("the Java parser did not run:\n" + tail(out, [tmp], 10))
            for line in out.splitlines():
                if "\t" in line:
                    name, message = line.split("\t", 1)
                    bad.setdefault(Path(name).name, message[:200])
        elif lang == "csharp":
            csc = csharp_compiler()
            for f in files:
                # With no standard library the compiler always stops at CS0518 once parsing is done,
                # and it never reaches that point when the file has a syntax error.
                rc, out = sh(["dotnet", str(csc), "-nologo", "-noconfig", "-nostdlib+", "-t:library",
                              f"-out:{tmp / 'parse.dll'}", str(f)], tmp)
                need_tool(rc, out, "dotnet")
                errors = re.findall(r"error (CS\d+): (.*)", out)
                if not errors:   # without the standard library csc always reports something; silence means it never ran
                    raise RuntimeError(f"the C# compiler did not run: {first_line(out)}")
                if not any(code == "CS0518" for code, _ in errors):
                    line = re.search(r"\((\d+),\d+\): error", out)
                    bad[f.name] = f"{line.group(1) if line else '?'}: {errors[0][0]} {errors[0][1]}"[:200]
        elif lang == "rust":
            for f in files:
                rc, out = sh(["rustfmt", "--edition", "2021", "--emit", "stdout", str(f)], tmp)
                need_tool(rc, out, "rustfmt")
                if rc != 0:
                    bad[f.name] = next((l.strip() for l in out.splitlines() if l.startswith("error")), first_line(out))[:200]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return bad


# ----------------------------------------------------------------------------------- reporting
def systems_for(lang: str) -> list[str]:
    """Every system with an implementation or a tests file. In: a language. Out: sorted names.
    Both kinds count, so a tests file whose implementation is gone shows as MISSING too (2026-11-05, session f3daac6e)."""
    ext = EXT[lang]
    names = {p.name[: -len(f"_{lang}.{ext}")] for p in (TEMPLATES / lang).glob(f"*_{lang}.{ext}")}
    names |= {p.name[: -len(f"_{lang}_tests.{ext}")] for p in (TEMPLATES / lang).glob(f"*_{lang}_tests.{ext}")}
    return sorted(names)


def key(lang: str, system: str) -> str:
    return f"{system}/{lang}"


def render_summary(lang: str, res: dict, baseline: set[str], regress: list[str], fixed: list[str]) -> str:
    icon = {"PASS": "✅", "FAIL": "❌", "MISSING": "⛔", "BROKEN": "⛔"}
    rows = ["| system | status | tests | known failing |", "|---|---|---|---|"]
    for system, r in sorted(res.items()):
        rows.append(f"| {system} | {icon.get(r['status'], '❔')} {r['status']} | {r['tests']} | "
                    f"{'yes' if key(lang, system) in baseline else ''} |")
    npass = sum(1 for r in res.values() if r["status"] == "PASS")
    out = [f"### {lang}: {npass}/{len(res)} suites pass", "", *rows, ""]
    if regress:
        out += ["**Regressions (not passing, and either not in the baseline or MISSING/BROKEN, which it cannot "
                "excuse):** " + ", ".join(regress), ""]
    if fixed:
        out += ["**Newly passing (remove from `ci/baseline.json`):** " + ", ".join(fixed), ""]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lang", required=True, choices=sorted(LANGS))
    ap.add_argument("--systems", help="comma-separated system names (default: all)")
    ap.add_argument("--baseline", help="JSON file: {\"known_failing\": [\"system/lang\", ...]}")
    ap.add_argument("--update-baseline", help="rewrite this baseline file from this run's failures")
    ap.add_argument("--json", help="write per-suite results here")
    ap.add_argument("--summary", help="append a markdown table here (e.g. $GITHUB_STEP_SUMMARY)")
    ap.add_argument("--parse-only", action="store_true", help="only parse every template; exit 1 if one does not parse")
    a = ap.parse_args()

    setup, run = LANGS[a.lang]
    names = systems_for(a.lang)
    if a.systems:
        names = [s for s in names if s in set(a.systems.split(","))]
    ext = EXT[a.lang]
    try:
        ctx = setup()
        # [2026-11-05, session f3daac6e] every template is parsed, also those of a --systems subset
        broken = parse_failures(a.lang, sorted((TEMPLATES / a.lang).glob(f"*.{ext}")), ctx)
    except Exception as e:  # setup problems are infrastructure errors, not test results
        print(f"SETUP ERROR ({a.lang}): {e}", file=sys.stderr)
        return 2
    if a.parse_only:
        for name, why in sorted(broken.items()):
            print(f"BROKEN {name}: {why}")
        print(f"{a.lang}: {len(broken)} of {len(list((TEMPLATES / a.lang).glob(f'*.{ext}')))} files do not parse")
        return 1 if broken else 0

    baseline: set[str] = set()
    if a.baseline and Path(a.baseline).is_file():
        baseline = set(json.loads(Path(a.baseline).read_text())["known_failing"])
    started = time.monotonic()
    res: dict[str, dict] = {}
    for s in names:
        impl = TEMPLATES / a.lang / f"{s}_{a.lang}.{ext}"
        tests = TEMPLATES / a.lang / f"{s}_{a.lang}_tests.{ext}"
        absent = [p.name for p in (impl, tests) if not p.is_file()]
        unparsed = [f"{p.name}: {broken[p.name]}" for p in (impl, tests) if p.name in broken]
        if absent:
            r = result("MISSING", 0, "not in the library: " + ", ".join(absent))
        elif unparsed:
            r = result("BROKEN", 0, "does not parse: " + "; ".join(unparsed))
        elif time.monotonic() - started > BUDGET_SECONDS:
            r = result("FAIL", 0, "skipped: run time budget exhausted")
        else:
            # A suite expected to pass gets ONE retry, so a timing blip on a shared runner is not a
            # regression. Known-failing suites are never retried. The test itself is never changed.
            attempts = 1 if key(a.lang, s) in baseline else 2
            for _ in range(attempts):
                tmp = Path(tempfile.mkdtemp(prefix=f"aoi_{a.lang}_"))
                try:
                    r = run(impl, tests, tmp, ctx)
                except Exception as e:  # a runner bug must not hide the other suites
                    r = result("FAIL", 0, f"runner error: {e!r}")
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)
                if r["status"] == "PASS" and r["tests"] == 0:
                    r = result("FAIL", 0, "exited cleanly without running a single test")
                if r["status"] == "PASS":
                    break
        res[s] = r
        print(f"{s:<28} {r['status']:<8} tests={r['tests']:<3} "
              f"{r['detail'].splitlines()[0][:80] if r['detail'] else ''}", flush=True)

    regress = [s for s, r in res.items()
               if r["status"] in NEVER_EXCUSED or (r["status"] != "PASS" and key(a.lang, s) not in baseline)]
    fixed = [s for s, r in res.items() if r["status"] == "PASS" and key(a.lang, s) in baseline]

    if a.json:
        Path(a.json).write_text(json.dumps(res, indent=2))
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as f:
            f.write(render_summary(a.lang, res, baseline, regress, fixed) + "\n")
    if a.update_baseline:
        p = Path(a.update_baseline)
        keep = set(json.loads(p.read_text())["known_failing"]) if p.is_file() else set()
        keep = {k for k in keep if not k.endswith(f"/{a.lang}")}
        keep |= {key(a.lang, s) for s, r in res.items() if r["status"] == "FAIL"}   # MISSING and BROKEN are never listed
        p.write_text(json.dumps({"known_failing": sorted(keep)}, indent=2) + "\n")
    print(f"\n{a.lang}: {sum(r['status'] == 'PASS' for r in res.values())}/{len(res)} pass; "
          f"regressions={len(regress)}; newly passing={len(fixed)}")
    return 1 if regress else 0


if __name__ == "__main__":
    sys.exit(main())
