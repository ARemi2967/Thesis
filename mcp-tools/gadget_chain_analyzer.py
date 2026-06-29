#!/usr/bin/env python3
"""
Gadget Chain Analyzer - MCP Tool 1 (v3.0)
Analyzes java-chains.jar and generates minimal pom.xml for each chain recipe.

Core insight (from actual YAML inspection):
  - YAML `chain` field is an ORDERED PIPELINE of gadget component names,
    e.g. [CommonsBeanutils1, TemplatesImpl, BytecodeConvert, Exec]
  - It is NOT a dependency list — dependencies are implied by the component names
  - Most components are java-chains internal framework pieces (no external Maven deps)
  - Only ~20 components require real third-party library dependencies

Dependency resolution (3-tier priority):
  1. BOOT-INF/lib/  — scan actual JARs bundled in the fat JAR for real versions
  2. COMPONENT_DEP_MAP — component-name → (groupId, artifactId, fallback-version)
  3. Skip framework/internal components silently (BytecodeConvert, Exec, TemplatesImpl…)
"""

import os
import sys
import json
import zipfile
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from collections import defaultdict

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("Warning: PyYAML not installed. Run: pip install pyyaml")


# ---------------------------------------------------------------------------
# Component → Maven coordinate mapping
#
# Each entry:  component_name -> list of (groupId, artifactId, fallback_version)
#
# "fallback_version" is used only when the artifact is NOT found in BOOT-INF/lib/.
# Versions here were cross-verified against the java-chains ShowGadget page.
#
# Rules for adding entries:
#   - Only add components that need REAL third-party Maven dependencies
#   - Framework internals (BytecodeConvert, Exec, TemplatesImpl, etc.) are NOT listed
#     here — the resolver will simply skip them (they live inside java-chains itself)
#   - One component can require multiple Maven artifacts (list of tuples)
# ---------------------------------------------------------------------------
COMPONENT_DEP_MAP: Dict[str, List[Tuple[str, str, str]]] = {
    # Commons BeanUtils
    "CommonsBeanutils1": [
        ("commons-beanutils", "commons-beanutils", "1.9.4"),
        ("commons-logging",   "commons-logging",   "1.2"),
    ],
    "CommonsBeanutils2": [
        ("commons-beanutils", "commons-beanutils", "1.8.2"),
        ("commons-logging",   "commons-logging",   "1.1.1"),
    ],

    # Commons Collections
    "CommonsCollectionsK1": [
        ("commons-collections", "commons-collections", "3.2.1"),
    ],
    "CommonsCollectionsK2": [
        ("org.apache.commons", "commons-collections4", "4.0"),
    ],
    "CommonsCollectionsK3": [
        ("commons-collections", "commons-collections", "3.2.1"),
    ],
    "CommonsCollectionsK4": [
        ("org.apache.commons", "commons-collections4", "4.0"),
    ],

    # Fastjson
    "Fastjson": [
        ("com.alibaba", "fastjson", "1.2.83"),
    ],
    "FastjsonToString1": [
        ("com.alibaba", "fastjson", "1.2.83"),
    ],
    "Fastjson2": [
        ("com.alibaba.fastjson2", "fastjson2", "2.0.26"),
    ],

    # Jackson
    "Jackson": [
        ("com.fasterxml.jackson.core", "jackson-databind", "2.11.4"),
        ("com.fasterxml.jackson.core", "jackson-core",     "2.11.4"),
    ],
    "JacksonToString": [
        ("com.fasterxml.jackson.core", "jackson-databind", "2.11.4"),
    ],

    # Rome RSS
    "Rome1": [
        ("rome", "rome", "1.0"),
    ],
    "Rome2": [
        ("com.rometools", "rome", "1.7.0"),
    ],

    # C3P0 connection pool
    #
    # Original components (old java-chains names)
    "C3p0DataSource": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    "C3p0DataSource2": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    "C3p0DataSource3": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    "C3p0DataSource4": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    "C3p0Reference": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    "C3P0WrapperConnPool": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    #
    # 1.4.4 new: C3p0_* prefix variants (same dependency, different class entry points)
    "C3p0_C3p0Reference": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    "C3p0_C3p0Jndi": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    "C3p0_C3p0Jndi2": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    "C3p0_C3p0HexSerialize": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    #
    # 1.4.4 new: Mchange* prefix variants (com.mchange groupId, same dep)
    # MchangeC3p0Reference: supports LDAP remote bytecode load, works on c3p0 0.9.1.2~0.10.1
    #   0.9.5.5 can retrigger same class name bytecode (0.10.1 cannot)
    "MchangeC3p0Reference": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    "MchangeC3p0Jndi": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    "MchangeC3p0Jndi2": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],
    # MchangeC3p0HexSerialize: WrapperConnectionPoolDataSource secondary deserialization
    "MchangeC3p0HexSerialize": [
        ("com.mchange", "c3p0", "0.9.5.5"),
    ],

    # XBean (for Hessian XBean chain)
    "XBeanToString": [
        ("org.apache.xbean", "xbean-naming", "4.20"),
    ],

    # Tomcat EL (JNDI ResourceRef chain)
    "TomcatElRef": [
        ("org.apache.tomcat.embed", "tomcat-embed-core", "9.0.43"),
    ],

    # Groovy
    "GroovyShellRef": [
        ("org.codehaus.groovy", "groovy", "2.4.21"),
    ],

    # SnakeYAML
    "SnakeyamlRef": [
        ("org.yaml", "snakeyaml", "1.26"),
    ],

    # BeanShell
    "BeanshellRef": [
        ("org.beanshell", "bsh", "2.0b5"),
    ],

    # HikariCP JDBC attack
    "HikariJdbcAttack": [
        ("com.zaxxer", "HikariCP", "3.4.5"),
    ],

    # Druid JDBC attack
    "DruidJdbcAttack": [
        ("com.alibaba", "druid", "1.2.16"),
    ],

    # H2 database (JDBC exploit)
    # MUST use 1.4.199: java-chains H2 JDBC payloads use INIT=RUNSCRIPT/CREATE ALIAS syntax
    # that requires H2 1.x security defaults. H2 2.x added restrictions that break payloads.
    "H2JavaJdbc1": [
        ("com.h2database", "h2", "1.4.199"),
    ],
    "H2JavaExecJdbc1": [
        ("com.h2database", "h2", "1.4.199"),
    ],

    # Axis2
    "Axis2MetaDataEntry": [
        ("org.apache.axis2", "axis2-kernel",         "1.7.9"),
        ("org.apache.axis2", "axis2-transport-http", "1.7.9"),
    ],

    # Spring (Hessian spring chains)
    "SpringAbstractBeanFactoryPointcutAdvisor": [
        ("org.springframework", "spring-aop",  "5.2.3.RELEASE"),
        ("org.springframework", "spring-core", "5.2.3.RELEASE"),
    ],
    "SpringPartiallyComparableAdvisorHolder": [
        ("org.springframework", "spring-aop",  "5.2.3.RELEASE"),
        ("org.springframework", "spring-core", "5.2.3.RELEASE"),
    ],
    "SpringExec": [
        ("org.springframework", "spring-core", "5.2.3.RELEASE"),
    ],
    "SpringJndi1": [
        ("org.springframework", "spring-core", "5.2.3.RELEASE"),
    ],

    # Hessian (for HessianSSRF / Hessian payload wrappers)
    "HessianPayload": [
        ("com.caucho", "hessian", "4.0.38"),
    ],
	    # ── 1.4.4 新增 ──
    "ClosureWithTemplatesImplSandboxed": [
        ("org.codehaus.groovy", "groovy", "2.4.7"),
        ("org.kohsuke", "groovy-sandbox", "1.19"),
    ],
    "ClosureWithRuntimeSandboxed": [
        ("org.codehaus.groovy", "groovy", "2.4.7"),
        ("org.kohsuke", "groovy-sandbox", "1.19"),
    ],
    "ClosureWithJNDISandboxed": [
        ("org.codehaus.groovy", "groovy", "2.4.7"),
        ("org.kohsuke", "groovy-sandbox", "1.19"),
    ],
    "MapProxy": [
        ("cn.hutool", "hutool-core", "5.8.11"),
    ],
    "Groovy反序列化链": [
        ("org.codehaus.groovy", "groovy", "2.4.21"),
    ],
    "GroovyGString": [
        ("org.codehaus.groovy", "groovy", "2.4.21"),
    ],
    "Groovy2GString": [
        ("org.codehaus.groovy", "groovy", "2.4.21"),
    ],
    "GStringCompareToToString": [
        ("org.codehaus.groovy", "groovy", "2.4.21"),
    ],
}

# Components that are java-chains internal framework pieces — no external deps needed.
# Listed explicitly so we can warn if an UNKNOWN component appears (might need a new entry).
FRAMEWORK_COMPONENTS: Set[str] = {
    "BytecodeConvert", "Exec", "Sleep", "DNSLogWithInfo",
    "FindClass", "FindClassByBomb",
    "JavaNativeSerialization", "JavaNativeSerializationCommonsCollectionsK3",
    "BcelConvert", "JsConvert", "ElConvert", "GroovyConvert",
    "BeanshellConvert", "SnakeyamlJarConvert", "SnakeyamlJarSpi4JNDI",
    "CharsetJarConvert2",
    "SignedObject", "TWrap", "DWrap",
    "TemplatesImpl", "TransformerWithTemplatesImpl",
    "LazyValueWithBcel", "LazyValueWithDS", "LazyValueWithJNDI",
    "ProxyLazyValueUIDefaults", "SwingLazyValueUIDefaults", "SwingLazyValueMethodUtil",
    "XsltOnlyJdk", "XsltSpring",
    "Jsp", "SpringBeanXmlClassLoader",
    "FakeMySQLReadFile", "RMIConnector",
    # JDK built-ins
    "JdbcRowSetImpl", "LdapAttribute", "LdapClassLoader",
	    # ── 1.4.4 新增 ──
    "LazyValueWithUrlClassLoader",        # 新 LazyValue 变体，加载本地 jar
    "JsConver3",                          # JS 字节码转换变体3
    "TWrapHighVersion",                   # Spring 动态代理处理高版本 JDK TemplatesImpl
    "XsltOnlyJdk2",                       # Xslt 链变体2（基于 JS，不依赖 Spring）
    "ExecCustom",                         # 执行任意命令的字节码
    "BypassJrmpClient",                   # Bypass 高版本 JDK JRMP
    "ClosureWithTemplatesImplSandboxed",  # Groovy 沙箱-TemplatesImpl
    "ClosureWithRuntimeSandboxed",        # Groovy 沙箱-命令执行
    "ClosureWithJNDISandboxed",           # Groovy 沙箱-JNDI
    "SpringBeanXMLDecoderClassLoader",    # Spring Bean XML + XMLDecoder
    "GStringCompareToToString",           # GString compareTo → toString
    "GroovyGString",                      # Hessian Groovy GString 链触发器
    "Groovy2GString",                     # GString 入口链
    "MapProxy",                           # hutool MapProxy 二次反序列化桥
    "FastJsonbBackDoor",                  # FastJsonb 后门类
    "MemShellPartyGadget",                # MemShellParty 内存马注入字节码
    "RuoYiShell",                         # RuoYi Shell 字节码
    # Echo 类（各中间件回显，均为 Bytecode tag）
    "ApusicEcho", "ResinEcho", "JettyEcho", "GlassFishEcho",
    "WebLogicEcho", "WebSphereEcho", "TongWebEcho", "UndertowEcho",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MavenArtifact:
    groupId: str
    artifactId: str
    version: str
    resolved_from: str = "component_map"   # "boot_inf_lib" | "component_map"


@dataclass
class GadgetChain:
    name: str
    description: str
    payload_types: List[str]
    pipeline: List[str]           # raw component names from YAML chain field
    maven_artifacts: List[Dict[str, str]]
    unknown_components: List[str] # components not in map and not in framework set


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class GadgetChainAnalyzer:

    def __init__(self, jar_path: str):
        self.jar_path = jar_path
        self.detected_chains: Dict[str, GadgetChain] = {}
        # artifact_name (without version) -> version string, populated from BOOT-INF/lib/
        self.lib_versions: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_jar(self) -> Dict[str, GadgetChain]:
        """Parse the JAR and return all chain recipes with resolved deps."""
        print(f"Analyzing {self.jar_path} ...")

        if not os.path.exists(self.jar_path):
            raise FileNotFoundError(f"JAR not found: {self.jar_path}")

        with zipfile.ZipFile(self.jar_path, "r") as jar:
            # Step 1: scan BOOT-INF/lib/ to collect actual bundled versions
            self._scan_boot_inf_lib(jar)

            # Step 2: read chain recipes from YAML
            chain_defs = self._load_yaml_chains(jar)

        # Step 3: for each recipe, resolve Maven deps from component pipeline
        for chain_def in chain_defs:
            chain = self._build_chain(chain_def)
            if chain:
                self.detected_chains[chain.name] = chain

        print(f"Loaded {len(self.detected_chains)} chain recipes")
        return self.detected_chains

    def save_results(self, output_dir: str = "gadget-dependencies") -> Dict[str, Any]:
        """Write gadget_chains_summary.json + one pom.xml per chain."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        summary = {
            "total_chains": len(self.detected_chains),
            "lib_versions_found": len(self.lib_versions),
            "chains": [self._chain_to_dict(c) for c in self.detected_chains.values()],
            "metadata": {
                "source_jar": str(Path(self.jar_path).resolve()),
                "analyzer_version": "3.0.0",
            },
        }

        summary_path = out / "gadget_chains_summary.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        print(f"Summary → {summary_path}")

        for chain in self.detected_chains.values():
            safe = re.sub(r"[^\w\-]", "_", chain.name)
            chain_dir = out / safe
            chain_dir.mkdir(parents=True, exist_ok=True)
            pom_path = chain_dir / "pom.xml"
            with open(pom_path, "w", encoding="utf-8") as f:
                f.write(self._generate_pom(chain))
            print(f"  pom.xml → {pom_path}")

        return summary

    # ------------------------------------------------------------------
    # Step 1: scan BOOT-INF/lib/ for real versions
    # ------------------------------------------------------------------

    def _scan_boot_inf_lib(self, jar: zipfile.ZipFile):
        """
        Parse filenames like BOOT-INF/lib/commons-beanutils-1.9.4.jar
        and build self.lib_versions: { "commons-beanutils": "1.9.4", ... }
        """
        lib_entries = [
            e for e in jar.namelist()
            if e.startswith("BOOT-INF/lib/") and e.endswith(".jar")
        ]
        print(f"Found {len(lib_entries)} JARs in BOOT-INF/lib/")

        for entry in lib_entries:
            filename = entry[len("BOOT-INF/lib/"):-4]  # strip prefix + .jar

            # Try: name-version  (version starts with digit)
            m = re.match(r"^(.+?)-(\d[\w.\-]*)$", filename)
            if m:
                artifact, version = m.group(1), m.group(2)
                # Keep the first (longest-artifact-name) match wins
                if artifact not in self.lib_versions:
                    self.lib_versions[artifact] = version
            else:
                # No version in filename — store as-is with empty version
                if filename not in self.lib_versions:
                    self.lib_versions[filename] = ""

        print(f"Extracted {len(self.lib_versions)} version entries from lib/")

    def _resolve_version(self, groupId: str, artifactId: str, fallback: str,
                     component_name: str = "") -> Tuple[str, str]:
        """
        Return the version from COMPONENT_DEP_MAP (the fallback parameter).

        COMPONENT_DEP_MAP versions are the authoritative vulnerable versions —
        verified against java-chains ShowGadget. They must NOT be overridden by
        BOOT-INF/lib/ versions because java-chains only bundles ONE version of each
        library for its own runtime use, which may differ from the version each chain
        actually exploits.

        Example: BOOT-INF/lib/ has commons-beanutils-1.8.3.jar (tool runtime),
        but CB1链 needs 1.9.4 and CB2链 needs 1.8.2 as the target vulnerable versions.

        lib_versions is still populated by _scan_boot_inf_lib for debug/reporting.
        """
        return fallback, "component_map"

    # ------------------------------------------------------------------
    # Step 2: load chain recipes from YAML
    # ------------------------------------------------------------------

    def _load_yaml_chains(self, jar: zipfile.ZipFile) -> List[Dict[str, Any]]:
        """
        Read BOOT-INF/classes/default-chains.yaml from the JAR.

        YAML structure (actual format confirmed from source):
          PayloadType1|PayloadType2|...:
            - name: "CB1链"
              desc: "..."
              chain: [ComponentA, ComponentB, ...]
        """
        yaml_path = "BOOT-INF/classes/default-chains.yaml"

        if yaml_path not in jar.namelist():
            print(f"WARNING: {yaml_path} not found in JAR — using built-in fallback")
            return self._fallback_chain_defs()

        if not YAML_AVAILABLE:
            print("WARNING: PyYAML not installed — using built-in fallback")
            return self._fallback_chain_defs()

        try:
            raw = jar.read(yaml_path).decode("utf-8")
            data = yaml.safe_load(raw)
        except Exception as e:
            print(f"WARNING: Failed to parse YAML: {e} — using built-in fallback")
            return self._fallback_chain_defs()

        definitions = []
        for key, items in (data or {}).items():
            if not isinstance(items, list):
                continue
            payload_types = [p.strip() for p in key.split("|")]
            for item in items:
                if not isinstance(item, dict) or "name" not in item:
                    continue
                definitions.append({
                    "name":          item.get("name", ""),
                    "desc":          item.get("desc", ""),
                    "pipeline":      item.get("chain", []),   # list of component names
                    "payload_types": payload_types,
                })

        print(f"Loaded {len(definitions)} chain recipes from YAML")
        return definitions

    def _fallback_chain_defs(self) -> List[Dict[str, Any]]:
        """Minimal fallback when YAML cannot be read."""
        return [
            {"name": "CB1链",  "desc": "CommonsBeanutils1 1.9.x",
             "pipeline": ["CommonsBeanutils1", "TemplatesImpl", "BytecodeConvert", "Exec"],
             "payload_types": ["JavaNativePayload"]},
            {"name": "K1链",   "desc": "CommonsCollections 3.2.1",
             "pipeline": ["CommonsCollectionsK1", "TemplatesImpl", "BytecodeConvert", "Exec"],
             "payload_types": ["JavaNativePayload"]},
            {"name": "K2链",   "desc": "CommonsCollections4 4.0",
             "pipeline": ["CommonsCollectionsK2", "TemplatesImpl", "BytecodeConvert", "Exec"],
             "payload_types": ["JavaNativePayload"]},
            {"name": "Fastjson链", "desc": "Fastjson 1.2.x",
             "pipeline": ["Fastjson", "TemplatesImpl", "BytecodeConvert", "Sleep"],
             "payload_types": ["JavaNativePayload"]},
            {"name": "Jackson链", "desc": "Jackson",
             "pipeline": ["Jackson", "TWrap", "TemplatesImpl", "BytecodeConvert", "Sleep"],
             "payload_types": ["JavaNativePayload"]},
        ]

    # ------------------------------------------------------------------
    # Step 3: resolve deps for each chain recipe
    # ------------------------------------------------------------------

    def _build_chain(self, chain_def: Dict[str, Any]) -> Optional[GadgetChain]:
        name = chain_def.get("name", "").strip()
        if not name:
            return None

        pipeline: List[str] = chain_def.get("pipeline", [])
        # normalize: handle both list and legacy string formats
        if isinstance(pipeline, str):
            pipeline = [s.strip() for s in pipeline.split(",") if s.strip()]

        # Walk every component in the pipeline and collect Maven deps
        seen_coords: Dict[str, MavenArtifact] = {}   # "groupId:artifactId" → artifact
        unknown: List[str] = []

        for component in pipeline:
            if component in FRAMEWORK_COMPONENTS:
                continue   # java-chains internal, no external dep

            if component in COMPONENT_DEP_MAP:
                for (gid, aid, fallback_ver) in COMPONENT_DEP_MAP[component]:
                    coord_key = f"{gid}:{aid}"
                    if coord_key in seen_coords:
                        continue  # already added by another component
                    real_ver, src = self._resolve_version(gid, aid, fallback_ver,
                                      component_name=component)
                    seen_coords[coord_key] = MavenArtifact(
                        groupId=gid, artifactId=aid,
                        version=real_ver, resolved_from=src,
                    )
            else:
                # Component is neither a known framework piece nor in our map
                unknown.append(component)

        if unknown:
            print(f"  [WARN] '{name}' has unknown components: {unknown}")

        return GadgetChain(
            name=name,
            description=chain_def.get("desc", ""),
            payload_types=chain_def.get("payload_types", []),
            pipeline=pipeline,
            maven_artifacts=[asdict(a) for a in seen_coords.values()],
            unknown_components=unknown,
        )

    # ------------------------------------------------------------------
    # pom.xml generation
    # ------------------------------------------------------------------

    def _generate_pom(self, chain: GadgetChain) -> str:
        # ASCII-only: [^a-z0-9\-] catches Chinese/Unicode that \w would pass through
        safe_id = re.sub(r"[^a-z0-9\-]", "-", chain.name.lower())
        safe_id = re.sub(r"-+", "-", safe_id).strip("-") or "chain"

        dep_lines = [
            "        <!-- Spring Boot Web (required for /deserialize endpoint) -->",
            "        <dependency>",
            "            <groupId>org.springframework.boot</groupId>",
            "            <artifactId>spring-boot-starter-web</artifactId>",
            "        </dependency>",
        ]

        for art in chain.maven_artifacts:
            gid  = art["groupId"]
            aid  = art["artifactId"]
            ver  = art["version"]
            src  = art.get("resolved_from", "")
            note = " (version from BOOT-INF/lib)" if src == "boot_inf_lib" else " (fallback version)"
            dep_lines += [
                f"",
                f"        <!-- {chain.name}: {aid}{note} -->",
                f"        <dependency>",
                f"            <groupId>{gid}</groupId>",
                f"            <artifactId>{aid}</artifactId>",
                f"            <version>{ver}</version>",
                f"        </dependency>",
            ]

        deps_block = "\n".join(dep_lines)

        # Pipeline comment for documentation
        pipeline_str = " → ".join(chain.pipeline)

        pom = f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.3.12.RELEASE</version>
        <relativePath/>
    </parent>

    <groupId>com.deserialization.lab</groupId>
    <artifactId>{safe_id}-env</artifactId>
    <version>1.0.0</version>
    <description>{chain.description or chain.name} — Payload types: {", ".join(chain.payload_types)}</description>

    <!--
        Chain pipeline: {pipeline_str}
        Generated by gadget_chain_analyzer v3.0
    -->

    <properties>
        <java.version>1.8</java.version>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
{deps_block}

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.8.1</version>
                <configuration>
                    <source>1.8</source>
                    <target>1.8</target>
                    <encoding>UTF-8</encoding>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
"""
        return pom

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _chain_to_dict(self, c: GadgetChain) -> Dict[str, Any]:
        return {
            "name":               c.name,
            "description":        c.description,
            "payload_types":      c.payload_types,
            "pipeline":           c.pipeline,
            "maven_artifacts":    c.maven_artifacts,
            "unknown_components": c.unknown_components,
        }

    # ------------------------------------------------------------------
    # LLM-facing query methods (for new MCP tools)
    # ------------------------------------------------------------------

    def query_component(self, component_name: str,
                        pipeline: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Query one component's dependency info for LLM reasoning.

        Returns MAP lookup result, pipeline context, BOOT-INF/lib versions,
        and a confidence level.
        """
        # MAP lookup
        map_entry = COMPONENT_DEP_MAP.get(component_name)
        is_framework = component_name in FRAMEWORK_COMPONENTS

        if map_entry:
            map_result = {
                "found": True,
                "dependencies": [
                    {"groupId": g, "artifactId": a, "version": v}
                    for g, a, v in map_entry
                ],
            }
            confidence = "exact_match"
        elif is_framework:
            map_result = {"found": True, "framework_internal": True,
                         "dependencies": []}
            confidence = "framework"
        else:
            map_result = {"found": False, "dependencies": []}
            confidence = "unknown"

        # Pipeline context — adjacent components' dependency status
        pipeline_context = []
        if pipeline:
            for comp in pipeline:
                if comp in COMPONENT_DEP_MAP:
                    deps = [{"groupId": g, "artifactId": a, "version": v}
                            for g, a, v in COMPONENT_DEP_MAP[comp]]
                    pipeline_context.append({"component": comp, "known": True,
                                             "dependencies": deps})
                elif comp in FRAMEWORK_COMPONENTS:
                    pipeline_context.append({"component": comp, "known": True,
                                             "framework_internal": True,
                                             "dependencies": []})
                else:
                    pipeline_context.append({"component": comp, "known": False,
                                             "dependencies": []})

        # BOOT-INF/lib version hints for related artifacts
        lib_hints: Dict[str, str] = {}
        if map_entry:
            for g, a, _v in map_entry:
                if a in self.lib_versions:
                    lib_hints[f"{g}:{a}"] = self.lib_versions[a]

        return {
            "component": component_name,
            "map_result": map_result,
            "pipeline_context": pipeline_context,
            "lib_version_hints": lib_hints,
            "confidence": confidence,
        }

    def resolve_new_chain_deps(self, chain_name: str,
                               pipeline: List[str],
                               payload_types: List[str]) -> Dict[str, Any]:
        """
        Analyze a new chain's pipeline and classify each component as
        known or unknown, for LLM to reason about.
        """
        components = []
        unknown_count = 0

        for comp in pipeline:
            if comp in COMPONENT_DEP_MAP:
                deps = [{"groupId": g, "artifactId": a, "version": v}
                        for g, a, v in COMPONENT_DEP_MAP[comp]]
                components.append({"name": comp, "status": "known",
                                   "maven_coords": deps})
            elif comp in FRAMEWORK_COMPONENTS:
                components.append({"name": comp, "status": "framework",
                                   "maven_coords": []})
            else:
                components.append({"name": comp, "status": "unknown",
                                   "maven_coords": []})
                unknown_count += 1

        # Suggest controller type using existing rules
        try:
            from vuln_env_generator import _pick_controller
            suggested_ctrl = _pick_controller(chain_name, payload_types)
        except Exception:
            suggested_ctrl = "NATIVE"

        return {
            "chain": {"name": chain_name, "pipeline": pipeline,
                      "payload_types": payload_types},
            "components": components,
            "unknown_count": unknown_count,
            "suggested_controller": suggested_ctrl,
            "ready_for_generation": unknown_count == 0,
        }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Gadget Chain Analyzer v3.0 — component-pipeline-aware dep resolution"
    )
    parser.add_argument("jar",    help="Path to java-chains.jar")
    parser.add_argument("output", nargs="?", default="gadget-dependencies",
                        help="Output directory (default: gadget-dependencies)")
    args = parser.parse_args()

    try:
        analyzer = GadgetChainAnalyzer(args.jar)
        chains   = analyzer.analyze_jar()
        summary  = analyzer.save_results(args.output)

        print()
        print("=" * 60)
        print(f"Done.  {len(chains)} chains  |  {len(analyzer.lib_versions)} lib versions resolved")
        print(f"Output: {Path(args.output).resolve()}")
        print("=" * 60)

    except Exception as exc:
        import traceback
        print(f"Error: {exc}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
