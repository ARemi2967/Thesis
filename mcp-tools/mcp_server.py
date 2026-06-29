#!/usr/bin/env python3
"""
MCP Server for Java Deserialization Analysis (v3.0)
Provides MCP tools for gadget chain analysis and environment generation.

Usage:
    # MCP server mode (stdio — for Claude Desktop etc.)
    python mcp_server.py

    # HTTP transport
    python mcp_server.py --transport http --port 8000

    # CLI / debug mode
    python mcp_server.py --cli --jar java-chains.jar --list
    python mcp_server.py --cli --jar java-chains.jar --chain CB1链
"""

import sys
import os
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

from gadget_chain_analyzer import GadgetChainAnalyzer, COMPONENT_DEP_MAP, FRAMEWORK_COMPONENTS
from vuln_env_generator import VulnerableEnvGenerator, explain_controller_rules
from llm_decision_log import log_decision, query_decisions, get_statistics

mcp = FastMCP(
    "Java Deserialization Analyzer",
    instructions="""
    MCP server for analyzing java-chains.jar gadget chains and generating test environments.

    Workflow:
    1. analyze_gadget_chains  — parse the JAR, resolve deps, write pom.xml files
    2. list_all_chains         — list every chain recipe found
    3. get_chain_details        — full pipeline + Maven artifacts for one chain
    4. get_pom_content          — read the generated pom.xml text
    5. generate_vuln_environment / generate_all_vuln_environments — build Spring Boot projects
    """,
)

# In-memory cache of the last successful analysis
_last_analysis_result: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Tool 1 — analyze
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_gadget_chains(
    jar_path: str,
    output_dir: str = "gadget-dependencies",
) -> Dict[str, Any]:
    """
    Parse java-chains.jar, resolve Maven dependencies for every chain recipe,
    and write one pom.xml per chain under output_dir.

    Args:
        jar_path:   Path to java-chains.jar
        output_dir: Where to save gadget_chains_summary.json and per-chain pom.xml files

    Returns:
        success, total_chains, chain_names, summary dict, output_dir path
    """
    global _last_analysis_result
    try:
        from pathlib import Path
        analyzer = GadgetChainAnalyzer(jar_path)
        chains   = analyzer.analyze_jar()
        summary  = analyzer.save_results(output_dir)
        _last_analysis_result = summary
        return {
            "success":      True,
            "total_chains": len(chains),
            "chain_names":  list(chains.keys()),
            "summary":      summary,
            "output_dir":   str(Path(output_dir).resolve()),
        }
    except Exception as exc:
        return {"success": False, "error": str(exc), "chain_names": [], "total_chains": 0}


# ---------------------------------------------------------------------------
# Tool 2 — list
# ---------------------------------------------------------------------------

@mcp.tool()
def list_all_chains() -> Dict[str, Any]:
    """
    Return a list of all chain recipe names from the most recent analysis.
    Call analyze_gadget_chains first.
    """
    if _last_analysis_result is None:
        return {
            "success": False,
            "error": "No analysis result cached. Run analyze_gadget_chains first.",
            "chains": [], "total": 0,
        }
    chains = [c["name"] for c in _last_analysis_result.get("chains", [])]
    return {"success": True, "chains": chains, "total": len(chains)}


# ---------------------------------------------------------------------------
# Tool 3 — chain detail (replaces old get_chain_dependencies)
# ---------------------------------------------------------------------------

@mcp.tool()
def get_chain_details(chain_name: str) -> Dict[str, Any]:
    """
    Return full details for one chain recipe: description, payload_types,
    component pipeline, resolved Maven artifacts, and any unknown components.

    Args:
        chain_name: Exact name as returned by list_all_chains
                    (e.g. 'CB1链', 'K1链', 'Fastjson链')
    """
    if _last_analysis_result is None:
        return {"success": False, "error": "Run analyze_gadget_chains first."}

    for chain in _last_analysis_result.get("chains", []):
        if chain["name"] == chain_name:
            return {"success": True, "chain": chain}

    return {
        "success": False,
        "error": f"Chain '{chain_name}' not found. Use list_all_chains to see available names.",
    }


# ---------------------------------------------------------------------------
# Tool 4 — read pom.xml
# ---------------------------------------------------------------------------

@mcp.tool()
def get_pom_content(
    chain_name: str,
    output_dir: str = "gadget-dependencies",
) -> Dict[str, Any]:
    """
    Return the text of the pom.xml generated for chain_name.

    Args:
        chain_name: Chain recipe name (directory name is derived from it)
        output_dir: Base directory used in analyze_gadget_chains
    """
    import re
    safe = re.sub(r"[^\w\-]", "_", chain_name)
    pom_path = Path(output_dir) / safe / "pom.xml"

    if not pom_path.exists():
        return {
            "success": False,
            "error": f"pom.xml not found at {pom_path}. "
                     f"Run analyze_gadget_chains first, or check chain_name spelling.",
        }
    try:
        return {
            "success": True,
            "content": pom_path.read_text(encoding="utf-8"),
            "path":    str(pom_path.resolve()),
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Tool 5 — generate single environment
# ---------------------------------------------------------------------------

@mcp.tool()
def generate_vuln_environment(
    chain_name: str,
    pom_dir:    str = "gadget-dependencies",
    output_dir: str = "generated-env",
) -> Dict[str, Any]:
    """
    Generate a minimal Spring Boot project with a /deserialize endpoint for chain_name.

    Args:
        chain_name: Chain recipe name (must match a pom.xml in pom_dir)
        pom_dir:    Directory produced by analyze_gadget_chains
        output_dir: Where to write the generated Spring Boot project
    """
    try:
        generator = VulnerableEnvGenerator(pom_dir, output_dir)
        result    = generator.generate_single_environment(chain_name)
        if result:
            return {"success": True, **result}
        return {"success": False, "error": f"Generator returned None for '{chain_name}'"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Tool 6 — generate all environments
# ---------------------------------------------------------------------------

@mcp.tool()
def generate_full_lab(
    pom_dir: str = "gadget-dependencies",
    output_dir: str = "generated-env",
) -> Dict[str, Any]:
    """
	    Generate Spring Boot projects for every chain that has a pom.xml in pom_dir.
		Generate all vulnerable environments and docker-compose lab.

    Args:
        pom_dir:    Directory produced by analyze_gadget_chains
        output_dir: Where to write the generated projects
    """
    try:
        generator = VulnerableEnvGenerator(pom_dir, output_dir)

        envs = generator.generate_all_environments()
        compose = generator.generate_docker_compose(
            envs.get("environments", {})
        )

        return {
            "success": True,
            "total_envs": envs.get("total_generated", 0),
            "compose_file": compose,
            "env_directory": envs.get("output_directory")
        }

    except Exception as exc:
        return {"success": False, "error": str(exc)}


# =========================================================================
# LLM Decision Tools — query + confirm pairs
# =========================================================================

# ---------------------------------------------------------------------------
# Tool 7 — resolve component dependency (query)
# ---------------------------------------------------------------------------

@mcp.tool()
def resolve_component_dependency(
    component_name: str,
    pipeline: Optional[list] = None,
) -> Dict[str, Any]:
    """
    Query dependency info for one gadget component.  Returns the
    COMPONENT_DEP_MAP lookup result, pipeline context, and BOOT-INF/lib
    version hints.  The LLM should review this data, reason about whether
    the dependency is correct, then call confirm_dependency_resolution.

    Args:
        component_name: Name of the gadget component (e.g. 'CommonsBeanutils1')
        pipeline:       Full pipeline list for context (optional)
    """
    try:
        analyzer = GadgetChainAnalyzer("")
        return {"success": True, "data": analyzer.query_component(component_name, pipeline)}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Tool 8 — confirm dependency resolution
# ---------------------------------------------------------------------------

@mcp.tool()
def confirm_dependency_resolution(
    component_name: str,
    llm_maven_coords: str,
    llm_reasoning: str,
    map_agreed: bool = True,
) -> Dict[str, Any]:
    """
    Record the LLM's dependency resolution decision for a component.
    If map_agreed is False and llm_maven_coords is provided, the component
    will be registered in COMPONENT_DEP_MAP.

    Args:
        component_name:   The gadget component being resolved
        llm_maven_coords: LLM's answer, format: 'groupId:artifactId:version'
                          (multiple deps separated by ';')
        llm_reasoning:    Why the LLM chose these coordinates
        map_agreed:       Whether the LLM agrees with COMPONENT_DEP_MAP
    """
    try:
        new_deps = []
        for part in llm_maven_coords.split(";"):
            parts = [p.strip() for p in part.strip().split(":")]
            if len(parts) == 3:
                new_deps.append(tuple(parts))

        if not map_agreed and new_deps:
            COMPONENT_DEP_MAP[component_name] = new_deps

        map_entry = COMPONENT_DEP_MAP.get(component_name)
        map_result = None
        if map_entry:
            map_result = [{"groupId": g, "artifactId": a, "version": v}
                          for g, a, v in map_entry]

        llm_result = {"maven_coords": llm_maven_coords, "reasoning": llm_reasoning}

        decision_id = log_decision(
            category="dependency_resolution",
            input_data={"component": component_name},
            map_result=map_result,
            llm_result=llm_result,
            agreed=map_agreed,
        )
        return {"success": True, "logged": True, "decision_id": decision_id}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Tool 9 — analyze new chain (query)
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_new_chain(
    chain_name: str,
    pipeline: str,
    payload_types: str,
) -> Dict[str, Any]:
    """
    Analyze a new gadget chain's pipeline, classifying each component as
    known or unknown.  Returns dependency info for known components and
    highlights unknown ones for the LLM to reason about.

    Args:
        chain_name:    Name of the new chain
        pipeline:      Pipeline components, comma-separated
                       (e.g. 'CommonsBeanutils1,TemplatesImpl,BytecodeConvert,Exec')
        payload_types: Payload types, comma-separated
                       (e.g. 'JavaNativePayload,ShiroPayload')
    """
    try:
        pipe = [s.strip() for s in pipeline.split(",") if s.strip()]
        pts  = [s.strip() for s in payload_types.split(",") if s.strip()]

        analyzer = GadgetChainAnalyzer("")
        result = analyzer.resolve_new_chain_deps(chain_name, pipe, pts)
        return {"success": True, "data": result}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Tool 10 — register chain analysis (confirm)
# ---------------------------------------------------------------------------

@mcp.tool()
def register_chain_analysis(
    chain_name: str,
    llm_dependencies: str,
    llm_controller_type: str,
    llm_reasoning: str,
) -> Dict[str, Any]:
    """
    Register the LLM's analysis of a new chain — dependencies and controller
    type.  Updates COMPONENT_DEP_MAP with LLM-provided coordinates for
    previously unknown components.

    Args:
        chain_name:          Name of the chain
        llm_dependencies:    JSON string: {"component": "groupId:artifactId:version", ...}
        llm_controller_type: Controller type the LLM chose (NATIVE, HESSIAN, etc.)
        llm_reasoning:       Why the LLM chose these deps and controller
    """
    try:
        deps = json.loads(llm_dependencies) if isinstance(llm_dependencies, str) else llm_dependencies
        added = 0
        for comp, coords_str in deps.items():
            parts = [p.strip() for p in coords_str.split(":")]
            if len(parts) == 3:
                COMPONENT_DEP_MAP[comp] = [tuple(parts)]
                added += 1

        decision_id = log_decision(
            category="new_chain",
            input_data={"chain_name": chain_name},
            map_result={"existing_components": list(COMPONENT_DEP_MAP.keys())},
            llm_result={
                "dependencies": deps,
                "controller_type": llm_controller_type,
                "reasoning": llm_reasoning,
            },
            agreed=False,
        )
        return {"success": True, "registered": True, "components_added": added,
                "decision_id": decision_id}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Tool 11 — infer controller type (query)
# ---------------------------------------------------------------------------

@mcp.tool()
def infer_controller_type(
    chain_name: str,
    payload_types: str,
) -> Dict[str, Any]:
    """
    Evaluate all controller routing rules for a chain and return detailed
    results.  The LLM should review the rule evaluations, check for conflicts,
    and confirm or override the rule-based suggestion.

    Args:
        chain_name:    Chain name
        payload_types: Comma-separated payload types
                       (e.g. 'HessianPayload,Hessian2Payload')
    """
    try:
        pts = [s.strip() for s in payload_types.split(",") if s.strip()]
        result = explain_controller_rules(chain_name, pts)
        return {"success": True, "data": result}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Tool 12 — confirm controller type
# ---------------------------------------------------------------------------

@mcp.tool()
def confirm_controller_type(
    chain_name: str,
    llm_choice: str,
    llm_reasoning: str,
    rule_agreed: bool = True,
) -> Dict[str, Any]:
    """
    Record the LLM's controller type decision for a chain.

    Args:
        chain_name:    Chain name
        llm_choice:    Controller type the LLM selected (NATIVE, HESSIAN, etc.)
        llm_reasoning: Why this controller type was chosen
        rule_agreed:   Whether the LLM agrees with the rule-based result
    """
    try:
        decision_id = log_decision(
            category="controller_type",
            input_data={"chain_name": chain_name},
            map_result={"rule_result": "see infer_controller_type"},
            llm_result={"controller_type": llm_choice, "reasoning": llm_reasoning},
            agreed=rule_agreed,
        )
        return {"success": True, "logged": True, "decision_id": decision_id}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Tool 13 — analyze test failure
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_test_failure(
    chain_name: str,
    error_log: str,
) -> Dict[str, Any]:
    """
    Present a test failure case for the LLM to analyze.  Returns chain
    details, controller type, and the error log.  The LLM should diagnose
    the root cause and suggest a fix.

    Args:
        chain_name: Chain that failed
        error_log:  Error output from the test runner
    """
    try:
        chain_info = None
        if _last_analysis_result:
            for c in _last_analysis_result.get("chains", []):
                if c["name"] == chain_name:
                    chain_info = c
                    break

        from vuln_env_generator import _pick_controller
        ctrl = _pick_controller(chain_name, chain_info["payload_types"]) if chain_info else "UNKNOWN"

        return {
            "success": True,
            "data": {
                "chain_name": chain_name,
                "controller_type": ctrl,
                "maven_artifacts": chain_info.get("maven_artifacts", []) if chain_info else [],
                "unknown_components": chain_info.get("unknown_components", []) if chain_info else [],
                "error_log": error_log,
            },
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Tool 14 — decision statistics
# ---------------------------------------------------------------------------

@mcp.tool()
def get_decision_statistics() -> Dict[str, Any]:
    """Return statistics on all recorded LLM decisions (for ablation study)."""
    try:
        return {"success": True, **get_statistics()}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Resource — server metadata
# ---------------------------------------------------------------------------

@mcp.resource("info://server")
def get_server_info() -> str:
    return json.dumps({
        "name":    "Java Deserialization Analyzer",
        "version": "4.0.0",
        "tools":   [
            "analyze_gadget_chains",
            "list_all_chains",
            "get_chain_details",
            "get_pom_content",
            "generate_vuln_environment",
            "generate_full_lab",
            "resolve_component_dependency",
            "confirm_dependency_resolution",
            "analyze_new_chain",
            "register_chain_analysis",
            "infer_controller_type",
            "confirm_controller_type",
            "analyze_test_failure",
            "get_decision_statistics",
        ],
        "workflow": [
            "1. analyze_gadget_chains(jar_path) — parse JAR, resolve deps, write pom.xml files",
            "2. list_all_chains()               — see all chain recipes",
            "3. get_chain_details(chain_name)   — pipeline + Maven coords for one chain",
            "4. resolve_component_dependency(component) — LLM queries dependency info",
            "5. confirm_dependency_resolution(...)      — LLM confirms dependency decision",
            "6. analyze_new_chain(...)                  — LLM analyzes a new chain pipeline",
            "7. register_chain_analysis(...)            — LLM registers new chain analysis",
            "8. infer_controller_type(...)              — LLM evaluates controller rules",
            "9. confirm_controller_type(...)            — LLM confirms controller choice",
            "10. generate_vuln_environment(...)         — build Spring Boot test project",
            "11. analyze_test_failure(...)              — LLM diagnoses test failures",
        ],
    }, indent=2, ensure_ascii=False)


@mcp.resource("knowledge://component-dep-map")
def get_component_dep_map() -> str:
    """Expose the full COMPONENT_DEP_MAP as an MCP resource for LLM reference."""
    data = {}
    for comp, deps in COMPONENT_DEP_MAP.items():
        data[comp] = [{"groupId": g, "artifactId": a, "version": v}
                      for g, a, v in deps]
    return json.dumps(data, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

@mcp.prompt(title="Analyze JAR File")
def analyze_jar_prompt(jar_path: str) -> str:
    return f"""Please analyze the java-chains gadget chains in: {jar_path}

Steps:
1. analyze_gadget_chains("{jar_path}") — scan JAR and generate pom.xml files
2. list_all_chains()                   — review all chain recipes
3. get_chain_details("<name>")         — inspect pipeline + Maven artifacts
4. generate_vuln_environment("<name>") — create a test environment for interesting chains
"""


# ---------------------------------------------------------------------------
# CLI mode (backward compat + debugging)
# ---------------------------------------------------------------------------

def run_cli_mode(args):
    global _last_analysis_result

    if args.jar:
        result = analyze_gadget_chains(args.jar, args.output)

        if not result["success"]:
            print(f"Error: {result['error']}")
            sys.exit(1)

        print(f"\nAnalysis complete")
        print(f"  Total chains : {result['total_chains']}")
        print(f"  Output dir   : {result['output_dir']}")

        if args.list:
            print("\nAll chains:")
            for name in result["chain_names"]:
                print(f"  {name}")

        if args.chain:
            detail = get_chain_details(args.chain)
            if detail["success"]:
                c = detail["chain"]
                print(f"\n{c['name']}")
                print(f"  Description   : {c['description']}")
                print(f"  Payload types : {', '.join(c['payload_types'])}")
                print(f"  Pipeline      : {' → '.join(c['pipeline'])}")
                print(f"  Maven deps ({len(c['maven_artifacts'])}):")
                for a in c["maven_artifacts"]:
                    src = a.get("resolved_from", "")
                    tag = " [lib]" if src == "boot_inf_lib" else " [fallback]"
                    print(f"    {a['groupId']}:{a['artifactId']}:{a['version']}{tag}")
                if c.get("unknown_components"):
                    print(f"  WARN unknown components: {c['unknown_components']}")
            else:
                print(f"Error: {detail['error']}")

    elif args.generate:
        result = generate_vuln_environment(args.generate, args.output, "generated-env")
        if result["success"]:
            print(f"Generated: {result.get('project_path', '?')}")
        else:
            print(f"Error: {result['error']}")
            sys.exit(1)

    elif args.generate_all:
        result = generate_all_vuln_environments(args.output, "generated-env")
        if result.get("success"):
            print(f"Generated {result['total_generated']} environments")
        else:
            print(f"Error: {result.get('error', 'unknown')}")
            sys.exit(1)

    elif args.schema:
        schema = {
            "tools": [
                {
                    "name": "analyze_gadget_chains",
                    "description": "Parse java-chains.jar, resolve Maven deps, write pom.xml files",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "jar_path":   {"type": "string", "description": "Path to java-chains.jar"},
                            "output_dir": {"type": "string", "description": "Output directory",
                                          "default": "gadget-dependencies"},
                        },
                        "required": ["jar_path"],
                    },
                },
                {
                    "name": "list_all_chains",
                    "description": "List all chain recipe names from the last analysis",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "get_chain_details",
                    "description": "Full details for one chain: pipeline + Maven artifacts",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "chain_name": {"type": "string",
                                          "description": "Exact chain name (e.g. 'CB1链')"},
                        },
                        "required": ["chain_name"],
                    },
                },
                {
                    "name": "get_pom_content",
                    "description": "Read the generated pom.xml for a chain",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "chain_name": {"type": "string"},
                            "output_dir": {"type": "string", "default": "gadget-dependencies"},
                        },
                        "required": ["chain_name"],
                    },
                },
                {
                    "name": "generate_vuln_environment",
                    "description": "Generate a Spring Boot /deserialize project for one chain",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "chain_name": {"type": "string"},
                            "pom_dir":    {"type": "string", "default": "gadget-dependencies"},
                            "output_dir": {"type": "string", "default": "generated-env"},
                        },
                        "required": ["chain_name"],
                    },
                },
                {
                    "name": "generate_all_vuln_environments",
                    "description": "Generate Spring Boot projects for all chains",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "pom_dir":    {"type": "string", "default": "gadget-dependencies"},
                            "output_dir": {"type": "string", "default": "generated-env"},
                        },
                    },
                },
            ]
        }
        print(json.dumps(schema, indent=2, ensure_ascii=False))

    else:
        print("No action specified. Use --help for options.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="MCP Server — Java Deserialization Analyzer v3.0")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http", "http"],
                        default="stdio")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--cli",          action="store_true")
    parser.add_argument("--jar",          help="Path to java-chains.jar")
    parser.add_argument("--output",       default="gadget-dependencies")
    parser.add_argument("--list",         action="store_true")
    parser.add_argument("--chain",        help="Chain name for --list detail")
    parser.add_argument("--generate",     help="Generate env for chain name")
    parser.add_argument("--generate-all", action="store_true")
    parser.add_argument("--schema",       action="store_true")
    # parse_known_args instead of parse_args:
    # silently ignore any unrecognized flags (e.g. --mcp passed by some MCP clients)
    # so the server does not crash with "unrecognized arguments" on startup.
    args, _ = parser.parse_known_args()

    cli_flags = [args.jar, args.chain, args.generate, args.generate_all, args.schema, args.list]
    if args.cli or any(cli_flags):
        run_cli_mode(args)
    else:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        elif args.transport in ("sse", "http"):
            mcp.run(transport="sse")
        elif args.transport == "streamable-http":
            mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
