# 基于LLM的Java反序列化漏洞链路最小化环境构建

**Construction of Java Deserialization Vulnerability Link Minimization Environment Based on LLM**

> 一个面向安全研究与教学的 Java 反序列化漏洞靶场平台。基于 LLM + MCP 自动分析 `java-chains.jar` 中的 Gadget Chain，为每条链生成**仅包含必需依赖**的最小化 Spring Boot 漏洞环境，并通过 Docker Compose 一键编排独立靶标容器与统一网关。

---

## 目录

- [项目背景](#项目背景)
- [系统架构](#系统架构)
- [目录结构](#目录结构)
- [技术栈](#技术栈)
- [环境要求](#环境要求)
- [快速开始（Docker 一键部署）](#快速开始docker-一键部署)
- [手动构建与部署](#手动构建与部署)
- [MCP 工具使用](#mcp-工具使用)
- [Gateway API 说明](#gateway-api-说明)
- [测试与验证](#测试与验证)
- [已支持的反序列化链](#已支持的反序列化链)
- [常见问题](#常见问题)
- [免责声明](#免责声明)
- [许可证](#许可证)

---

## 项目背景

Java 反序列化漏洞长期位居 OWASP 高危榜单，但目前社区靶场（如 Vulhub、DeserializationLab）多以"完整漏洞应用"形式呈现，依赖冗余、与生产环境耦合深、难以聚焦 Gadget Chain 本身。本研究提出一种**链路最小化**思想：

1. 利用 LLM 解析 `java-chains.jar`（来自 `Y4er/java-chains`）中内置的 Gadget Chain 配方；
2. 通过 MCP（Model Context Protocol）将"依赖解析、控制器选择、Pom 生成"等步骤封装为可被 LLM 调用的工具；
3. LLM 决策每条链所需的**最小 Maven 依赖集合**，生成仅暴露 `/deserialize` 接口的 Spring Boot 工程；
4. 全部容器由 `docker-compose` 编排，网关统一转发 Payload，便于自动化测试与对照实验。

该平台可用于：漏洞原理学习、PoC 验证、防御检测规则研发、漏洞利用对比研究。

---

## 系统架构

```
┌────────────────────────────────────────────────────────────────┐
│                        分析期（离线）                            │
│   java-chains.jar  ──►  MCP Server (Python)  ──►  LLM 决策     │
│                              │                                 │
│                              ▼                                 │
│              gadget-dependencies/  (每条链一份 pom.xml)          │
│                              │                                 │
│                              ▼                                 │
│              generated-env/  (每条链一份 Spring Boot 工程)       │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                      运行期（Docker Compose）                    │
│                                                                │
│   ┌──────────────┐    HTTP    ┌──────────────────────────┐     │
│   │  Gateway     │ ─────────► │   Chain Container        │     │
│   │  :8080       │            │  (axis2/cb1/k1/...)      │     │
│   │  Spring Boot │ ◄───────── │  每个暴露 /deserialize    │     │
│   └──────────────┘   RCE结果  │  与 /api/exec             │     │
│           │                   └──────────────────────────┘     │
│           ▼                                                    │
│      Web UI (Thymeleaf)                                        │
└────────────────────────────────────────────────────────────────┘
```

**核心组件**

| 组件 | 角色 | 端口 |
|---|---|---|
| `gateway/` | Spring Boot 2.7 Web 网关，UI + REST API，转发 Payload 到指定链容器 | `8080` |
| `mcp-tools/` | Python MCP Server，提供 13 个工具供 LLM 调用分析 gadget chain | stdio / `8000` |
| `gadget-dependencies/` | LLM 分析产物：每条链一份 `pom.xml` + 全局 `gadget_chains_summary.json` | — |
| `generated-env/` | 每条链对应的可独立构建的 Spring Boot 靶标工程 | `8081–8131` |
| `java-chains/java-chains.jar` | 上游 Gadget Chain 配方数据源 | — |
| `test-reports/` | 自动化测试结果（JSON） | — |

---

## 目录结构

```
.
├── CLAUDE.md                       # Claude Code 项目级指令
├── README.md                       # 本文件
├── build-all.sh                    # 批量编译 gateway + 所有链容器的脚本
├── docker-compose.yml              # 一键拉起 gateway + 链容器
│
├── gateway/                        # Spring Boot 网关服务
│   ├── Dockerfile
│   ├── pom.xml
│   └── src/main/java/com/gateway/
│       ├── GatewayApplication.java
│       ├── controller/
│       │   ├── ApiController.java      # REST API
│       │   └── UiController.java       # Thymeleaf 页面
│       └── service/
│           ├── ChainService.java       # 转发 Payload 到容器
│           └── LibraryVersion.java
│
├── mcp-tools/                      # LLM 决策用的 MCP 工具集
│   ├── mcp_server.py                # FastMCP 服务入口（13 个工具）
│   ├── gadget_chain_analyzer.py     # 解析 jar / 依赖映射
│   ├── vuln_env_generator.py        # 生成 Spring Boot 工程
│   ├── test_runner.py               # 自动化测试运行器
│   ├── llm_decision_log.py          # 决策日志
│   ├── _chain_data.py
│   ├── _payloads.py
│   └── test_config.yaml
│
├── gadget-dependencies/            # 链的 pom.xml（LLM 生成产物）
│   ├── gadget_chains_summary.json
│   ├── CB1链/pom.xml
│   ├── K1链/pom.xml
│   └── ... 
│
├── generated-env/                  # 最小化靶标 Spring Boot 工程
│   ├── axis2/{pom.xml, Dockerfile, src/}
│   ├── cb1/{pom.xml, Dockerfile, src/}
│   └── ... (端口从 8081开始)
│
├── java-chains/                    # 上游 gadget chain 数据源
│   ├── java-chains.jar
│   └── chains-config/
│
└── test-reports/
    └── automated_test_results.json
```

---

## 技术栈

- **网关层**：Java 8 · Spring Boot 2.7.18 · Thymeleaf · Lombok · Jackson
- **分析层**：Python 3.9+ · [FastMCP](https://github.com/jlowin/fastmcp)
- **容器化**：Docker · Docker Compose v3.8 · eclipse-temurin:8u432-jdk
- **构建工具**：Maven 3.6+
- **LLM 协议**：MCP（Model Context Protocol）

---

## 环境要求

| 软件 | 最低版本 | 备注 |
|---|---|---|
| Docker | 20.10+ | 必装 |
| Docker Compose | v2.0+ | 必装 |
| JDK | 8 | 仅手动构建时需要 |
| Maven | 3.6+ | 仅手动构建时需要 |
| Python | 3.9+ | 仅使用 MCP 工具时需要 |
| Git | 任意 | 克隆仓库 |

内存建议 ≥ 16 GB，磁盘空间 ≥ 30 GB（构建产物较多）。

---

## 快速开始（Docker 一键部署）

> 该路径假设 `generated-env/` 与 `gadget-dependencies/` 已存在（仓库已包含生成产物）。若需重新生成，请参考 [MCP 工具使用](#mcp-工具使用)。

### 1. 克隆仓库

```bash
git clone https://github.com/ARemi2967/Thesis.git
cd <repo-name>
```

### 2. （可选）批量预编译所有链的 JAR

`docker-compose build` 会自动在每个容器内执行 `mvn package`，但若想提前发现编译错误可手动跑：

```bash
chmod +x build-all.sh
./build-all.sh
```

### 3. 启动全部服务

```bash
docker-compose up -d --build
```

首次构建约 30–60 分钟（镜像并行受 Docker 资源限制，可能需要分批）。完成后查看状态：

```bash
docker-compose ps
```

预期输出：`deserialization-gateway` 与  `xxx-env` 容器全部 `Up`。

### 4. 访问网关

- **Web UI**：<http://localhost:8080>
- **REST API**：<http://localhost:8080/api/chains>

### 5. 触发一次反序列化测试

```bash
# 列出所有可用链
curl http://localhost:8080/api/chains

# 向 CB1 链容器发送 Payload（需先用 java-chains 工具生成 Payload）
curl -X POST http://localhost:8080/api/trigger \
  -H "Content-Type: application/json" \
  -d '{"chain":"CB1链","payload":"<base64-payload>"}'

# 直接在容器内执行命令验证 RCE
curl "http://localhost:8080/api/exec/CB1链?cmd=id"
```

### 6. 停止与清理

```bash
docker-compose down              # 仅停止
docker-compose down -v           # 停止并删除卷
docker-compose down --rmi local  # 同时删除本地构建的镜像
```

---

## 手动构建与部署

### 编译 Gateway

```bash
cd gateway
mvn clean package -DskipTests
java -jar target/deserialization-gateway-1.0.0.jar
# 或开发模式：
mvn spring-boot:run
```

启动后监听 `localhost:8080`，默认从 `/data/gadget-dependencies` 与 `/data/generated-env` 读取链信息（容器内路径，本机运行需调整 `BS5_ROOT` 环境变量或修改 `application.properties`）。

### 单独构建某个链容器

```bash
cd generated-env/cb1
mvn clean package -DskipTests
docker build -t chain-cb1 .
docker run --rm -p 8087:8080 chain-cb1
```

每个链容器都暴露：

- `POST /deserialize` —— 接收序列化字节流并触发反序列化
- `GET /api/exec?cmd=...` —— 直接执行 Shell 命令（仅 NATIVE/HESSIAN 类型链可用，用于验证 RCE）

---

## MCP 工具使用

`mcp-tools/mcp_server.py` 提供三种运行模式：

### 1. MCP stdio 模式（接 Claude Desktop / Cursor 等客户端）

```bash
cd mcp-tools
pip install fastmcp
python mcp_server.py
```

在客户端配置文件中注册：

```json
{
  "mcpServers": {
    "java-deserialization": {
      "command": "python",
      "args": ["E:/test/mcp-tools/mcp_server.py"]
    }
  }
}
```

### 2. HTTP 传输模式

```bash
python mcp_server.py --transport http --port 8000
```

### 3. CLI 调试模式

```bash
# 列出所有链
python mcp_server.py --cli --jar ../java-chains/java-chains.jar --list

# 查看某条链详情
python mcp_server.py --cli --jar ../java-chains/java-chains.jar --chain CB1链
```

### 完整工作流（从零生成环境）

```bash
# 步骤 1：分析 jar，生成 gadget-dependencies/<chain>/pom.xml
# 调用 analyze_gadget_chains(jar_path, output_dir)

# 步骤 2：列出所有链
# 调用 list_all_chains()

# 步骤 3：查看链详情（依赖、控制器类型）
# 调用 get_chain_details(chain_name)

# 步骤 4：生成单条链的 Spring Boot 工程
# 调用 generate_vuln_environment(chain_name, pom_dir, output_dir)

# 步骤 5：一次性生成全部环境 + docker-compose
# 调用 generate_full_lab(pom_dir, output_dir)
```

LLM 决策类工具（query/confirm 配对）：

| 工具 | 用途 |
|---|---|
| `resolve_component_dependency` / `confirm_dependency_resolution` | 解析 gadget 组件对应的 Maven 坐标 |
| `analyze_new_chain` / `register_chain_analysis` | 分析新链依赖并登记 |
| `infer_controller_type` / `confirm_controller_type` | 推断链所需的控制器类型（NATIVE/HESSIAN/JNDI 等） |
| `analyze_test_failure` | 测试失败时让 LLM 诊断根因 |

---

## Gateway API 说明

| Method | Path | 说明 |
|---|---|---|
| GET | `/` | Web UI 首页（Thymeleaf 渲染链列表） |
| GET | `/api/chains` | 返回所有链 JSON |
| GET | `/api/chains/by-category` | 按分类分组返回 |
| POST | `/api/trigger` | 转发 Payload 到指定链容器 |
| GET | `/api/exec/{chainName}?cmd=` | 在链容器内执行命令验证 RCE |

`/api/trigger` 请求体：

```json
{
  "chain": "CB1链",
  "payload": "<序列化字节的 Base64 字符串>"
}
```

---

## 测试与验证

### 自动化测试

```bash
cd mcp-tools
python test_runner.py --config test_config.yaml
```

测试结果输出到 `test-reports/automated_test_results.json`，包含每条链的：

- 触发状态（成功/失败/超时）
- 响应时间
- DNSLog / JNDI 回连情况（可选）
- 错误堆栈

### 手动验证单条链

```bash
# 1. 启动该链的容器
docker-compose up -d cb1

# 2. 用 java-chains.jar 生成 Payload
java -jar java-chains/java-chains.jar --chain CB1链 --payload JavaNativePayload

# 3. 经 Gateway 触发
curl -X POST http://localhost:8080/api/trigger \
  -H "Content-Type: application/json" \
  -d '{"chain":"CB1链","payload":"<生成的 payload>"}'

# 4. 验证 RCE
curl "http://localhost:8080/api/exec/CB1链?cmd=cat /etc/passwd"
```

---

## 已支持的反序列化链

涵盖主流反序列化利用场景，按类型分为：

- **JDK 原生链**：JDK 原生链 1/2、BCEL、JNDI、JDK17 RCE 1/2
- **Commons 系**：CB1、CB2、CB1 JNDI 1/2
- **Fastjson 系**：Fastjson、Fastjson2、Fastjson JNDI、Fastjson C3P0 H2
- **Jackson 系**：Jackson、Jackson C3P0 H2
- **Hessian 系**：Hessian Fastjson / Jackson / XBean、二次反序列化、Hessian 反序列化炸弹
- **Spring 系**：Spring JNDI 1/2、Spring Bean XML、Spring 命令执行、SpringBoot charsets.jar
- **数据库 JDBC**：C3P0 1/2、Druid Jdbc、HikariJdbc、H2 Jdbc Url、ReadFile
- **其他**：K1–K4、K1 二次反序列化 1/2、Rome1/2、Groovy、SnakeYaml、Axis2、BeanshellRef、XSLT、Tomcat EL、JSP 文件、DNSLog 探测、Sleep 探测、命令执行、反序列化炸弹

完整列表见 `gadget-dependencies/gadget_chains_summary.json`。

---

## 常见问题

**Q1：构建过慢或卡死？**
A：Maven 首次下载依赖较慢，建议配置国内镜像（阿里云）。可设置环境变量 `MAVEN_OPTS=-Dmaven.repo.snapshot=false`。

**Q2：`gateway` 容器读取不到链信息？**
A：`docker-compose.yml` 通过 volume 把宿主机 `gadget-dependencies/` 与 `generated-env/` 挂载到容器内 `/data/`，请确保宿主机路径正确，且这两个目录非空。

**Q3：如何重新让 LLM 生成环境？**
A：删除 `gadget-dependencies/` 与 `generated-env/` 目录，按 [MCP 工具使用](#mcp-工具使用) 章节重新跑 `analyze_gadget_chains` 与 `generate_full_lab`。

**Q4：Windows 下脚本无法执行？**
A：`build-all.sh` 是 Bash 脚本，请使用 Git Bash / WSL 运行；或直接在 PowerShell 中手动 `cd` 到每个目录执行 `mvn package`。

---

## 免责声明

本项目仅用于**安全教学、漏洞原理研究、防御技术验证**等合法用途。使用者应：

1. 仅在**本地隔离环境**或**授权的测试环境**中运行；
2. 不得用于未授权的渗透测试、攻击真实系统；
3. 遵守所在国家/地区关于网络安全、数据保护的法律法规（如《中华人民共和国网络安全法》《数据安全法》等）；
4. 因不当使用造成的任何法律责任与后果，由使用者自行承担，与项目作者及所在单位无关。

---

## 许可证

本项目采用 [MIT License](LICENSE)。

研究中使用的上游工具：
- `java-chains.jar` —— 来自 [Y4er/java-chains](https://github.com/Y4er/java-chains)，请遵守其许可证。
- 上游漏洞组件（Fastjson、Jackson、Commons-Beanutils 等）—— 分别遵循其原始许可证。
