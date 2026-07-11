package com.gateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class ChainService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final Map<String, String> chainUrls;
    private final Map<String, Map<String, Object>> dependenciesCache;
    private final Map<String, Map<String, Object>> chainsInfo;
    private final List<Map<String, Object>> generatedEnvironments;
    private final Path bs5RootPath;

    // -----------------------------------------------------------------------
    // safe_name <-> original chain name  (mirrors _CHAIN_SAFE_NAME in vuln_env_generator.py)
    // -----------------------------------------------------------------------
    private static final Map<String, String> SAFE_TO_CHAIN;
    static {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("cb1",                "CB1链");
        m.put("cb1jndi1",           "CB1 JNDI链1");
        m.put("cb1jndi2",           "CB1 JNDI链2");
        m.put("cb2",                "CB2链");
        m.put("k1",                 "K1链");
        m.put("k1deser1",           "K1链二次反序列化1");
        m.put("k1deser2",           "K1链二次反序列化2");
        m.put("k2",                 "K2链");
        m.put("k3",                 "K3链");
        m.put("k4",                 "K4链");
        m.put("fastjson",           "Fastjson链");
        m.put("fastjsonjndi",       "Fastjson JNDI链");
        m.put("fastjsonc3p0h2",     "Fastjson C3p0 Jdbc h2链");
        m.put("fastjson2",          "Fastjson2链");
        m.put("jackson",            "Jackson链");
        m.put("jacksonc3p0h2",      "Jackson C3p0 Jdbc h2链");
        m.put("deserbomb",          "反序列化炸弹");
        m.put("dnslogclass",        "DNSLog探测类");
        m.put("c3p01",              "C3P0反序列化1");
        m.put("c3p02",              "C3P0反序列化2");
        m.put("cmdexec",            "命令执行");
        m.put("dnslogchain",        "DNSLog探测链");
        m.put("sleepchain",         "Sleep探测链");
        m.put("hessiandeser",       "二次反序列化链");
        m.put("jdknative1",         "JDK原生链1");
        m.put("jdknative2",         "JDK原生链2（慎用）");
        m.put("jdkbcel",            "JDK原生BCEL链");
        m.put("jdkjndi",            "JDK原生JNDI链");
        m.put("springjndi1",        "Spring JNDI链1");
        m.put("springjndi2",        "Spring JNDI链2");
        m.put("springexec",         "Spring 命令执行");
        m.put("xslt",               "Xslt 代码执行");
        m.put("rome1",              "Rome1低版本二次反序列化链");
        m.put("rome2",              "Rome2高版本二次反序列化链");
        m.put("jspfile",            "JSP文件");
        m.put("h2jdbcurl",          "H2 Jdbc Url");
        m.put("springbeanxml",      "Spring Bean Xml 加载字节码");
        m.put("springbootcharsets", "SpringBoot charsets.jar生成");
        m.put("tomcatel",           "经典 Tomcat EL 执行");
        m.put("groovy",             "Groovy 脚本执行");
        m.put("snakeyaml",          "SnakeYaml 利用");
        m.put("beanshellref",       "BeanshellRef 利用");
        m.put("hikarijdbc",         "HikariJdbcAttack Jdbc 利用");
        m.put("druidjdbc",          "Druid Jdbc 利用");
        m.put("axis2",              "Axis2链");
        m.put("hessianxbean",       "Hessian XBean 链");
        m.put("hessianfastjson",    "Hessian Fastjson 链");
        m.put("hessianjackson",     "Hessian Jackson 链");
        m.put("readfile",           "ReadFile");
        // v3.1: JDK17 high-version chains (present in gadget_chains_summary.json)
        m.put("jdk17rce",           "JDK17 RCE链");
        m.put("jdk17rce2",          "JDK17 RCE链2");
        SAFE_TO_CHAIN = Collections.unmodifiableMap(m);
    }

    private static final Map<String, String> CHAIN_TO_SAFE;
    static {
        Map<String, String> m = new LinkedHashMap<>();
        SAFE_TO_CHAIN.forEach((safe, chain) -> m.put(chain, safe));
        CHAIN_TO_SAFE = Collections.unmodifiableMap(m);
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    public ChainService() {
        this.restTemplate          = new RestTemplate();
        this.objectMapper          = new ObjectMapper();
        this.chainUrls             = new HashMap<>();
        this.dependenciesCache     = new HashMap<>();
        this.chainsInfo            = new HashMap<>();
        this.generatedEnvironments = new ArrayList<>();
        this.bs5RootPath           = determineBs5RootPath();
        System.out.println("BS5 Root Path: " + this.bs5RootPath.toAbsolutePath());
        loadMcpData();
    }

    // -----------------------------------------------------------------------
    // Path discovery  — NO hard-coded local paths, container-friendly
    // -----------------------------------------------------------------------

    /**
     * Resolve the BS5 root directory (parent of gadget-dependencies/).
     *
     * Search order:
     *   1. JVM system property  -Dbs5.root=...
     *   2. Environment variable BS5_ROOT=...  (Dockerfile sets BS5_ROOT=/data)
     *   3. Current working directory and up to two parent directories
     */
    private Path determineBs5RootPath() {
        // 1. JVM system property
        String prop = System.getProperty("bs5.root");
        if (prop != null) {
            Path p = Paths.get(prop);
            if (Files.exists(p.resolve("gadget-dependencies"))) return p;
            System.err.println("Warning: -Dbs5.root=" + prop
                + " has no gadget-dependencies/ subdirectory.");
        }

        // 2. Environment variable  (Docker: ENV BS5_ROOT=/data)
        String envVar = System.getenv("BS5_ROOT");
        if (envVar != null) {
            Path p = Paths.get(envVar);
            if (Files.exists(p.resolve("gadget-dependencies"))) return p;
            System.err.println("Warning: BS5_ROOT=" + envVar
                + " has no gadget-dependencies/ subdirectory.");
        }

        // 3. Walk up from CWD (convenient when running from gateway/ or gateway/target/)
        Path cwd = Paths.get(".").toAbsolutePath().normalize();
        Path candidate = cwd;
        for (int i = 0; i <= 2; i++) {
            if (candidate == null) break;
            if (Files.exists(candidate.resolve("gadget-dependencies"))) return candidate;
            candidate = candidate.getParent();
        }

        System.err.println("Warning: gadget-dependencies/ not found. "
            + "Set BS5_ROOT env var or -Dbs5.root JVM argument.");
        return cwd;
    }

    // -----------------------------------------------------------------------
    // MCP data loading
    // -----------------------------------------------------------------------

    private void loadMcpData() {
        loadChainsSummary();
        loadDependencies();
        loadGeneratedEnvironments();
        initializeChainUrls();
    }

    /**
     * Load gadget_chains_summary.json (v3 schema):
     *   name, description,
     *   payload_types      List<String>
     *   pipeline           List<String>
     *   maven_artifacts    List<{groupId,artifactId,version,resolved_from}>
     *   unknown_components List<String>
     */
    private void loadChainsSummary() {
        Path path = bs5RootPath.resolve("gadget-dependencies")
                               .resolve("gadget_chains_summary.json");
        System.out.println("Looking for chains summary at: " + path);
        if (!Files.exists(path)) {
            System.err.println("Warning: gadget_chains_summary.json not found at " + path);
            return;
        }
        try {
            JsonNode root   = objectMapper.readTree(Files.readAllBytes(path));
            JsonNode chains = root.get("chains");
            if (chains != null && chains.isArray()) {
                for (JsonNode c : chains) {
                    String name = c.get("name").asText();
                    @SuppressWarnings("unchecked")
                    Map<String, Object> info = objectMapper.treeToValue(c, Map.class);
                    chainsInfo.put(name, info);
                }
            }
            System.out.println("Loaded " + chainsInfo.size() + " chains from MCP analysis");
        } catch (IOException e) {
            System.err.println("Error loading chains summary: " + e.getMessage());
        }
    }

    private void loadDependencies() {
        Path depsPath = bs5RootPath.resolve("gadget-dependencies");
        if (!Files.exists(depsPath)) return;
        try (Stream<Path> paths = Files.walk(depsPath)) {
            paths.filter(p -> p.toString().endsWith(".json")
                         && !p.getFileName().toString().equals("gadget_chains_summary.json"))
                 .forEach(p -> {
                     try {
                         @SuppressWarnings("unchecked")
                         Map<String, Object> info = objectMapper.treeToValue(
                             objectMapper.readTree(Files.readAllBytes(p)), Map.class);
                         dependenciesCache.put(p.getFileName().toString().replace(".json", ""), info);
                     } catch (IOException e) {
                         System.err.println("Error loading " + p + ": " + e.getMessage());
                     }
                 });
        } catch (IOException e) {
            System.err.println("Error walking gadget-dependencies: " + e.getMessage());
        }
    }

    /**
     * Load generated-env/ subdirectories.
     * Directory names are safe ASCII (e.g. "cb1").
     * Reverse-lookup via SAFE_TO_CHAIN to attach chain metadata.
     */
    private void loadGeneratedEnvironments() {
        Path envPath = bs5RootPath.resolve("generated-env");
        if (!Files.exists(envPath)) return;
        try (Stream<Path> paths = Files.list(envPath)) {
            paths.filter(Files::isDirectory).forEach(p -> {
                String safe      = p.getFileName().toString();
                String chainName = SAFE_TO_CHAIN.getOrDefault(safe, safe);

                Map<String, Object> envInfo = new HashMap<>();
                envInfo.put("name",          safe);
                envInfo.put("chainName",     chainName);
                envInfo.put("path",          p.toAbsolutePath().toString());
                envInfo.put("hasPom",        Files.exists(p.resolve("pom.xml")));
                envInfo.put("hasDockerfile", Files.exists(p.resolve("Dockerfile")));
                envInfo.put("hasSource",     Files.exists(p.resolve("src")));

                if (chainsInfo.containsKey(chainName)) {
                    Map<String, Object> ci = chainsInfo.get(chainName);
                    envInfo.put("payloadTypes",   ci.getOrDefault("payload_types",   Collections.emptyList()));
                    envInfo.put("pipeline",       ci.getOrDefault("pipeline",         Collections.emptyList()));
                    envInfo.put("mavenArtifacts", ci.getOrDefault("maven_artifacts",  Collections.emptyList()));
                }
                generatedEnvironments.add(envInfo);
            });
            System.out.println("Loaded " + generatedEnvironments.size() + " generated environments");
        } catch (IOException e) {
            System.err.println("Error loading generated environments: " + e.getMessage());
        }
    }

    private void initializeChainUrls() {
        if (!chainsInfo.isEmpty()) {
            chainsInfo.keySet().forEach(chain -> {
                String safe = CHAIN_TO_SAFE.getOrDefault(chain,
                    chain.toLowerCase().replaceAll("[^a-z0-9]", ""));
                if (safe.isEmpty()) safe = "chain";
                chainUrls.put(chain, "http://" + safe + ":8080");
            });
        } else {
            loadDefaultChains();
        }
    }

    private void loadDefaultChains() {
        for (String c : new String[]{
            "BeanShell1","CommonsCollections1","CommonsCollections2","CommonsCollections3",
            "CommonsCollections4","CommonsCollections5","CommonsCollections6","CommonsCollections7",
            "Groovy1","Groovy2","JRMPClient","JRMPListener","Jdk7u21","C3P0",
            "Hibernate1","Hibernate2","Spring1","Spring2","Myfaces1","Myfaces2","JNDI"
        }) chainUrls.put(c, "http://" + c.toLowerCase() + ":8080");
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    public List<String> getAllChains() { return new ArrayList<>(chainUrls.keySet()); }

    public List<String> getAvailableCategories() {
        return chainsInfo.values().stream()
            .map(info -> {
                @SuppressWarnings("unchecked")
                List<String> pts = (List<String>) info.getOrDefault("payload_types", Collections.emptyList());
                return pts.isEmpty() ? "Unknown" : primaryCategory(pts.get(0));
            })
            .distinct().sorted().collect(Collectors.toList());
    }

    public Map<String, List<String>> getChainsByCategory() {
        Map<String, List<String>> map = new HashMap<>();
        chainsInfo.forEach((name, info) -> {
            @SuppressWarnings("unchecked")
            List<String> pts = (List<String>) info.getOrDefault("payload_types", Collections.emptyList());
            map.computeIfAbsent(pts.isEmpty() ? "Unknown" : primaryCategory(pts.get(0)),
                k -> new ArrayList<>()).add(name);
        });
        return map;
    }

    public Map<String, Object> getChainInfo(String chainName) {
        return chainsInfo.getOrDefault(chainName, Collections.emptyMap());
    }

    /**
     * Trigger deserialization on the target chain container.
     * All generated environments expose POST /api/deserialize.
     * INFO-type chains (JSP文件 etc.) do not have this endpoint —
     * the gateway returns an informative error rather than a connection failure.
     */
    public String triggerDeserialization(String chainName, String payload) {
        // Guard: INFO-only chains have no /api/deserialize endpoint
        Map<String, Object> info = chainsInfo.get(chainName);
        if (info != null) {
            @SuppressWarnings("unchecked")
            List<String> pts = (List<String>) info.getOrDefault("payload_types", Collections.emptyList());
            if (pts.contains("OtherPayload") && !chainName.toLowerCase().contains("jdbc")) {
                return "{\"status\":\"NOT_SUPPORTED\","
                    + "\"message\":\"This chain is a payload-generation utility. "
                    + "Use java-chains to generate the payload file and deploy it manually.\","
                    + "\"chain\":\"" + chainName + "\"}";
            }
        }

        String baseUrl = resolveChainUrl(chainName);
        System.out.println("Triggering deserialization: " + chainName + " -> " + baseUrl);
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            Map<String, String> body = Collections.singletonMap("payload", payload);
            ResponseEntity<String> resp = restTemplate.postForEntity(
                baseUrl + "/api/deserialize", new HttpEntity<>(body, headers), String.class);
            return resp.getBody() != null ? resp.getBody() : "No response";
        } catch (Exception e) {
            System.err.println("Deserialize error: " + e.getMessage());
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Forward a command to the target chain container's GET /api/exec endpoint.
     * Available on NATIVE, HESSIAN, and JDBC chain containers.
     */
    public String execOnChain(String chainName, String cmd) {
        String baseUrl = resolveChainUrl(chainName);
        System.out.println("Exec on chain: " + chainName + " cmd=" + cmd);
        try {
            String encoded = java.net.URLEncoder.encode(cmd, "UTF-8");
            ResponseEntity<String> resp = restTemplate.getForEntity(
                baseUrl + "/api/exec?cmd=" + encoded, String.class);
            return resp.getBody() != null ? resp.getBody() : "No response";
        } catch (Exception e) {
            System.err.println("Exec error: " + e.getMessage());
            return "{\"status\":\"ERROR\",\"error\":\""
                + e.getMessage().replace("\"", "'") + "\"}";
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private String resolveChainUrl(String chainName) {
        String url = chainUrls.get(chainName);
        if (url == null) throw new RuntimeException("Chain not found in URL mapping: " + chainName);
        return url;
    }

    /**
     * Map the first payload_type to a human-readable category name.
     *
     * Priority order matters — FakeMySQLRead must be checked before the
     * broader FakeMySQL prefix (which falls into JavaNative in v3.0).
     *
     * Categories returned:
     *   Hessian     — HessianPayload / Hessian2Payload / Hessian2ToStringPayload
     *   JNDI_REF    — JNDIResourceRefPayload / JNDIReferencePayload / JNDIRefBypassPayload
     *   JNDI_BASIC  — JNDIBasicPayload / BytecodePayload / JNDIShowHandPayload / FakeMySQLSHPayload
     *   FakeMySQL   — FakeMySQLReadPayload  (ReadFile链)
     *   Other       — OtherPayload  (JSP文件, Spring Bean Xml, charsets.jar)
     *   JavaNative  — everything else (JavaNativePayload, ShiroPayload, JRMPListener, …)
     */
    private static String primaryCategory(String pt) {
        if (pt == null) return "Unknown";
        // Hessian family
        if (pt.startsWith("Hessian"))                                           return "Hessian";
        // JNDI families
        if (pt.startsWith("JNDIResource") || pt.startsWith("JNDIRef"))         return "JNDI_REF";
        if (pt.startsWith("JNDIBasic")    || pt.startsWith("Bytecode")
                || pt.startsWith("JNDIShow"))                                   return "JNDI_BASIC";
        // FakeMySQLSHPayload — used by 命令执行/DNSLog探测链/Sleep探测链 alongside JNDI_BASIC types;
        // it falls into JNDI_BASIC via _JNDI_BASIC_PTS in the generator, so show same category here.
        if (pt.equals("FakeMySQLSHPayload"))                                    return "JNDI_BASIC";
        // FakeMySQLReadPayload — ReadFile链 only; must be checked BEFORE the broader FakeMySQL* check
        if (pt.equals("FakeMySQLReadPayload"))                                  return "FakeMySQL";
        // OtherPayload — payload-generation utility chains
        if (pt.equals("OtherPayload"))                                          return "Other";
        // JavaNative / Shiro / JRMP / remaining FakeMySQL variants
        if (pt.startsWith("JavaNative")   || pt.startsWith("JNDI")
                || pt.startsWith("JRMPListener") || pt.startsWith("FakeMySQL")
                || pt.startsWith("Shiro"))                                      return "JavaNative";
        return pt;
    }

    public Map<String, Object> getDependencies(String chainName) {
        Map<String, Object> info = chainsInfo.get(chainName);
        return info != null ? info : dependenciesCache.getOrDefault(chainName, Collections.emptyMap());
    }

    public Map<String, Map<String, Object>> getAllDependencies() {
        return chainsInfo.isEmpty() ? new HashMap<>(dependenciesCache) : new HashMap<>(chainsInfo);
    }

    public List<Map<String, Object>> getGeneratedEnvironments()      { return generatedEnvironments; }

    public Map<String, Object> getEnvironmentInfo(String envName) {
        return generatedEnvironments.stream()
            .filter(e -> envName.equals(e.get("name")) || envName.equals(e.get("chainName")))
            .findFirst().orElse(Collections.emptyMap());
    }

    public String getPomContent(String chainName) {
        try {
            // (?U) makes \w Unicode-aware in Java, matching Python's re.sub(r'[^\w\-]','_')
            // which is what gadget_chain_analyzer uses when writing directory names.
            // Without (?U), Java \w is ASCII-only: "BeanshellRef 利用" -> "BeanshellRef___"
            // With    (?U), Java \w is Unicode:     "BeanshellRef 利用" -> "BeanshellRef_利用"
            String unicodeDir = chainName.replaceAll("(?U)[^\\w\\-]", "_");
            String asciiDir   = chainName.replaceAll("[^\\w\\-]", "_");  // legacy fallback

            for (String d : new String[]{unicodeDir, asciiDir, chainName}) {
                Path pom = bs5RootPath.resolve("gadget-dependencies").resolve(d).resolve("pom.xml");
                if (Files.exists(pom)) return new String(Files.readAllBytes(pom));
            }

            // Last-resort: fuzzy scan (normalize both sides, ignore all non-alphanumeric)
            Path depsDir = bs5RootPath.resolve("gadget-dependencies");
            if (Files.exists(depsDir)) {
                String normChain = chainName.replaceAll("[^a-zA-Z0-9]", "").toLowerCase();
                try (Stream<Path> dirs = Files.list(depsDir)) {
                    Optional<Path> found = dirs
                        .filter(Files::isDirectory)
                        .filter(d2 -> d2.getFileName().toString()
                            .replaceAll("[^a-zA-Z0-9]", "").toLowerCase()
                            .equals(normChain))
                        .findFirst();
                    if (found.isPresent()) {
                        Path pom = found.get().resolve("pom.xml");
                        if (Files.exists(pom)) return new String(Files.readAllBytes(pom));
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading POM for " + chainName + ": " + e.getMessage());
        }
        return null;
    }

    public boolean isChainAnalyzed(String chainName)       { return chainsInfo.containsKey(chainName); }

    public boolean isEnvironmentGenerated(String chainName) {
        String safe = CHAIN_TO_SAFE.getOrDefault(chainName, "");
        return generatedEnvironments.stream()
            .anyMatch(e -> chainName.equals(e.get("chainName")) || safe.equals(e.get("name")));
    }

    public void refreshMcpData() {
        chainsInfo.clear(); dependenciesCache.clear();
        generatedEnvironments.clear(); chainUrls.clear();
        loadMcpData();
    }
}
