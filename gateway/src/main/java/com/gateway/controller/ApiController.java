package com.gateway.controller;

import com.gateway.service.ChainService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ApiController {

    @Autowired
    private ChainService chainService;

    // -----------------------------------------------------------------------
    // Chain listing
    // -----------------------------------------------------------------------

    @GetMapping("/chains")
    public ResponseEntity<?> getAvailableChains() {
        Map<String, Object> response = new HashMap<>();
        response.put("chains",     chainService.getAllChains());
        response.put("total",      chainService.getAllChains().size());
        response.put("categories", chainService.getAvailableCategories());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/chains/by-category")
    public ResponseEntity<?> getChainsByCategory() {
        return ResponseEntity.ok(chainService.getChainsByCategory());
    }

    // -----------------------------------------------------------------------
    // Deserialization trigger
    // -----------------------------------------------------------------------

    @PostMapping("/trigger")
    public ResponseEntity<?> triggerDeserialization(@RequestBody TriggerRequest request) {
        if (request.getPayload() == null || request.getPayload().trim().isEmpty()) {
            Map<String, Object> m = new HashMap<>();
            m.put("success",   false);
            m.put("error",    "Payload is required. Please provide a serialized payload.");
            m.put("timestamp", System.currentTimeMillis());
            return ResponseEntity.badRequest().body(m);
        }
        try {
            String result = chainService.triggerDeserialization(
                request.getChain(), request.getPayload());
            Map<String, Object> ok = new HashMap<>();
            ok.put("success",   true);
            ok.put("result",    result);
            ok.put("timestamp", System.currentTimeMillis());
            return ResponseEntity.ok(ok);
        } catch (Exception e) {
            Map<String, Object> err = new HashMap<>();
            err.put("success",   false);
            err.put("error",     e.getMessage());
            err.put("timestamp", System.currentTimeMillis());
            return ResponseEntity.badRequest().body(err);
        }
    }

    // -----------------------------------------------------------------------
    // /api/exec  — forward command to a target chain container
    // -----------------------------------------------------------------------

    /**
     * Execute a shell command on the target chain container and return the output.
     *
     * This forwards the request to GET http://&lt;chainContainer&gt;:8080/api/exec?cmd=...
     * which is available on NATIVE and HESSIAN chain environments.
     *
     * Intended use:
     *   1. First send a payload via POST /api/trigger to trigger RCE.
     *   2. Then call GET /api/exec/{chainName}?cmd=id to directly verify
     *      command execution on the container (independent of the gadget).
     *
     * Example:
     *   GET /api/exec/CB1链?cmd=id
     *   GET /api/exec/CB1链?cmd=cat%20/etc/passwd
     *
     * @param chainName  URL-encoded chain name
     * @param cmd        shell command string
     */
    @GetMapping("/exec/{chainName}")
    public ResponseEntity<?> execOnChain(
            @PathVariable String chainName,
            @RequestParam(defaultValue = "id") String cmd) {
        try {
            String raw = chainService.execOnChain(chainName, cmd);

            // The target returns JSON — pass it through as-is wrapped in gateway envelope
            Map<String, Object> response = new HashMap<>();
            response.put("chain",  chainName);
            response.put("cmd",    cmd);
            response.put("result", raw);
            response.put("timestamp", System.currentTimeMillis());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> err = new HashMap<>();
            err.put("success", false);
            err.put("chain",   chainName);
            err.put("cmd",     cmd);
            err.put("error",   e.getMessage());
            return ResponseEntity.badRequest().body(err);
        }
    }

    // -----------------------------------------------------------------------
    // Chain detail / dependencies / pom
    // -----------------------------------------------------------------------

    @GetMapping("/dependencies/{chain}")
    public ResponseEntity<?> getDependencies(@PathVariable String chain) {
        Map<String, Object> deps = chainService.getDependencies(chain);
        if (deps.isEmpty()) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(deps);
    }

    @GetMapping("/dependencies")
    public ResponseEntity<?> getAllDependencies() {
        return ResponseEntity.ok(chainService.getAllDependencies());
    }

    @GetMapping("/chain-info/{chain}")
    public ResponseEntity<?> getChainInfo(@PathVariable String chain) {
        Map<String, Object> info = chainService.getChainInfo(chain);
        if (info.isEmpty()) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(info);
    }

    @GetMapping("/pom/{chain}")
    public ResponseEntity<?> getPomContent(@PathVariable String chain) {
        String content = chainService.getPomContent(chain);
        if (content == null) return ResponseEntity.notFound().build();
        Map<String, Object> response = new HashMap<>();
        response.put("chain",   chain);
        response.put("content", content);
        return ResponseEntity.ok(response);
    }

    // -----------------------------------------------------------------------
    // Environments
    // -----------------------------------------------------------------------

    @GetMapping("/environments")
    public ResponseEntity<?> getGeneratedEnvironments() {
        Map<String, Object> response = new HashMap<>();
        response.put("environments", chainService.getGeneratedEnvironments());
        response.put("total",        chainService.getGeneratedEnvironments().size());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/environments/{envName}")
    public ResponseEntity<?> getEnvironmentInfo(@PathVariable String envName) {
        Map<String, Object> info = chainService.getEnvironmentInfo(envName);
        if (info.isEmpty()) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(info);
    }

    // -----------------------------------------------------------------------
    // Categories / health / refresh
    // -----------------------------------------------------------------------

    @GetMapping("/categories")
    public ResponseEntity<?> getCategories() {
        Map<String, Object> response = new HashMap<>();
        response.put("categories", chainService.getAvailableCategories());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshMcpData() {
        try {
            chainService.refreshMcpData();
            Map<String, Object> response = new HashMap<>();
            response.put("success",      true);
            response.put("message",      "MCP data refreshed successfully");
            response.put("chains",       chainService.getAllChains().size());
            response.put("environments", chainService.getGeneratedEnvironments().size());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> err = new HashMap<>();
            err.put("success", false);
            err.put("error",   e.getMessage());
            return ResponseEntity.badRequest().body(err);
        }
    }

    @GetMapping("/health/{chainName}")
    public ResponseEntity<?> checkChainHealth(@PathVariable String chainName) {
        Map<String, Object> response = new HashMap<>();
        response.put("chain",               chainName);
        response.put("analyzed",            chainService.isChainAnalyzed(chainName));
        response.put("environmentGenerated", chainService.isEnvironmentGenerated(chainName));
        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    public ResponseEntity<?> getSystemHealth() {
        Map<String, Object> response = new HashMap<>();
        response.put("chains",       chainService.getAllChains().size());
        response.put("environments", chainService.getGeneratedEnvironments().size());
        response.put("categories",   chainService.getAvailableCategories().size());
        response.put("timestamp",    System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }
}

// ---------------------------------------------------------------------------
// Request DTO
// ---------------------------------------------------------------------------

class TriggerRequest {
    private String chain;
    private String payload;
    public String getChain()             { return chain; }
    public void   setChain(String chain) { this.chain = chain; }
    public String getPayload()               { return payload; }
    public void   setPayload(String payload) { this.payload = payload; }
}
