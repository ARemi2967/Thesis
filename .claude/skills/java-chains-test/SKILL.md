# java-chains-test Skill

Automated testing of Java deserialization gadget chains using Chrome DevTools MCP.

## Prerequisites

- Chrome DevTools MCP server configured and running
- java-chains web application accessible (default: http://localhost:8080)
- Target vulnerable environments running via docker-compose

## Workflow

### Step 1: Open java-chains Web Interface

Use Chrome DevTools MCP to navigate to the java-chains web application.

1. Open browser and navigate to java-chains URL
2. Wait for the page to load completely
3. Verify the chain list is visible

### Step 2: Select Target Chain

For each gadget chain to test:

1. Find the chain in the web interface chain list
2. Click to select the target chain
3. Configure payload parameters:
   - Command: `echo chain_ok` (for RCE verification)
   - Or `sleep 3` (for sleep-based verification)
4. For JNDI chains: configure JNDI server URL pointing to the test environment

### Step 3: Generate Payload

1. Click the generate button to create the serialized payload
2. Copy the generated payload (base64 encoded)
3. If the chain requires a specific protocol (Hessian, AMF, etc.), ensure the correct format is selected

### Step 4: Send Payload to Target Environment

1. Navigate to the target environment URL: `http://localhost:<port>/api/trigger`
2. Send the payload via POST request with JSON body:
   ```json
   {
     "chain": "<chain_name>",
     "payload": "<base64_payload>"
   }
   ```
3. Alternatively, use the environment's web UI to submit the payload

### Step 5: Verify Exploitation

1. For RCE chains: Check `/api/exec/<chain_name>?cmd=echo chain_ok` for expected output
2. For Sleep chains: Measure response time (should be >= 3000ms)
3. For JNDI chains: Verify the JNDI callback was received
4. Record the result (pass/fail)

### Step 6: Report Results

After testing all chains:
1. Summarize: total tested, passed, failed, skipped
2. For failures: include chain name, error details, and suggested fix
3. Save results to test report

## Chain Categories

| Category | Test Method | Verification |
|----------|-------------|-------------|
| NATIVE | ObjectInputStream payload | `/api/exec` RCE check |
| HESSIAN | Hessian2 payload | `/api/exec` RCE check |
| AMF | AMF3 payload | `/api/exec` RCE check |
| JNDI_BASIC | JNDI lookup payload | Sleep check (3s) |
| JNDI_REF | JNDI Reference payload | `/api/exec` RCE check |
| JDBC | JDBC URL payload | `/api/exec` RCE check |
| FAKE_MYSQL | MySQL protocol | File read verification |

## Notes

- Test chains in batches to avoid overloading environments
- For JNDI chains, ensure the JNDI server is running and accessible
- Some chains may crash the JVM (e.g., JDK原生链2) — skip these
- Record all LLM decisions during testing for ablation study analysis
