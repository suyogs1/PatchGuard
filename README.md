# PatchGuard AIRLOCK | Autonomous Self-Healing Runner (Proof Before Ship)

> **Vultr Agent Rush Hackathon Submission**  
> **Challenge:** 01 · Blast Radius Zero  
> **Execution Pattern:** Pattern A (Sandboxed Code Execution / Self-Healing Runner)  
> **Live Production Dashboard:** [http://64.177.57.156:3000](http://64.177.57.156:3000)  
> **FastAPI Interactive Docs:** [http://64.177.57.156:8001/docs](http://64.177.57.156:8001/docs)  
> **Repository:** [https://github.com/suyogs1/PatchGuard](https://github.com/suyogs1/PatchGuard)  

---

## 1. Overview & Problem Statement

Autonomous coding agents are rapidly entering CI/CD pipelines, but enterprise adoption is stalled by a fundamental safety barrier: **unbounded blast radius**. When an LLM generates a patch for a critical vulnerability, traditional continuous integration relies on passive static analysis or pre-existing unit tests. It cannot prove that:
1. The fix actually neutralizes the real-world, weaponized exploit.
2. The patch does not introduce regressions or side-channel exploits.
3. The evaluation environment itself remains protected from malicious payload escape.

**PatchGuard AIRLOCK** solves this by establishing an adversarial, closed-loop remediation control plane. Operating under **Pattern A (Self-Healing Runner / "Proof Before Ship")**, AIRLOCK subjects untrusted AI patches to live exploit replays inside isolated micro-sandboxes, verifies host containment via live system telemetry, and binds the entire lifecycle into a tamper-evident cryptographic receipt before opening a production pull request.

---

## 2. Vultr Services & Infrastructure Architecture

PatchGuard AIRLOCK uses Vultr as its core control plane and intelligence engine:

* **Vultr Cloud Compute (High Performance / Ubuntu 24.04 LTS):**  
  Hosts the core AIRLOCK control plane, container orchestration engine, and host telemetry monitors.
* **Vultr Marketplace (Coolify Deployment Engine):**  
  Deploys, manages, and provisions the multi-container production stack (FastAPI backend + Next.js frontend) with automated zero-downtime builds and network isolation.
* **Vultr Serverless Inference (`deepseek-v4-flash-0731`):**  
  Powers the autonomous reasoning engine. When Sandbox #01 captures an active exploit, AIRLOCK dispatches AST data, exception traces, and execution telemetry to Vultr Serverless Inference. The model diagnoses the root cause, analyzes potential attack bypasses, and emits an exact, minimal patch.

  ┌──────────────────────────────────────────────┐
                    │              Client Browser                  │
                    │           (Next.js 16 Dashboard)             │
                    └──────────────────────┬───────────────────────┘
                                           │ HTTP / WebSocket (:8001)
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ VULTR CLOUD COMPUTE CONTROL PLANE                                                       │
│                                                                                         │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │ FastAPI Control Layer (server.py)                                                 │  │
│  │ - Secret Hygiene: API keys stay isolated on host runtime                          │  │
│  │ - Telemetry Monitor: Samples /proc/stat & memory delta every 250ms                │  │
│  │ - Lifecycle Manager: Strict resource quotas (1 CPU, 512MB RAM, PID cap: 100)      │  │
│  └───────────┬──────────────────────────────────────────┬────────────────────────────┘  │
│              │                                          │                               │
│              │ Dispatch Failure Logs & AST              │ Spawns Isolated Containers    │
│              ▼                                          ▼ via /var/run/docker.sock      │
│  ┌───────────────────────────────┐     ┌─────────────────────────────────────────────┐  │
│  │   Vultr Serverless Inference  │     │ Google gVisor Micro-Sandboxes (runsc)       │  │
│  │   (deepseek-v4-flash-0731)    │     │                                             │  │
│  │                               │     │  [Sandbox #01: Reproduction Phase]          │  │
│  │  - Zero-shot Root Cause AST   │     │  - Replays target exploit payload           │  │
│  │  - Deterministic Patch Synth  │     │  - Confirms vulnerability trigger           │  │
│  │  - Security Invariant Rules   │     │  - Ephemeral destroy on exit                │  │
│  └───────────┬───────────────────┘     │                                             │  │
│              │ Emits Patch             │  [Sandbox #02: Proof-Before-Ship Phase]     │  │
│              └────────────────────────►│  - Applies AI-synthesized patch             │  │
│                                        │  - Replays primary attack (verifies block)  │  │
│                                        │  - Red-Team mutation barrage (fuzz tests)   │  │
│                                        │  - Runs full 47/47 regression suite         │  │
│                                        └─────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┬──────────────────────────────────┘
│
│ Verified Fix + Evidence Receipt
▼
┌─────────────────────────────────┐
│       GitHub Pull Request       │
│ - Branch: patchguard/fix-*      │
│ - Tamper-evident SHA-256 Digest │
│ - Host Containment Audit Logs   │
└─────────────────────────────────┘

---

## 3. How the Agent Executes Real Tasks (The 4-Phase Loop)

1. **Adversarial Reproduction (Sandbox #01):**  
   AIRLOCK initializes an isolated micro-sandbox running under Google gVisor (`runsc`). The unpatched code is subjected to the reported exploit payload (e.g., path traversal, command injection) to confirm exploitability in a live environment.
2. **Autonomous Reasoning & Patch Synthesis:**  
   Runtime stack traces, syscall patterns, and AST representations are forwarded to **Vultr Serverless Inference (`deepseek-v4-flash-0731`)**. The model analyzes the security boundaries and produces a minimal code patch.
3. **Dual-Sandbox Retest & Variant Barrage (Sandbox #02):**  
   A fresh, pristine micro-sandbox mounts the patched code. AIRLOCK re-executes the original exploit to confirm neutralization, executes a barrage of mutated exploit variants, and runs the entire regression test suite (47/47 tests).
4. **Host Telemetry & Cryptographic Proof:**  
   Host-level metrics continuously track CPU/RAM utilization via `/proc` delta sampling (<1% delta), confirming that the exploit was fully contained. A SHA-256 tamper-evident digest is generated and attached to an automated GitHub Pull Request.

---

## 4. Challenge 01: Blast Radius Zero Compliance

* **Process Isolation:** Sandboxes execute with Google gVisor (`runsc`), intercepting all syscalls in a sandboxed user-space kernel to prevent container escapes.
* **Secret Hygiene:** Production secrets (`VULTR_API_KEY`, `GITHUB_TOKEN`) exist strictly on the FastAPI host runtime and are never mounted or exposed inside sandbox containers.
* **Resource Limits:** Sandboxes enforce strict hard caps: 1.0 vCPU, 512 MB memory, and a maximum of 100 PIDs.
* **Lifecycle Discipline:** All sandbox instances are fully destroyed and unmounted immediately upon execution completion.

---

## 5. Security Lab Targets Available for Testing

| Target ID | Title | CVSS | Vector | Target File |
| :--- | :--- | :---: | :--- | :--- |
| **PG-LAB-001** | Subprocess Shell Expansion | 9.8 | CWE-78: Command Injection | `app/services/query.py` |
| **PG-LAB-002** | Arbitrary Path Traversal | 8.6 | CWE-22: Pathname Limitation | `app/routes/files.py` |
| **PG-LAB-003** | Unsafe Deserialization | 9.8 | CWE-502: Pickle RCE | `app/auth/session.py` |

---

## 6. Local Setup & Quickstart

### Prerequisites
* Docker & Docker Compose
* Google gVisor (`runsc`) installed on the host Docker daemon
* Vultr Serverless Inference API Key

```bash
# 1. Clone repository
git clone [https://github.com/suyogs1/PatchGuard.git](https://github.com/suyogs1/PatchGuard.git)
cd PatchGuard

# 2. Build sandbox image
docker build -t patchguard-sandbox:latest - << 'EOF'
FROM python:3.11-slim
RUN useradd -u 1000 sandboxuser && \
    mkdir -p /workspace /tmp && \
    chown -R sandboxuser:sandboxuser /workspace /tmp
WORKDIR /workspace
USER sandboxuser
EOF

# 3. Configure environment
cat << 'EOF' > .env
VULTR_API_KEY=your_vultr_api_key_here
GITHUB_TOKEN=your_github_token_here
GITHUB_REPO=suyogs1/PatchGuard
EOF

# 4. Start services
docker compose up -d --build

---

### Command to Push to GitHub from Your Server

Run this command directly in your server terminal at `/root/patchguard`:

```bash
cd /root/patchguard

# Write README.md and push to main
git add README.md
git commit -m "docs: complete submission README matching Vultr hackathon criteria"

export GITHUB_TOKEN=$(grep -E '^GITHUB_TOKEN=' /data/coolify/services/*/.env 2>/dev/null || grep -E '^GITHUB_TOKEN=' .env 2>/dev/null | head -n1 | cut -d '=' -f2- | tr -d '"' | tr -d "'" | tr -d '\r')
git push https://suyogs1:${GITHUB_TOKEN}@github.com/suyogs1/PatchGuard.git main
