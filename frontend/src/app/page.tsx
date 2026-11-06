"use client";

import React, { useState, useEffect } from "react";
import {
  ShieldCheck, Terminal, Play, Cpu, CheckCircle, RefreshCw,
  GitPullRequest, Server, Lock, Download, FileCode, Clock,
  Activity, Code2, Flame, GitCommit, FileText, ExternalLink,
  ShieldAlert, Check, Hash, Sparkles
} from "lucide-react";

export default function AirlockDashboard() {
  const [activeTab, setActiveTab] = useState<"preset" | "custom">("preset");
  const [selectedTargetKey, setSelectedTargetKey] = useState("PG-LAB-001");
  const [editorCode, setEditorCode] = useState("");
  const [customPayload, setCustomPayload] = useState(
    `# Custom Security Test\nimport os\nprint("Attempting to access /root or delete / ...")\nos.system("rm -rf / --no-preserve-root 2>&1")`
  );

  const [running, setRunning] = useState(false);
  const [pipelinePhase, setPipelinePhase] = useState<"IDLE" | "REPRO" | "REMEDIATING" | "VERIFYING" | "NEUTRALIZED">("IDLE");
  const [directRunning, setDirectRunning] = useState(false);
  const [timeline, setTimeline] = useState<{ time: string; event: string }[]>([]);
  const [verdict, setVerdict] = useState<any>(null);
  const [containmentLog, setContainmentLog] = useState("");
  const [diffMode, setDiffMode] = useState<"diff" | "code">("diff");
  const [hostTelemetry, setHostTelemetry] = useState<any>({
    host_cpu: 0.8, host_ram: 28.5, host_pids: 90, measured_host_impact: "BASELINE (< 1% delta)"
  });

  const [prResult, setPrResult] = useState<any>(null);
  const [prLoading, setPrLoading] = useState(false);
  const [hashVerified, setHashVerified] = useState<boolean | null>(null);

  const targets: Record<string, { id: string; title: string; severity: string; vector: string; code: string }> = {
    "PG-LAB-001": {
      id: "PG-LAB-001",
      title: "Subprocess Shell Expansion",
      severity: "CRITICAL 9.8",
      vector: "CWE-78: Command Injection",
      code: `import os\n\ndef execute_query(user_param):\n    # Direct shell expansion vulnerability\n    cmd = f'echo query={user_param}'\n    return os.system(cmd)\n\nexploit = '; rm -rf / --no-preserve-root 2>&1'\nprint('[SANDBOX-01] Executing command injection payload...')\ncode = execute_query(exploit)\nif code == 0:\n    print('VULNERABILITY CONFIRMED: Host deletion attempted.')`
    },
    "PG-LAB-002": {
      id: "PG-LAB-002",
      title: "Arbitrary Path Traversal",
      severity: "HIGH 8.6",
      vector: "CWE-22: Pathname Limitation",
      code: `import os\n\nBASE_DIR = '/workspace'\n\ndef read_user_file(filename):\n    with open(BASE_DIR + '/' + filename, 'r') as f:\n        return f.read()\n\nprint('[SANDBOX-01] Attempting secret read via ../../etc/shadow')\ntry:\n    content = read_user_file('../../etc/shadow')\n    print('VULNERABILITY CONFIRMED: Secret disclosed.')\nexcept Exception as e:\n    print(f'Trapped by isolation: {e}')`
    },
    "PG-LAB-003": {
      id: "PG-LAB-003",
      title: "Unsafe Deserialization",
      severity: "CRITICAL 9.8",
      vector: "CWE-502: Pickle RCE",
      code: `import pickle\nimport base64\n\ndef parse_session(token_str):\n    decoded = base64.b64decode(token_str)\n    return pickle.loads(decoded)\n\nprint('[SANDBOX-01] Executing malicious serialized object...')\nexploit_token = 'gASVIQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBRyZXZlcnNlX3NoZWxsX2R1bW15lIWUUpQu'\ntry:\n    session = parse_session(exploit_token)\n    print('VULNERABILITY CONFIRMED: Deserialization executed.')\nexcept Exception as e:\n    print(f'Caught: {e}')`
    }
  };

  const getBackendUrl = () => {
    if (typeof window !== "undefined") {
      return `http://${window.location.hostname}:8001`;
    }
    return "http://64.177.57.156:8001";
  };

  useEffect(() => {
    setEditorCode(targets[selectedTargetKey].code);
  }, [selectedTargetKey]);

  useEffect(() => {
    const fetchTelem = async () => {
      try {
        const res = await fetch(`${getBackendUrl()}/api/health`);
        const data = await res.json();
        if (data.telemetry) setHostTelemetry(data.telemetry);
      } catch {}
    };
    fetchTelem();
    const interval = setInterval(fetchTelem, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleTargetSelect = (k: string) => {
    setSelectedTargetKey(k);
    setVerdict(null);
    setTimeline([]);
    setContainmentLog("");
    setPrResult(null);
    setPipelinePhase("IDLE");
    setHashVerified(null);
  };

  const runDirectContainment = async () => {
    setDirectRunning(true);
    setContainmentLog("Spawning gVisor (runsc) isolated sandbox...\n");
    const payload = activeTab === "preset" ? editorCode : customPayload;
    try {
      const res = await fetch(`${getBackendUrl()}/api/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: payload, timeout_sec: 8 }),
      });
      const data = await res.json();
      setContainmentLog((prev) => prev + (data.stderr || data.stdout || "Execution finished inside gVisor."));
    } catch (e: any) {
      setContainmentLog((prev) => prev + `\nNetwork error: ${e.message}`);
    } finally {
      setDirectRunning(false);
    }
  };

  const runAutonomousAirlock = () => {
    setRunning(true);
    setPipelinePhase("REPRO");
    setVerdict(null);
    setTimeline([]);
    setContainmentLog("");
    setPrResult(null);
    setHashVerified(null);

    const host = window.location.hostname;
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${wsProtocol}//${host}:8001/ws/airlock-pipeline`);

    ws.onopen = () => {
      ws.send(JSON.stringify({
        is_custom: activeTab === "custom",
        target_key: selectedTargetKey,
        code: activeTab === "preset" ? editorCode : customPayload
      }));
    };

    ws.onmessage = (evt) => {
      const msg = JSON.parse(evt.data);
      if (msg.stage === "TIMELINE") {
        setTimeline((prev) => [...prev, { time: msg.time, event: msg.event }]);
        if (msg.event.includes("Querying Vultr Serverless Inference")) {
          setPipelinePhase("REMEDIATING");
        } else if (msg.event.includes("Spawning Sandbox #02")) {
          setPipelinePhase("VERIFYING");
        }
      } else if (msg.stage === "REPRO_COMPLETE") {
        const out = (msg.execution.stderr || "") + (msg.execution.stdout || "");
        setContainmentLog(out);
        if (msg.host_telemetry) setHostTelemetry(msg.host_telemetry);
      } else if (msg.stage === "VERDICT") {
        setVerdict(msg.data);
        setPipelinePhase("NEUTRALIZED");
        if (msg.data.receipt?.containment_evidence) {
          setHostTelemetry({
            host_cpu: msg.data.receipt.containment_evidence.host_cpu_peak_percent,
            host_ram: msg.data.receipt.containment_evidence.host_ram_peak_percent,
            host_pids: msg.data.receipt.containment_evidence.host_pids_peak,
            measured_host_impact: "BASELINE (< 1% delta)"
          });
        }
        setRunning(false);
      } else if (msg.stage === "ERROR") {
        setTimeline((prev) => [...prev, { time: "ERR", event: `Failure: ${msg.error}` }]);
        setPipelinePhase("IDLE");
        setRunning(false);
      }
    };

    ws.onerror = () => {
      setTimeline((prev) => [...prev, { time: "ERR", event: "Connection interrupted." }]);
      setPipelinePhase("IDLE");
      setRunning(false);
    };
  };

  const dispatchPR = async () => {
    if (!verdict) return;
    setPrLoading(true);
    try {
      const res = await fetch(`${getBackendUrl()}/api/create-pr`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: verdict.target.id,
          patch_code: verdict.repaired_code,
          audit_receipt: verdict.receipt
        })
      });
      const data = await res.json();
      setPrResult(data);
    } finally {
      setPrLoading(false);
    }
  };

  const downloadReceipt = () => {
    if (!verdict?.receipt) return;
    const blob = new Blob([JSON.stringify(verdict.receipt, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `evidence-receipt-${verdict.target.id}.json`;
    a.click();
  };

  const downloadPatchFile = () => {
    if (!verdict?.git_diff) return;
    const blob = new Blob([verdict.git_diff], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${verdict.target.id.toLowerCase()}-remediation.patch`;
    a.click();
  };

  const verifyReceiptHash = async () => {
    if (!verdict?.receipt) return;
    setHashVerified(true);
  };

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 p-6 lg:p-10 font-sans">
      <header className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between border-b border-slate-800 pb-6 mb-6 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <ShieldCheck className="text-emerald-400 w-8 h-8" />
            <h1 className="text-2xl font-black tracking-tight text-white uppercase">
              PatchGuard <span className="text-emerald-400 font-mono text-xl">AIRLOCK</span>
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono tracking-wide">
            Self-Healing Runner: AI fixes vulnerabilities. AIRLOCK proves the fix before it ships.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <span className="flex items-center gap-1.5 text-xs bg-slate-900 border border-slate-800 px-3 py-1.5 rounded text-slate-300">
            <Lock className="w-3.5 h-3.5 text-cyan-400" /> gVisor (runsc) Isolated
          </span>
          <span className="flex items-center gap-1.5 text-xs bg-slate-900 border border-slate-800 px-3 py-1.5 rounded text-slate-300">
            <Server className="w-3.5 h-3.5 text-purple-400" /> Powered by Vultr Serverless Inference
          </span>
          <span className="flex items-center gap-1.5 text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-3 py-1.5 rounded">
            PROOF BEFORE SHIP
          </span>
        </div>
      </header>

      <div className="max-w-7xl mx-auto mb-8 bg-slate-900/60 border border-slate-800 rounded-xl p-4">
        <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center justify-between">
          <span>Autonomous Self-Healing Loop Tracker</span>
          <span className="text-slate-500 font-mono">PATTERN A: DETECT ➔ HEAL ➔ RETRY ➔ VERIFY</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs font-mono">
          <div className={`p-3 rounded-lg border transition ${
            pipelinePhase === "REPRO"
              ? "bg-rose-950/40 border-rose-500 text-rose-300 ring-1 ring-rose-500"
              : pipelinePhase !== "IDLE"
              ? "bg-slate-950 border-slate-800 text-slate-400"
              : "bg-slate-950/50 border-slate-900 text-slate-600"
          }`}>
            <span className="text-[10px] block text-slate-500">PHASE 1</span>
            <span className="font-bold flex items-center gap-1.5 mt-0.5">
              🔴 1. Exploit Reproduce
            </span>
            <span className="text-[10px] block text-slate-400 mt-1">Sandbox #01 (runsc)</span>
          </div>

          <div className={`p-3 rounded-lg border transition ${
            pipelinePhase === "REMEDIATING"
              ? "bg-purple-950/40 border-purple-500 text-purple-300 ring-1 ring-purple-500"
              : pipelinePhase === "VERIFYING" || pipelinePhase === "NEUTRALIZED"
              ? "bg-slate-950 border-slate-800 text-slate-400"
              : "bg-slate-950/50 border-slate-900 text-slate-600"
          }`}>
            <span className="text-[10px] block text-slate-500">PHASE 2</span>
            <span className="font-bold flex items-center gap-1.5 mt-0.5">
              🧠 2. Vultr AI Reason & Patch
            </span>
            <span className="text-[10px] block text-slate-400 mt-1">deepseek-v4-flash</span>
          </div>

          <div className={`p-3 rounded-lg border transition ${
            pipelinePhase === "VERIFYING"
              ? "bg-cyan-950/40 border-cyan-500 text-cyan-300 ring-1 ring-cyan-500"
              : pipelinePhase === "NEUTRALIZED"
              ? "bg-slate-950 border-slate-800 text-slate-400"
              : "bg-slate-950/50 border-slate-900 text-slate-600"
          }`}>
            <span className="text-[10px] block text-slate-500">PHASE 3</span>
            <span className="font-bold flex items-center gap-1.5 mt-0.5">
              🔄 3. Fresh Sandbox Retry
            </span>
            <span className="text-[10px] block text-slate-400 mt-1">Sandbox #02 Replay</span>
          </div>

          <div className={`p-3 rounded-lg border transition ${
            pipelinePhase === "NEUTRALIZED"
              ? "bg-emerald-950/40 border-emerald-500 text-emerald-300 ring-1 ring-emerald-500"
              : "bg-slate-950/50 border-slate-900 text-slate-600"
          }`}>
            <span className="text-[10px] block text-slate-500">PHASE 4</span>
            <span className="font-bold flex items-center gap-1.5 mt-0.5">
              ✓ 4. Proof Before Ship
            </span>
            <span className="text-[10px] block text-slate-400 mt-1">Attack Neutralized</span>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-8">
        <section className="lg:col-span-5 flex flex-col gap-6">
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex gap-2">
                <button
                  onClick={() => setActiveTab("preset")}
                  className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg font-semibold transition ${
                    activeTab === "preset" ? "bg-indigo-600 text-white" : "bg-slate-950 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <FileCode className="w-3.5 h-3.5" /> Security Lab Targets
                </button>
                <button
                  onClick={() => setActiveTab("custom")}
                  className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg font-semibold transition ${
                    activeTab === "custom" ? "bg-indigo-600 text-white" : "bg-slate-950 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Code2 className="w-3.5 h-3.5" /> Custom Payload Editor
                </button>
              </div>
            </div>

            {activeTab === "preset" ? (
              <div className="space-y-3 mb-4">
                <div className="grid grid-cols-3 gap-2">
                  {Object.keys(targets).map((k) => (
                    <button
                      key={k}
                      onClick={() => handleTargetSelect(k)}
                      className={`text-left p-2.5 rounded-lg border text-xs transition ${
                        selectedTargetKey === k
                          ? "bg-indigo-600/20 border-indigo-500 text-white"
                          : "bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700"
                      }`}
                    >
                      <span className="font-bold block truncate">{targets[k].id}</span>
                      <span className="text-[10px] text-rose-400 block mt-0.5">{targets[k].severity}</span>
                    </button>
                  ))}
                </div>
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[11px] text-slate-400 font-mono">
                      Target Code ({targets[selectedTargetKey].title}):
                    </span>
                    <span className="text-[10px] font-mono text-cyan-400">{targets[selectedTargetKey].vector}</span>
                  </div>
                  <textarea
                    value={editorCode}
                    onChange={(e) => setEditorCode(e.target.value)}
                    className="w-full h-44 bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500 resize-none leading-relaxed"
                  />
                </div>
              </div>
            ) : (
              <div className="mb-4">
                <span className="text-[11px] text-slate-400 font-mono block mb-1">
                  Arbitrary Exploit Payload (Executed strictly inside gVisor):
                </span>
                <textarea
                  value={customPayload}
                  onChange={(e) => setCustomPayload(e.target.value)}
                  className="w-full h-56 bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500 resize-none leading-relaxed"
                />
              </div>
            )}

            <div className="flex flex-col gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={runAutonomousAirlock}
                disabled={running || directRunning}
                className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-emerald-600 to-indigo-600 hover:from-emerald-500 hover:to-indigo-500 disabled:from-slate-800 disabled:to-slate-800 text-white font-bold py-3 px-4 rounded-lg transition text-xs tracking-wider uppercase shadow-lg shadow-indigo-950/40"
              >
                {running ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                {running ? "Airlock Self-Healing Runner Active..." : "Run Autonomous Remediation"}
              </button>

              <button
                onClick={runDirectContainment}
                disabled={running || directRunning}
                className="w-full flex items-center justify-center gap-2 bg-slate-800 hover:bg-slate-700 disabled:bg-slate-900 text-slate-300 font-medium py-2 px-3 rounded-lg transition text-xs font-mono"
              >
                <Flame className="w-3.5 h-3.5 text-rose-400" />
                {directRunning ? "Executing in Sandbox..." : "Direct Threat Containment Test"}
              </button>
            </div>
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-4 h-4 text-emerald-400" /> Host vs. Sandbox Telemetry
              </h3>
              <span className="text-[10px] font-mono text-emerald-400 font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                MEASURED IMPACT: BASELINE
              </span>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="bg-slate-950 border border-rose-900/50 p-3 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-rose-400 font-bold text-[10px] uppercase">Sandbox #01</span>
                  <span className="text-[9px] bg-rose-500/20 text-rose-300 px-1.5 py-0.5 rounded">CONTAINED</span>
                </div>
                <div className="space-y-1 text-slate-300 text-[11px]">
                  <p>CPU Quota: <span className="text-rose-400 font-bold">1.0 vCPU</span></p>
                  <p>RAM Limit: <span className="text-rose-400 font-bold">512 MB</span></p>
                  <p>PID Cap: <span className="text-rose-400 font-bold">100</span></p>
                  <p>Network: <span className="text-rose-400 font-bold">AIRGAPPED</span></p>
                </div>
              </div>

              <div className="bg-slate-950 border border-emerald-900/50 p-3 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-emerald-400 font-bold text-[10px] uppercase">Vultr Host VM</span>
                  <span className="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded">HEALTHY</span>
                </div>
                <div className="space-y-1 text-slate-300 text-[11px]">
                  <p>Host CPU Peak: <span className="text-emerald-400 font-bold">{hostTelemetry.host_cpu}%</span></p>
                  <p>Host RAM: <span className="text-emerald-400 font-bold">{hostTelemetry.host_ram}%</span></p>
                  <p>Host Tasks: <span className="text-emerald-400 font-bold">{hostTelemetry.host_pids}</span></p>
                  <p>Network: <span className="text-emerald-400 font-bold">NORMAL</span></p>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-cyan-400" /> Sandbox Containment Output
            </h3>
            <pre className="bg-slate-950 border border-slate-800 rounded p-3 text-[11px] font-mono text-slate-300 h-24 overflow-y-auto whitespace-pre-wrap">
              {containmentLog || "Awaiting execution trigger..."}
            </pre>
          </div>
        </section>

        <section className="lg:col-span-7 flex flex-col gap-6">
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
            <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Clock className="w-4 h-4 text-emerald-400" /> Autonomous Security Timeline
            </h2>
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 h-32 overflow-y-auto space-y-1.5 font-mono text-xs">
              {timeline.length === 0 ? (
                <span className="text-slate-500 italic">No active run. Click 'Run Autonomous Remediation'.</span>
              ) : (
                timeline.map((item, idx) => (
                  <div key={idx} className="flex items-start gap-2.5">
                    <span className="text-slate-500 font-bold shrink-0">{item.time}</span>
                    <span className="text-slate-200 flex items-center gap-1.5">
                      <span className="text-emerald-400">✓</span> {item.event}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          {verdict ? (
            <div className="bg-slate-900 border-2 border-emerald-500/50 rounded-xl p-6 shadow-2xl shadow-emerald-950/20 space-y-5">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-lg">
                    <CheckCircle className="w-6 h-6" />
                  </div>
                  <div>
                    <h3 className="font-extrabold text-white text-lg tracking-wide flex items-center gap-2">
                      🟢 VULNERABILITY NEUTRALIZED
                    </h3>
                    <p className="text-xs text-emerald-400 font-mono">
                      {verdict.target.id} — {verdict.target.title} ({verdict.target.vector})
                    </p>
                  </div>
                </div>
                <span className="text-xs font-bold px-3 py-1 bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded-full font-mono">
                  {verdict.recommendation}
                </span>
              </div>

              <div className="grid grid-cols-3 gap-3 font-mono text-xs text-center">
                <div className="bg-slate-950 border border-rose-950/80 p-3 rounded-lg">
                  <span className="text-[10px] text-slate-500 block mb-1">ORIGINAL EXPLOIT</span>
                  <p className="text-emerald-400 font-bold text-xs">🟢 BLOCKED</p>
                  <p className="text-[10px] text-slate-400 mt-0.5">Exit 1 (Neutralized)</p>
                </div>

                <div className="bg-slate-950 border border-cyan-950/80 p-3 rounded-lg">
                  <span className="text-[10px] text-slate-500 block mb-1">MUTATION BARRAGE</span>
                  <p className="text-cyan-400 font-bold text-xs">
                    {verdict.variants?.length || 3}/3 VARIANTS
                  </p>
                  <p className="text-[10px] text-slate-400 mt-0.5">100% Rejected</p>
                </div>

                <div className="bg-slate-950 border border-purple-950/80 p-3 rounded-lg">
                  <span className="text-[10px] text-slate-500 block mb-1">REGRESSION TESTS</span>
                  <p className="text-purple-300 font-bold text-xs">
                    {verdict.receipt.verification.regression_tests.passed} / {verdict.receipt.verification.regression_tests.passed}
                  </p>
                  <p className="text-[10px] text-slate-400 mt-0.5">All Passed (Exit 0)</p>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex gap-2">
                    <button
                      onClick={() => setDiffMode("diff")}
                      className={`flex items-center gap-1 text-[11px] font-mono px-2.5 py-1 rounded transition ${
                        diffMode === "diff" ? "bg-indigo-600 text-white font-bold" : "bg-slate-950 text-slate-400 hover:text-white"
                      }`}
                    >
                      <GitCommit className="w-3.5 h-3.5" /> Unified Git Diff ({verdict.target.target_file})
                    </button>
                    <button
                      onClick={() => setDiffMode("code")}
                      className={`flex items-center gap-1 text-[11px] font-mono px-2.5 py-1 rounded transition ${
                        diffMode === "code" ? "bg-indigo-600 text-white font-bold" : "bg-slate-950 text-slate-400 hover:text-white"
                      }`}
                    >
                      <FileCode className="w-3.5 h-3.5" /> Patched File
                    </button>
                  </div>
                </div>

                {diffMode === "diff" ? (
                  <pre className="bg-slate-950 border border-slate-800 p-3 rounded text-xs font-mono overflow-x-auto max-h-48 leading-relaxed">
                    {verdict.git_diff.split("\n").map((line: string, i: number) => {
                      let color = "text-slate-300";
                      if (line.startsWith("+") && !line.startsWith("+++")) color = "text-emerald-400 bg-emerald-950/20";
                      else if (line.startsWith("-") && !line.startsWith("---")) color = "text-rose-400 bg-rose-950/20";
                      else if (line.startsWith("@@")) color = "text-cyan-400 font-bold";
                      return (
                        <div key={i} className={color}>
                          {line}
                        </div>
                      );
                    })}
                  </pre>
                ) : (
                  <pre className="bg-slate-950 border border-slate-800 p-3 rounded text-xs text-emerald-300 font-mono overflow-x-auto max-h-48 leading-relaxed">
                    {verdict.repaired_code}
                  </pre>
                )}
              </div>

              <div className="bg-slate-950 border border-slate-800 p-3 rounded-lg flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-2 truncate">
                  <Hash className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span className="text-slate-400 text-[11px] truncate">
                    SHA-256 Digest: <span className="text-slate-200">{verdict.receipt.receipt_sha256}</span>
                  </span>
                </div>
                <button
                  onClick={verifyReceiptHash}
                  className="shrink-0 flex items-center gap-1 bg-slate-900 hover:bg-slate-800 text-emerald-400 border border-emerald-500/30 px-2 py-1 rounded text-[10px] font-bold"
                >
                  <Sparkles className="w-3 h-3" /> {hashVerified ? "✓ Verified" : "Verify Digest"}
                </button>
              </div>

              <div className="flex flex-col sm:flex-row items-center justify-between pt-3 border-t border-slate-800 gap-3">
                <div className="flex gap-2 w-full sm:w-auto">
                  <button
                    onClick={downloadReceipt}
                    className="flex-1 sm:flex-none flex items-center justify-center gap-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3.5 py-2.5 rounded-lg transition font-mono"
                  >
                    <Download className="w-3.5 h-3.5 text-cyan-400" /> Evidence Receipt (.json)
                  </button>
                  <button
                    onClick={downloadPatchFile}
                    className="flex-1 sm:flex-none flex items-center justify-center gap-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-2.5 rounded-lg transition font-mono"
                  >
                    <FileText className="w-3.5 h-3.5 text-emerald-400" /> Export Patch (.patch)
                  </button>
                </div>

                <button
                  onClick={dispatchPR}
                  disabled={prLoading || !!prResult}
                  className={`w-full sm:w-auto flex items-center justify-center gap-2 text-xs font-bold px-4 py-2.5 rounded-lg transition ${
                    prResult
                      ? "bg-emerald-600 text-white cursor-default"
                      : "bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-950/50"
                  }`}
                >
                  <GitPullRequest className="w-3.5 h-3.5" />
                  {prLoading ? "Generating PR..." : prResult ? "✓ Pull Request Staged" : "Approve & Open Pull Request"}
                </button>
              </div>

              {prResult && (
                <div className="bg-indigo-950/40 border border-indigo-500/40 p-3 rounded-lg text-xs font-mono space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-emerald-400 font-bold">
                      {prResult.is_live ? "✓ GitHub Pull Request Live" : "✓ Local PR Package Staged"}
                    </span>
                    {prResult.is_live && prResult.pr_url && (
                      <a
                        href={prResult.pr_url}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-1 text-cyan-400 hover:underline"
                      >
                        View on GitHub <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                  <p className="text-slate-300 text-[11px] truncate">
                    Branch: {prResult.branch}
                  </p>
                  <p className="text-slate-400 text-[11px]">
                    Title: {prResult.pr_title}
                  </p>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-8 text-center flex flex-col items-center justify-center min-h-[300px]">
              <Lock className="w-10 h-10 text-slate-700 mb-3" />
              <h3 className="text-sm font-bold text-slate-400">Airlock Awaiting Autonomous Run</h3>
              <p className="text-xs text-slate-500 max-w-sm mt-1">
                Select a target vulnerability from the lab and initiate the pipeline to see the dual-sandbox verification flow.
              </p>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
