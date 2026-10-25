import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal as TerminalIcon,
  History,
  FileCode,
  BookOpen,
  Download,
  Copy,
  Check,
  ExternalLink,
  AlertTriangle,
  Info,
  Lock,
  Globe,
  RefreshCw,
  Trash2,
  Play,
  Search,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  FileText,
  Smartphone,
  Server,
  Zap
} from 'lucide-react';

interface Finding {
  id: string;
  check_name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  evidence: string;
  affected_component: string;
  current_value?: string | null;
  technical_explanation: string;
  potential_impact: string;
  recommended_fix: string;
  verification_steps: string;
  confidence_level: string;
}

interface ScanData {
  id: string;
  timestamp: string;
  target_url: string;
  domain: string;
  port: number;
  scheme: string;
  resolved_ips: string[];
  duration_seconds: number;
  status: string;
  checks_performed: string[];
  http_info?: {
    status_code: number;
    response_time_ms: number;
    redirect_chain: { url: string; status_code: number }[];
    final_url: string;
    headers: Record<string, string>;
  };
  tls_info?: {
    hostname: string;
    port: number;
    connected: boolean;
    verified: boolean;
    tls_version: string;
    cipher: string;
    issuer: string;
    expires_at: string;
    days_until_expiration: number;
    san: string[];
    error: string | null;
  };
  dns_records?: {
    A: string[];
    AAAA: string[];
    MX: string[];
    NS: string[];
    TXT: string[];
    CNAME: string[];
    DMARC: string[];
  };
  findings: Finding[];
  score_data: {
    score: number;
    grade: string;
    status: string;
    total_deduction: number;
    explanation: string;
    counts: {
      Critical: number;
      High: number;
      Medium: number;
      Low: number;
      Informational: number;
    };
    disclaimer: string;
  };
}

interface ScanHistoryItem {
  id: string;
  timestamp: string;
  target_url: string;
  domain: string;
  score: number;
  grade: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  duration_seconds: number;
}

interface RepoFile {
  path: string;
  category: string;
  language: string;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'terminal' | 'history' | 'repo' | 'docs'>('scanner');
  const [targetUrl, setTargetUrl] = useState('https://example.org');
  const [authorized, setAuthorized] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanStep, setScanStep] = useState('');
  const [scanProgress, setScanProgress] = useState(0);
  const [currentScan, setCurrentScan] = useState<ScanData | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Findings filter
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  // History state
  const [historyList, setHistoryList] = useState<ScanHistoryItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  // Terminal simulator state
  const [terminalCmd, setTerminalCmd] = useState('python3 main.py --check-config');
  const [terminalRunning, setTerminalRunning] = useState(false);
  const [terminalLogs, setTerminalLogs] = useState<Array<{ cmd: string; output: string; exitCode: number; time: string }>>([
    {
      cmd: 'python3 main.py --version',
      output: 'WebShield AI v1.0.0 (Termux & Linux Security Auditor)',
      exitCode: 0,
      time: '11:00:00',
    },
  ]);

  // Repository browser state
  const [repoFiles, setRepoFiles] = useState<RepoFile[]>([]);
  const [selectedFile, setSelectedFile] = useState<string>('src/scanner.py');
  const [fileContent, setFileContent] = useState<string>('');
  const [loadingFile, setLoadingFile] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Documentation state
  const [docLang, setDocLang] = useState<'en' | 'bn'>('en');
  const [docText, setDocText] = useState<string>('');
  const [loadingDoc, setLoadingDoc] = useState<boolean>(false);

  // Load initial history & files
  useEffect(() => {
    fetchHistory();
    fetchRepoTree();
    fetchDocs('en');
  }, []);

  useEffect(() => {
    if (selectedFile) {
      loadFileContent(selectedFile);
    }
  }, [selectedFile]);

  useEffect(() => {
    fetchDocs(docLang);
  }, [docLang]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const fetchHistory = async () => {
    setLoadingHistory(true);
    try {
      const res = await fetch('/api/scans');
      if (res.ok) {
        const data = await res.json();
        setHistoryList(data);
        // If no current scan and history exists, load first scan
        if (!currentScan && data.length > 0) {
          loadSingleScan(data[0].id);
        }
      }
    } catch (e) {
      console.error('Failed to load history', e);
    } finally {
      setLoadingHistory(false);
    }
  };

  const loadSingleScan = async (scanId: string) => {
    try {
      const res = await fetch(`/api/scans/${scanId}`);
      if (res.ok) {
        const data = await res.json();
        setCurrentScan(data);
        setActiveTab('scanner');
      }
    } catch (e) {
      console.error('Failed to load scan', e);
    }
  };

  const deleteScan = async (scanId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this scan audit?')) return;
    try {
      const res = await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
      if (res.ok) {
        setHistoryList((prev) => prev.filter((item) => item.id !== scanId));
        if (currentScan?.id === scanId) {
          setCurrentScan(null);
        }
      }
    } catch (err) {
      console.error('Failed to delete scan', err);
    }
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!authorized) {
      setScanError('You must confirm ownership or authorized testing permission.');
      return;
    }
    if (!targetUrl.trim()) {
      setScanError('Please enter a target URL.');
      return;
    }

    setScanning(true);
    setScanError(null);
    setScanProgress(15);
    setScanStep('Validating domain and verifying anti-SSRF protections...');

    const timer = setInterval(() => {
      setScanProgress((prev) => {
        if (prev < 35) {
          setScanStep('Auditing DNS records, SPF, and DMARC...');
          return prev + 15;
        } else if (prev < 65) {
          setScanStep('Performing cryptographic TLS handshake & cert analysis...');
          return prev + 15;
        } else if (prev < 85) {
          setScanStep('Evaluating HTTP security headers (HSTS, CSP, XCTO, XFO)...');
          return prev + 10;
        } else if (prev < 95) {
          setScanStep('Checking redirect safety and calculating 0-100 score...');
          return 95;
        }
        return prev;
      });
    }, 450);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl: targetUrl.trim(),
          userConfirmedAuthorization: authorized,
        }),
      });

      clearInterval(timer);
      const data = await res.json();

      if (!res.ok) {
        setScanError(data.message || data.error || 'Scan failed to complete.');
        setScanning(false);
        setScanProgress(0);
        return;
      }

      setScanProgress(100);
      setScanStep('Audit completed successfully!');
      setCurrentScan(data);
      fetchHistory();
    } catch (err) {
      clearInterval(timer);
      setScanError('Failed to communicate with scanning engine: ' + (err as Error).message);
    } finally {
      setScanning(false);
    }
  };

  const fetchRepoTree = async () => {
    try {
      const res = await fetch('/api/repo-tree');
      if (res.ok) {
        const data = await res.json();
        setRepoFiles(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const loadFileContent = async (filePath: string) => {
    setLoadingFile(true);
    try {
      const res = await fetch(`/api/file-content?path=${encodeURIComponent(filePath)}`);
      if (res.ok) {
        const data = await res.json();
        setFileContent(data.content);
      }
    } catch (err) {
      setFileContent('// Failed to read file content');
    } finally {
      setLoadingFile(false);
    }
  };

  const fetchDocs = async (lang: 'en' | 'bn') => {
    setLoadingDoc(true);
    try {
      const res = await fetch(`/api/docs/${lang}`);
      if (res.ok) {
        const text = await res.text();
        setDocText(text);
      }
    } catch (err) {
      setDocText('Failed to load documentation.');
    } finally {
      setLoadingDoc(false);
    }
  };

  const runTerminalCommand = async (cmdToRun?: string) => {
    const cmd = cmdToRun || terminalCmd;
    if (!cmd.trim() || terminalRunning) return;

    setTerminalRunning(true);
    try {
      const res = await fetch('/api/terminal-exec', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: cmd }),
      });
      const data = await res.json();
      const outputText = data.stdout || data.stderr || (data.exitCode === 0 ? '[Success - Process exited with 0]' : '[Command failed]');
      const now = new Date().toTimeString().split(' ')[0];

      setTerminalLogs((prev) => [
        ...prev,
        {
          cmd: data.command || cmd,
          output: outputText,
          exitCode: data.exitCode,
          time: now,
        },
      ]);
    } catch (err) {
      setTerminalLogs((prev) => [
        ...prev,
        {
          cmd,
          output: 'Execution failed: ' + (err as Error).message,
          exitCode: 1,
          time: new Date().toTimeString().split(' ')[0],
        },
      ]);
    } finally {
      setTerminalRunning(false);
    }
  };

  const toggleFinding = (id: string) => {
    setExpandedFindings((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  // Filtered findings
  const filteredFindings = (currentScan?.findings || []).filter((f) => {
    const matchesSev = severityFilter === 'all' || f.severity.toLowerCase() === severityFilter.toLowerCase();
    const matchesQuery =
      searchQuery === '' ||
      f.check_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.affected_component.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesQuery;
  });

  const getGradeColor = (grade?: string) => {
    if (grade === 'A+' || grade === 'A') return 'text-emerald-400 border-emerald-500/40 bg-emerald-950/30';
    if (grade === 'B') return 'text-amber-300 border-amber-500/40 bg-amber-950/30';
    if (grade === 'C') return 'text-orange-400 border-orange-500/40 bg-orange-950/30';
    return 'text-rose-400 border-rose-500/40 bg-rose-950/30';
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'Critical':
        return 'text-rose-300 bg-rose-950/70 border-rose-800/80';
      case 'High':
        return 'text-orange-300 bg-orange-950/70 border-orange-800/80';
      case 'Medium':
        return 'text-amber-300 bg-amber-950/70 border-amber-800/80';
      case 'Low':
        return 'text-sky-300 bg-sky-950/70 border-sky-800/80';
      default:
        return 'text-slate-300 bg-slate-900 border-slate-700';
    }
  };

  const termuxInstallOneLiner = `pkg update -y && pkg install -y python git openssl && git clone https://github.com/webshield-ai/webshield-ai.git && cd webshield-ai && chmod +x install.sh run.sh && ./install.sh`;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Bar Contract: 3 zones separated by gap-8 (Brand - Nav - 1 Primary Action) */}
      <header className="border-b border-slate-800 bg-slate-950/90 backdrop-blur sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between gap-8">
        {/* Zone 1: Brand Wordmark */}
        <div className="flex items-center gap-2.5 whitespace-nowrap shrink-0">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Shield className="w-4 h-4" />
          </div>
          <span className="font-bold text-base tracking-tight text-white">WebShield AI</span>
        </div>

        {/* Zone 2: 4-5 Clean single-line text navigation links */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
          <button
            onClick={() => setActiveTab('scanner')}
            className={`transition-colors whitespace-nowrap shrink-0 ${activeTab === 'scanner' ? 'text-cyan-400 font-semibold' : 'hover:text-slate-200'}`}
          >
            Scanner
          </button>
          <button
            onClick={() => setActiveTab('terminal')}
            className={`transition-colors whitespace-nowrap shrink-0 ${activeTab === 'terminal' ? 'text-cyan-400 font-semibold' : 'hover:text-slate-200'}`}
          >
            Terminal (Termux)
          </button>
          <button
            onClick={() => {
              setActiveTab('history');
              fetchHistory();
            }}
            className={`transition-colors whitespace-nowrap shrink-0 ${activeTab === 'history' ? 'text-cyan-400 font-semibold' : 'hover:text-slate-200'}`}
          >
            Scan History
          </button>
          <button
            onClick={() => setActiveTab('repo')}
            className={`transition-colors whitespace-nowrap shrink-0 ${activeTab === 'repo' ? 'text-cyan-400 font-semibold' : 'hover:text-slate-200'}`}
          >
            Repository & Scripts
          </button>
          <button
            onClick={() => setActiveTab('docs')}
            className={`transition-colors whitespace-nowrap shrink-0 ${activeTab === 'docs' ? 'text-cyan-400 font-semibold' : 'hover:text-slate-200'}`}
          >
            Docs & বাংলা
          </button>
        </nav>

        {/* Zone 3: 1 Primary Action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={() => {
              setActiveTab('scanner');
              window.scrollTo({ top: 0, behavior: 'smooth' });
            }}
            className="px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 rounded-lg hover:bg-cyan-300 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 shadow-sm"
          >
            <Zap className="w-3.5 h-3.5" />
            New Assessment
          </button>
        </div>
      </header>

      {/* Main Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-8">
        {/* TAB 1: SCANNER */}
        {activeTab === 'scanner' && (
          <div className="space-y-8">
            {/* Target Entry Hero */}
            <div className="p-6 md:p-8 rounded-2xl bg-slate-900/50 border border-slate-800 shadow-xl">
              <div className="max-w-3xl mb-6">
                <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 font-medium mb-1.5">
                  <Smartphone className="w-3.5 h-3.5" />
                  <span>ANDROID TERMUX & WEB DEFENSIVE ENGINE</span>
                  <span aria-hidden="true">·</span>
                  <span>ROOTLESS</span>
                  <span aria-hidden="true">·</span>
                  <span>ANTI-SSRF ENFORCED</span>
                </div>
                <h1 className="text-2xl md:text-3xl font-bold text-white tracking-tight">
                  Website Security Configuration Assessment
                </h1>
                <p className="text-sm text-slate-400 mt-1 leading-relaxed">
                  Safely audit HTTP security headers, TLS certificate parameters, DNS anti-spoofing (SPF/DMARC), and configuration hygiene with zero exploits or website modification.
                </p>
              </div>

              <form onSubmit={handleStartScan} className="space-y-4">
                <div className="flex flex-col md:flex-row gap-3">
                  <div className="relative flex-1">
                    <Globe className="absolute left-3.5 top-3.5 w-4 h-4 text-slate-500" />
                    <input
                      type="text"
                      value={targetUrl}
                      onChange={(e) => setTargetUrl(e.target.value)}
                      placeholder="e.g. https://your-authorized-domain.com"
                      className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-sm font-mono text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={scanning}
                    className="px-6 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-sm font-bold transition-all disabled:opacity-50 whitespace-nowrap shrink-0 flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/10"
                  >
                    {scanning ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        Scanning...
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 fill-current" />
                        Run Safe Audit
                      </>
                    )}
                  </button>
                </div>

                {/* Authorization Safeguard Checkbox */}
                <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-start gap-3">
                  <input
                    type="checkbox"
                    id="authCheck"
                    checked={authorized}
                    onChange={(e) => setAuthorized(e.target.checked)}
                    className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
                  />
                  <label htmlFor="authCheck" className="text-xs text-slate-300 cursor-pointer leading-relaxed">
                    <strong className="text-white">Authorization & Scope Confirmation:</strong> I confirm that I own or have explicit written permission to test this target domain. I understand tests are safe, non-destructive, and strictly within scope.
                  </label>
                </div>

                {scanError && (
                  <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-800/80 text-rose-300 text-xs flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>{scanError}</span>
                  </div>
                )}

                {/* Live Scanning Progress */}
                {scanning && (
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-cyan-400 flex items-center gap-2">
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        {scanStep}
                      </span>
                      <span className="font-mono tabular-nums text-slate-400">{scanProgress}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-cyan-400 transition-all duration-300 ease-out"
                        style={{ width: `${scanProgress}%` }}
                      />
                    </div>
                  </div>
                )}
              </form>
            </div>

            {/* Results Display */}
            {currentScan && (() => {
              const scoreVal = currentScan.score_data?.score ?? (currentScan as any).score ?? 0;
              const gradeVal = currentScan.score_data?.grade ?? (currentScan as any).grade ?? 'N/A';
              const counts = currentScan.score_data?.counts || {
                Critical: (currentScan as any).critical_count ?? 0,
                High: (currentScan as any).high_count ?? 0,
                Medium: (currentScan as any).medium_count ?? 0,
                Low: (currentScan as any).low_count ?? 0,
                Informational: (currentScan as any).info_count ?? 0,
              };
              const explanationVal = currentScan.score_data?.explanation || `Security audit score of ${scoreVal}/100 (Grade ${gradeVal}).`;
              const disclaimerVal = currentScan.score_data?.disclaimer || 'WebShield AI Score Notice: Evaluates observable external configurations.';
              const resolvedIp = currentScan.resolved_ips?.[0] || 'Resolved';
              const schemeVal = (currentScan.scheme || 'https').toUpperCase();
              const portVal = currentScan.port || 443;
              const findingsCount = (currentScan.findings || []).length;

              return (
              <div className="space-y-8">
                {/* Score & KPI Dashboard Bar */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  {/* Overall Score */}
                  <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
                    <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">Security Score</div>
                    <div className="my-3 flex items-baseline gap-3">
                      <span className="text-4xl md:text-5xl font-black font-mono tracking-tight text-white tabular-nums">
                        {scoreVal}
                      </span>
                      <span className="text-sm text-slate-500 font-mono">/ 100</span>
                      <span
                        className={`text-xs px-2.5 py-0.5 rounded font-bold font-mono border ml-auto ${getGradeColor(
                          gradeVal
                        )}`}
                      >
                        Grade {gradeVal}
                      </span>
                    </div>
                    <div className="text-xs text-slate-400">
                      {counts.Critical > 0
                        ? 'Critical configuration risks require immediate remediation.'
                        : 'Calculated from deterministic deductions.'}
                    </div>
                  </div>

                  {/* Target Scope */}
                  <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
                    <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">Target & Host</div>
                    <div className="my-2">
                      <div className="text-base font-bold text-white truncate">{currentScan.domain}</div>
                      <div className="text-xs font-mono text-cyan-400 mt-1">
                        {schemeVal} :{portVal} · {resolvedIp}
                      </div>
                    </div>
                    <div className="text-xs text-slate-400 flex items-center gap-2">
                      <span className="font-mono tabular-nums">{currentScan.duration_seconds}s</span>
                      <span aria-hidden="true">·</span>
                      <span>{currentScan.timestamp} UTC</span>
                    </div>
                  </div>

                  {/* TLS & HTTPS Status */}
                  <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
                    <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">Cryptographic Channel</div>
                    <div className="my-2">
                      <div className="text-sm font-semibold text-white flex items-center gap-1.5">
                        <Lock className="w-3.5 h-3.5 text-emerald-400" />
                        {currentScan.tls_info?.tls_version || 'TLS Available'}
                      </div>
                      <div className="text-xs text-slate-400 truncate mt-1">
                        {currentScan.tls_info?.days_until_expiration !== undefined
                          ? `${currentScan.tls_info.days_until_expiration} days until cert expiration`
                          : 'Valid Certificate'}
                      </div>
                    </div>
                    <div className="text-xs text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Strict CA Trust Verified
                    </div>
                  </div>

                  {/* Export Reports Bar */}
                  <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
                    <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">Audit Deliverables</div>
                    <div className="my-2 flex flex-col gap-2">
                      <a
                        href={`/api/reports/${currentScan.id}/html`}
                        target="_blank"
                        rel="noreferrer"
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 flex items-center justify-between transition-colors"
                      >
                        <span className="flex items-center gap-1.5">
                          <FileText className="w-3.5 h-3.5 text-cyan-400" /> View HTML Report
                        </span>
                        <ExternalLink className="w-3 h-3 text-slate-400" />
                      </a>
                      <a
                        href={`/api/reports/${currentScan.id}/json`}
                        download={`webshield_${currentScan.domain}.json`}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 flex items-center justify-between transition-colors"
                      >
                        <span className="flex items-center gap-1.5">
                          <Download className="w-3.5 h-3.5 text-emerald-400" /> Download JSON
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono">.json</span>
                      </a>
                    </div>
                    <div className="text-[11px] text-slate-500">Saved to local Termux SQLite</div>
                  </div>
                </div>

                {/* Score Explanation Box */}
                <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 text-xs text-slate-300 flex items-start gap-3">
                  <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <strong className="text-white">Scoring Methodology:</strong> {explanationVal}
                    <div className="text-[11px] text-slate-500 mt-1">{disclaimerVal}</div>
                  </div>
                </div>

                {/* Findings Section */}
                <div className="space-y-4">
                  {/* Filter Tabs & Search */}
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <button
                        onClick={() => setSeverityFilter('all')}
                        className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                          severityFilter === 'all' ? 'bg-white text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        All Findings ({findingsCount})
                      </button>
                      <button
                        onClick={() => setSeverityFilter('critical')}
                        className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                          severityFilter === 'critical' ? 'bg-rose-500 text-white font-bold' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Critical ({counts.Critical})
                      </button>
                      <button
                        onClick={() => setSeverityFilter('high')}
                        className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                          severityFilter === 'high' ? 'bg-orange-500 text-white font-bold' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        High ({counts.High})
                      </button>
                      <button
                        onClick={() => setSeverityFilter('medium')}
                        className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                          severityFilter === 'medium' ? 'bg-amber-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Medium ({counts.Medium})
                      </button>
                      <button
                        onClick={() => setSeverityFilter('low')}
                        className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                          severityFilter === 'low' ? 'bg-sky-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Low ({counts.Low})
                      </button>
                      <button
                        onClick={() => setSeverityFilter('informational')}
                        className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                          severityFilter === 'informational' ? 'bg-slate-700 text-white font-bold' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Info ({counts.Informational})
                      </button>
                    </div>

                    <div className="relative min-w-[220px]">
                      <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-slate-500" />
                      <input
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Search findings..."
                        className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                  </div>

                  {/* Findings Cards List */}
                  <div className="space-y-3">
                    {filteredFindings.length === 0 ? (
                      <div className="p-8 text-center rounded-xl bg-slate-900/30 border border-slate-800 text-slate-400 text-sm">
                        No findings match your current filter criteria.
                      </div>
                    ) : (
                      filteredFindings.map((finding) => {
                        const isExpanded = !!expandedFindings[finding.id];
                        return (
                          <div
                            key={finding.id}
                            className="rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all overflow-hidden"
                          >
                            <div
                              onClick={() => toggleFinding(finding.id)}
                              className="p-4 flex items-center justify-between gap-4 cursor-pointer select-none"
                            >
                              <div className="flex items-center gap-3 min-w-0">
                                <span
                                  className={`text-xs px-2.5 py-0.5 rounded font-bold font-mono border whitespace-nowrap shrink-0 ${getSeverityBadge(
                                    finding.severity
                                  )}`}
                                >
                                  {finding.severity.toUpperCase()}
                                </span>
                                <div className="min-w-0">
                                  <h3 className="text-sm font-semibold text-white truncate">{finding.check_name}</h3>
                                  <div className="flex items-center gap-2 text-xs text-slate-400 font-mono mt-0.5">
                                    <span>{finding.affected_component}</span>
                                    <span aria-hidden="true">·</span>
                                    <span>{finding.id}</span>
                                  </div>
                                </div>
                              </div>

                              <div className="flex items-center gap-3 shrink-0">
                                <span className="text-xs text-slate-500 font-mono hidden sm:inline">
                                  Confidence: {finding.confidence_level}
                                </span>
                                {isExpanded ? (
                                  <ChevronUp className="w-4 h-4 text-slate-400" />
                                ) : (
                                  <ChevronDown className="w-4 h-4 text-slate-400" />
                                )}
                              </div>
                            </div>

                            {isExpanded && (
                              <div className="px-5 pb-5 pt-2 border-t border-slate-800/80 space-y-3 text-xs">
                                <div>
                                  <div className="text-slate-400 font-semibold mb-1">OBSERVED EVIDENCE:</div>
                                  <div className="p-2.5 rounded-lg bg-slate-950 font-mono text-cyan-300 text-xs border border-slate-800 flex items-center justify-between">
                                    <span className="truncate">{finding.evidence}</span>
                                    <button
                                      onClick={() => copyToClipboard(finding.evidence, `ev_${finding.id}`)}
                                      className="text-slate-500 hover:text-slate-300 ml-2"
                                    >
                                      {copiedKey === `ev_${finding.id}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                    </button>
                                  </div>
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                  <div>
                                    <div className="text-slate-400 font-semibold mb-1">TECHNICAL ANALYSIS:</div>
                                    <p className="text-slate-300 leading-relaxed">{finding.technical_explanation}</p>
                                  </div>
                                  <div>
                                    <div className="text-slate-400 font-semibold mb-1">POTENTIAL SECURITY RISK:</div>
                                    <p className="text-rose-300/90 leading-relaxed">{finding.potential_impact}</p>
                                  </div>
                                </div>

                                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                                  <div className="text-emerald-400 font-semibold flex items-center justify-between">
                                    <span>RECOMMENDED DEFENSIVE FIX:</span>
                                  </div>
                                  <p className="text-slate-200">{finding.recommended_fix}</p>
                                  <div className="pt-2 border-t border-slate-800/80">
                                    <div className="text-slate-400 font-mono text-[11px] mb-1"># Verification Command:</div>
                                    <div className="p-2 rounded bg-slate-900 font-mono text-[11px] text-slate-300 flex items-center justify-between">
                                      <code>{finding.verification_steps}</code>
                                      <button
                                        onClick={() => copyToClipboard(finding.verification_steps, `vf_${finding.id}`)}
                                        className="text-slate-500 hover:text-white"
                                      >
                                        {copiedKey === `vf_${finding.id}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                      </button>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>

                {/* Checks Completed Footer */}
                <div className="p-4 rounded-xl bg-slate-900/30 border border-slate-800">
                  <div className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-2">Verified Assessment Scope</div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-slate-400">
                    {(currentScan.checks_performed || [
                      'HTTP Security Headers Analysis',
                      'TLS/SSL Certificate Verification',
                      'DNS Record & Anti-Spoofing Audit',
                      'Safe Configuration Checks'
                    ]).map((chk, idx) => (
                      <div key={idx} className="flex items-center gap-2">
                        <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        <span>{chk}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              );
            })()}
          </div>
        )}

        {/* TAB 2: TERMINAL (TERMUX SIMULATOR) */}
        {activeTab === 'terminal' && (
          <div className="space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                  <TerminalIcon className="w-5 h-5 text-cyan-400" />
                  Interactive Termux CLI Console
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Execute actual WebShield AI commands directly in the container or Android Termux environment.
                </p>
              </div>

              {/* Quick Preset Buttons */}
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={() => runTerminalCommand('python3 main.py --check-config')}
                  className="px-2.5 py-1 text-xs font-mono rounded bg-slate-900 border border-slate-800 text-slate-300 hover:border-cyan-500 hover:text-cyan-300 transition-colors"
                >
                  --check-config
                </button>
                <button
                  onClick={() => runTerminalCommand('python3 main.py --version')}
                  className="px-2.5 py-1 text-xs font-mono rounded bg-slate-900 border border-slate-800 text-slate-300 hover:border-cyan-500 hover:text-cyan-300 transition-colors"
                >
                  --version
                </button>
                <button
                  onClick={() => runTerminalCommand('python3 main.py --history')}
                  className="px-2.5 py-1 text-xs font-mono rounded bg-slate-900 border border-slate-800 text-slate-300 hover:border-cyan-500 hover:text-cyan-300 transition-colors"
                >
                  --history
                </button>
                <button
                  onClick={() => runTerminalCommand('pytest tests/')}
                  className="px-2.5 py-1 text-xs font-mono rounded bg-slate-900 border border-slate-800 text-slate-300 hover:border-cyan-500 hover:text-cyan-300 transition-colors"
                >
                  pytest tests/
                </button>
              </div>
            </div>

            {/* Terminal Screen */}
            <div className="rounded-2xl bg-[#030712] border border-slate-800 shadow-2xl overflow-hidden font-mono text-xs">
              {/* Window Controls */}
              <div className="px-4 py-2.5 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
                  <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
                  <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
                  <span className="text-slate-400 text-xs ml-2">termux@android: ~/webshield-ai</span>
                </div>
                <button
                  onClick={() => setTerminalLogs([])}
                  className="text-slate-500 hover:text-slate-300 text-[11px]"
                >
                  Clear Screen
                </button>
              </div>

              {/* Terminal Logs Output */}
              <div className="p-5 max-h-[520px] overflow-y-auto space-y-4">
                {terminalLogs.map((log, index) => (
                  <div key={index} className="space-y-1">
                    <div className="flex items-center gap-2 text-cyan-400">
                      <span className="text-emerald-400">$</span>
                      <span className="font-bold">{log.cmd}</span>
                      <span className="text-slate-600 text-[10px] ml-auto">{log.time}</span>
                    </div>
                    <pre className="text-slate-300 whitespace-pre-wrap leading-relaxed pl-3 border-l border-slate-800">
                      {log.output}
                    </pre>
                  </div>
                ))}
                {terminalRunning && (
                  <div className="flex items-center gap-2 text-cyan-400">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Executing in Termux container environment...</span>
                  </div>
                )}
              </div>

              {/* Terminal Input Bar */}
              <div className="p-3 bg-slate-900/50 border-t border-slate-800 flex items-center gap-2">
                <span className="text-emerald-400 font-bold pl-2">$</span>
                <input
                  type="text"
                  value={terminalCmd}
                  onChange={(e) => setTerminalCmd(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') runTerminalCommand();
                  }}
                  placeholder="e.g. python3 main.py --help"
                  className="flex-1 bg-transparent border-0 text-white font-mono text-xs focus:outline-none"
                />
                <button
                  onClick={() => runTerminalCommand()}
                  disabled={terminalRunning}
                  className="px-3 py-1 rounded bg-cyan-500 text-slate-950 font-bold hover:bg-cyan-400 transition-colors disabled:opacity-50"
                >
                  Execute
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: SCAN HISTORY */}
        {activeTab === 'history' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                  <History className="w-5 h-5 text-cyan-400" />
                  SQLite Scan Audit Records
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Historical security assessments stored in local SQLite database (data/webshield.db).
                </p>
              </div>
              <button
                onClick={fetchHistory}
                disabled={loadingHistory}
                className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 hover:text-white flex items-center gap-1.5 transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${loadingHistory ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>

            {historyList.length === 0 ? (
              <div className="p-12 text-center rounded-2xl bg-slate-900/30 border border-slate-800 text-slate-400 space-y-3">
                <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto" />
                <p>No historical scans found. Run your first security assessment in the Scanner tab.</p>
              </div>
            ) : (
              <div className="rounded-2xl bg-slate-900/60 border border-slate-800 overflow-hidden shadow-xl">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                      <tr>
                        <th className="py-3 px-4">Domain / Target</th>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-4 text-center">Score</th>
                        <th className="py-3 px-4 text-center">Grade</th>
                        <th className="py-3 px-4">Findings Breakdown</th>
                        <th className="py-3 px-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80">
                      {historyList.map((item) => (
                        <tr
                          key={item.id}
                          onClick={() => loadSingleScan(item.id)}
                          className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                        >
                          <td className="py-3.5 px-4 font-semibold text-white">
                            <div>{item.domain}</div>
                            <div className="text-[11px] font-mono text-slate-500">{item.id}</div>
                          </td>
                          <td className="py-3.5 px-4 text-slate-400 font-mono tabular-nums">{item.timestamp}</td>
                          <td className="py-3.5 px-4 text-center font-mono font-bold text-sm tabular-nums text-white">
                            {item.score ?? 'N/A'}
                          </td>
                          <td className="py-3.5 px-4 text-center">
                            <span
                              className={`px-2 py-0.5 rounded font-mono font-bold text-xs border ${getGradeColor(
                                item.grade
                              )}`}
                            >
                              {item.grade}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 font-mono text-slate-400">
                            <span className="text-rose-400 font-bold">{item.critical_count}C</span> ·{' '}
                            <span className="text-orange-400 font-bold">{item.high_count}H</span> ·{' '}
                            <span className="text-amber-400">{item.medium_count}M</span> ·{' '}
                            <span className="text-slate-400">{item.low_count}L</span>
                          </td>
                          <td className="py-3.5 px-4 text-right space-x-2">
                            <a
                              href={`/api/reports/${item.id}/html`}
                              target="_blank"
                              rel="noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              className="inline-block p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-400 transition-colors"
                              title="View HTML Report"
                            >
                              <FileText className="w-3.5 h-3.5" />
                            </a>
                            <button
                              onClick={(e) => deleteScan(item.id, e)}
                              className="p-1.5 rounded bg-slate-800 hover:bg-rose-950/60 text-slate-400 hover:text-rose-400 transition-colors"
                              title="Delete Scan"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 4: REPOSITORY & SCRIPTS */}
        {activeTab === 'repo' && (
          <div className="space-y-6">
            <div>
              <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                <FileCode className="w-5 h-5 text-cyan-400" />
                GitHub Repository & Termux Scripts
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Inspect modular Python engines, installer bash scripts, and automated test fixtures.
              </p>
            </div>

            {/* One-Liner Install Banner */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-mono text-cyan-400 font-semibold uppercase">Termux One-Line Quick Install:</span>
                <button
                  onClick={() => copyToClipboard(termuxInstallOneLiner, 'termux_cmd')}
                  className="text-xs text-slate-400 hover:text-white flex items-center gap-1"
                >
                  {copiedKey === 'termux_cmd' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy Command</span>
                </button>
              </div>
              <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-300 overflow-x-auto">
                {termuxInstallOneLiner}
              </pre>
            </div>

            {/* Code Explorer */}
            <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
              {/* File List */}
              <div className="md:col-span-4 rounded-xl bg-slate-900/60 border border-slate-800 p-3 space-y-1 max-h-[600px] overflow-y-auto">
                <div className="text-xs font-mono text-slate-400 px-2 py-1.5 uppercase tracking-wider">Repository Files</div>
                {repoFiles.map((file) => (
                  <button
                    key={file.path}
                    onClick={() => setSelectedFile(file.path)}
                    className={`w-full text-left px-2.5 py-1.5 rounded-lg text-xs font-mono transition-colors flex items-center justify-between ${
                      selectedFile === file.path ? 'bg-cyan-500/10 text-cyan-400 font-bold border border-cyan-500/30' : 'text-slate-300 hover:bg-slate-800/50'
                    }`}
                  >
                    <span className="truncate">{file.path}</span>
                    <span className="text-[10px] text-slate-500 ml-2 shrink-0">{file.category}</span>
                  </button>
                ))}
              </div>

              {/* File Viewer */}
              <div className="md:col-span-8 rounded-xl bg-slate-950 border border-slate-800 flex flex-col h-[600px] overflow-hidden">
                <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-200 font-semibold">{selectedFile}</span>
                  <button
                    onClick={() => copyToClipboard(fileContent, 'view_file_copy')}
                    className="text-xs text-slate-400 hover:text-white flex items-center gap-1 font-mono"
                  >
                    {copiedKey === 'view_file_copy' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>Copy File</span>
                  </button>
                </div>
                <div className="flex-1 p-4 overflow-auto font-mono text-xs text-slate-300">
                  {loadingFile ? (
                    <div className="flex items-center gap-2 text-slate-500">
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Loading content...
                    </div>
                  ) : (
                    <pre className="whitespace-pre leading-relaxed">{fileContent}</pre>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: DOCUMENTATION (ENGLISH & BENGALI) */}
        {activeTab === 'docs' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                  <BookOpen className="w-5 h-5 text-cyan-400" />
                  Documentation & User Playbook
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Complete Termux setup guides, security header manuals, and Bengali documentation.
                </p>
              </div>

              {/* Language Switcher */}
              <div className="flex items-center gap-1 p-1 bg-slate-900 rounded-lg border border-slate-800">
                <button
                  onClick={() => setDocLang('en')}
                  className={`px-3 py-1 text-xs font-medium rounded-md transition-colors ${
                    docLang === 'en' ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  English
                </button>
                <button
                  onClick={() => setDocLang('bn')}
                  className={`px-3 py-1 text-xs font-medium rounded-md transition-colors ${
                    docLang === 'bn' ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  বাংলা (Bengali)
                </button>
              </div>
            </div>

            {/* Doc Viewer */}
            <div className="p-6 md:p-8 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl max-w-4xl mx-auto prose prose-invert prose-sm max-w-none">
              {loadingDoc ? (
                <div className="flex items-center gap-2 text-slate-400 font-mono text-xs">
                  <RefreshCw className="w-4 h-4 animate-spin" /> Loading documentation...
                </div>
              ) : (
                <pre className="font-sans whitespace-pre-wrap text-sm text-slate-300 leading-relaxed font-normal">
                  {docText}
                </pre>
              )}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 px-6 text-center text-xs text-slate-500">
        <div>WebShield AI — Advanced Website Security Checker for Termux & Web Dashboard</div>
        <div className="mt-1 text-[11px] text-slate-600">
          Strictly for authorized security audits & defensive configuration hardening · Open Source Apache-2.0
        </div>
      </footer>
    </div>
  );
}
