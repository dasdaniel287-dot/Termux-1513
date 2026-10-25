import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { spawn } from 'child_process';
import fs from 'fs';

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json());

// Helper to run python commands safely
function runPythonCommand(args: string[], cwd: string = process.cwd()): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const proc = spawn('python3', args, {
      cwd,
      env: { ...process.env, PYTHONUNBUFFERED: '1' },
    });
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d) => {
      stdout += d.toString();
    });
    proc.stderr.on('data', (d) => {
      stderr += d.toString();
    });

    proc.on('close', (code) => {
      resolve({ stdout, stderr, code: code ?? 0 });
    });

    proc.on('error', (err) => {
      stderr += err.message;
      resolve({ stdout, stderr, code: 1 });
    });
  });
}

// 1. POST /api/scan - Execute live security scan
app.post('/api/scan', async (req, res) => {
  const { targetUrl, userConfirmedAuthorization } = req.body;

  if (!userConfirmedAuthorization) {
    return res.status(400).json({
      error: 'SafetyViolation',
      message: 'Explicit user authorization required before scanning target.',
    });
  }

  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({
      error: 'InvalidTarget',
      message: 'Target URL is required.',
    });
  }

  const { stdout, stderr, code } = await runPythonCommand([
    'main.py',
    '--target',
    targetUrl.trim(),
    '--authorized',
    '--json',
  ]);

  if (code !== 0) {
    try {
      const errJson = JSON.parse(stdout);
      return res.status(400).json(errJson);
    } catch {
      return res.status(500).json({
        error: 'ScanFailed',
        message: stderr || stdout || 'Unknown execution error occurred during scan.',
      });
    }
  }

  try {
    const result = JSON.parse(stdout);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({
      error: 'ParseError',
      message: 'Failed to parse scan output from engine: ' + (err as Error).message,
      rawOutput: stdout,
    });
  }
});

// 2. GET /api/scans - Fetch scan history from SQLite
app.get('/api/scans', async (req, res) => {
  const script = `
import json
from src.database import ScanDatabase
db = ScanDatabase()
print(json.dumps(db.get_all_scans(50)))
`;
  const { stdout, stderr, code } = await runPythonCommand(['-c', script]);
  if (code !== 0) {
    return res.status(500).json({ error: 'DatabaseError', message: stderr });
  }
  try {
    const data = JSON.parse(stdout);
    return res.json(data);
  } catch (err) {
    return res.status(500).json({ error: 'ParseError', message: (err as Error).message });
  }
});

// 3. GET /api/scans/:id - Fetch single scan details
app.get('/api/scans/:id', async (req, res) => {
  const scanId = req.params.id;
  const script = `
import json, sys
from src.database import ScanDatabase
db = ScanDatabase()
print(json.dumps(db.get_scan_by_id(sys.argv[1]) or {}))
`;
  const { stdout, stderr, code } = await runPythonCommand(['-c', script, scanId]);
  if (code !== 0) {
    return res.status(500).json({ error: 'DatabaseError', message: stderr });
  }
  try {
    const data = JSON.parse(stdout);
    if (!data.id) {
      return res.status(404).json({ error: 'NotFound', message: 'Scan record not found.' });
    }
    return res.json(data);
  } catch (err) {
    return res.status(500).json({ error: 'ParseError', message: (err as Error).message });
  }
});

// 4. DELETE /api/scans/:id - Delete scan from history
app.delete('/api/scans/:id', async (req, res) => {
  const scanId = req.params.id;
  const script = `
import json, sys
from src.database import ScanDatabase
db = ScanDatabase()
print(json.dumps({"deleted": db.delete_scan(sys.argv[1])}))
`;
  const { stdout, stderr, code } = await runPythonCommand(['-c', script, scanId]);
  if (code !== 0) {
    return res.status(500).json({ error: 'DatabaseError', message: stderr });
  }
  try {
    return res.json(JSON.parse(stdout));
  } catch (err) {
    return res.status(500).json({ error: 'ParseError', message: (err as Error).message });
  }
});

// 5. GET /api/reports/:id/:format - View or download report
app.get('/api/reports/:id/:format', async (req, res) => {
  const { id, format } = req.params;
  if (!['html', 'json', 'txt'].includes(format)) {
    return res.status(400).send('Invalid format. Supported: html, json, txt');
  }

  // First check if report file exists in reports/ directory
  const reportsDir = path.resolve('reports');
  const files = fs.existsSync(reportsDir) ? fs.readdirSync(reportsDir) : [];
  const matchingFile = files.find((f) => f.includes(id) && f.endsWith(`.${format}`));

  if (matchingFile) {
    const filePath = path.join(reportsDir, matchingFile);
    if (format === 'html') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
    } else if (format === 'json') {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
    } else {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    }
    return res.sendFile(filePath);
  }

  // If not found as file, regenerate from database scan record
  const script = `
import json, sys
from src.database import ScanDatabase
from src.reports import ReportGenerator
db = ScanDatabase()
scan = db.get_scan_by_id(sys.argv[1])
if not scan:
    print(json.dumps({"error": "not_found"}))
else:
    # construct minimal report payload
    gen = ReportGenerator()
    fmt = sys.argv[2]
    if fmt == 'html':
        print(gen.generate_html(scan))
    elif fmt == 'txt':
        print(gen.generate_txt(scan))
    else:
        print(gen.generate_json(scan))
`;
  const { stdout, stderr, code } = await runPythonCommand(['-c', script, id, format]);
  if (code !== 0 || stdout.includes('{"error": "not_found"}')) {
    return res.status(404).send('Report not found for scan ID ' + id);
  }

  if (format === 'html') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
  } else if (format === 'json') {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
  } else {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  }
  return res.send(stdout);
});

// 6. POST /api/terminal-exec - Termux Terminal CLI simulator
app.post('/api/terminal-exec', async (req, res) => {
  const { command } = req.body;
  if (!command || typeof command !== 'string') {
    return res.status(400).json({ error: 'Command is required' });
  }

  const cleanCmd = command.trim();
  // Safe whitelist of allowed commands for the terminal simulator
  const allowedPrefixes = [
    'python3 main.py',
    'python main.py',
    './run.sh',
    './install.sh',
    'pytest',
    'python3 -m pytest',
    'ls',
    'cat',
  ];

  const isAllowed = allowedPrefixes.some((p) => cleanCmd.startsWith(p));
  if (!isAllowed) {
    return res.status(403).json({
      error: 'RestrictedCommand',
      output: `[Security Guard] Command '${cleanCmd}' not permitted in simulator. Allowed: python3 main.py [args], pytest, ./run.sh, ./install.sh`,
    });
  }

  const startTime = Date.now();
  const proc = spawn('bash', ['-c', cleanCmd], {
    cwd: process.cwd(),
    env: { ...process.env, PYTHONUNBUFFERED: '1', TERM: 'xterm-256color' },
  });

  let stdout = '';
  let stderr = '';

  proc.stdout.on('data', (d) => {
    stdout += d.toString();
  });
  proc.stderr.on('data', (d) => {
    stderr += d.toString();
  });

  proc.on('close', (code) => {
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    return res.json({
      command: cleanCmd,
      stdout,
      stderr,
      exitCode: code ?? 0,
      durationSeconds: duration,
    });
  });

  proc.on('error', (err) => {
    return res.json({
      command: cleanCmd,
      stdout: '',
      stderr: err.message,
      exitCode: 1,
      durationSeconds: '0.00',
    });
  });
});

// 7. GET /api/repo-tree - Inspect GitHub repository files
app.get('/api/repo-tree', (req, res) => {
  const repoFiles = [
    { path: 'main.py', category: 'CLI Entry Point', language: 'python' },
    { path: 'requirements.txt', category: 'Dependencies', language: 'text' },
    { path: 'install.sh', category: 'Termux Installer', language: 'bash' },
    { path: 'run.sh', category: 'Termux Runner', language: 'bash' },
    { path: 'README.md', category: 'Documentation', language: 'markdown' },
    { path: 'src/scanner.py', category: 'Core Engine', language: 'python' },
    { path: 'src/headers.py', category: 'Security Headers', language: 'python' },
    { path: 'src/tls_checker.py', category: 'TLS / SSL', language: 'python' },
    { path: 'src/dns_checker.py', category: 'DNS & SPF/DMARC', language: 'python' },
    { path: 'src/safety.py', category: 'Safety & Anti-SSRF', language: 'python' },
    { path: 'src/scoring.py', category: '0-100 Scoring', language: 'python' },
    { path: 'src/reports.py', category: 'Report Generator', language: 'python' },
    { path: 'src/database.py', category: 'SQLite Persistence', language: 'python' },
    { path: 'tests/test_safety.py', category: 'Pytest Suite', language: 'python' },
    { path: 'tests/test_headers.py', category: 'Pytest Suite', language: 'python' },
    { path: 'tests/test_scoring.py', category: 'Pytest Suite', language: 'python' },
    { path: 'tests/test_database.py', category: 'Pytest Suite', language: 'python' },
    { path: 'tests/test_reports.py', category: 'Pytest Suite', language: 'python' },
    { path: 'docs/en.md', category: 'Documentation', language: 'markdown' },
    { path: 'docs/bn.md', category: 'Bengali Docs', language: 'markdown' },
    { path: 'docs/architecture.md', category: 'Architecture', language: 'markdown' },
    { path: 'docs/troubleshooting.md', category: 'Troubleshooting', language: 'markdown' },
  ];
  return res.json(repoFiles);
});

// 8. GET /api/file-content - Read specific repo file
app.get('/api/file-content', (req, res) => {
  const filePath = req.query.path as string;
  if (!filePath || filePath.includes('..') || filePath.startsWith('/')) {
    return res.status(400).json({ error: 'Invalid file path' });
  }

  const fullPath = path.resolve(filePath);
  if (!fs.existsSync(fullPath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  try {
    const content = fs.readFileSync(fullPath, 'utf-8');
    return res.json({ path: filePath, content });
  } catch (err) {
    return res.status(500).json({ error: 'ReadError', message: (err as Error).message });
  }
});

// 9. GET /api/docs/:lang - Read documentation
app.get('/api/docs/:lang', (req, res) => {
  const lang = req.params.lang === 'bn' ? 'bn.md' : 'en.md';
  const docPath = path.resolve('docs', lang);
  if (!fs.existsSync(docPath)) {
    return res.status(404).send('Documentation file not found.');
  }
  const content = fs.readFileSync(docPath, 'utf-8');
  return res.send(content);
});

// Mount Vite or static server
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve('dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[WebShield AI] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[WebShield AI] Server failed to start:', err);
  process.exit(1);
});
