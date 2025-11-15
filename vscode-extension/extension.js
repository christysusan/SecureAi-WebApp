const vscode = require('vscode');

// Security detection patterns
const SECURITY_PATTERNS = [
  {
    id: 'hardcoded-api-key',
    pattern: /(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi,
    message: 'Hardcoded API key detected. Move to environment variables.',
    severity: vscode.DiagnosticSeverity.Error,
    cwe: 'CWE-798'
  },
  {
    id: 'aws-key',
    pattern: /(AKIA[0-9A-Z]{16})/g,
    message: 'AWS Access Key detected. Never commit AWS credentials.',
    severity: vscode.DiagnosticSeverity.Error,
    cwe: 'CWE-798'
  },
  {
    id: 'private-key',
    pattern: /-----BEGIN (RSA |DSA )?PRIVATE KEY-----/g,
    message: 'Private key detected. Remove from code immediately.',
    severity: vscode.DiagnosticSeverity.Error,
    cwe: 'CWE-798'
  },
  {
    id: 'password-hardcoded',
    pattern: /(password|passwd|pwd)\s*[:=]\s*["'](?!.*(\$\{|process\.env))[^"']{3,}["']/gi,
    message: 'Hardcoded password detected. Use environment variables.',
    severity: vscode.DiagnosticSeverity.Error,
    cwe: 'CWE-798'
  },
  {
    id: 'sql-injection',
    pattern: /(SELECT|INSERT|UPDATE|DELETE).*\+\s*\w+|(\$\{|\$)\w+/gi,
    message: 'Potential SQL injection. Use parameterized queries.',
    severity: vscode.DiagnosticSeverity.Warning,
    cwe: 'CWE-89'
  },
  {
    id: 'eval-usage',
    pattern: /\beval\s*\(/g,
    message: 'Use of eval() is dangerous. Avoid or sanitize input.',
    severity: vscode.DiagnosticSeverity.Warning,
    cwe: 'CWE-95'
  },
  {
    id: 'exec-command',
    pattern: /\b(exec|system|shell_exec|passthru)\s*\(/g,
    message: 'Command execution detected. Validate input to prevent injection.',
    severity: vscode.DiagnosticSeverity.Warning,
    cwe: 'CWE-78'
  },
  {
    id: 'weak-crypto',
    pattern: /\b(md5|sha1)\s*\(/gi,
    message: 'Weak cryptographic function. Use SHA-256 or better.',
    severity: vscode.DiagnosticSeverity.Warning,
    cwe: 'CWE-327'
  },
  {
    id: 'innerHTML-xss',
    pattern: /\.innerHTML\s*=\s*(?!["']\s*["'])\w+/g,
    message: 'Potential XSS vulnerability. Sanitize input or use textContent.',
    severity: vscode.DiagnosticSeverity.Warning,
    cwe: 'CWE-79'
  },
  {
    id: 'jwt-secret',
    pattern: /(jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*["'][^"']+["']/gi,
    message: 'JWT secret hardcoded. Move to secure environment variable.',
    severity: vscode.DiagnosticSeverity.Error,
    cwe: 'CWE-798'
  }
];

let diagnosticCollection;

function activate(context) {
  console.log('OneStop CYworld Guardian is now active');

  // Create diagnostic collection
  diagnosticCollection = vscode.languages.createDiagnosticCollection('onestop-security');
  context.subscriptions.push(diagnosticCollection);

  // Scan on file open
  if (vscode.window.activeTextEditor) {
    scanDocument(vscode.window.activeTextEditor.document);
  }

  // Scan on active editor change
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor) {
        scanDocument(editor.document);
      }
    })
  );

  // Scan on document change (real-time)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      const config = vscode.workspace.getConfiguration('onestop-cyworld');
      if (config.get('enableRealTime')) {
        scanDocument(event.document);
      }
    })
  );

  // Scan on document save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(document => {
      scanDocument(document);
    })
  );

  // Command: Scan current file
  context.subscriptions.push(
    vscode.commands.registerCommand('onestop-cyworld.scanFile', () => {
      if (vscode.window.activeTextEditor) {
        scanDocument(vscode.window.activeTextEditor.document);
        vscode.window.showInformationMessage('OneStop: File scan complete!');
      }
    })
  );

  // Command: Scan workspace
  context.subscriptions.push(
    vscode.commands.registerCommand('onestop-cyworld.scanWorkspace', async () => {
      const files = await vscode.workspace.findFiles('**/*.{js,ts,py,java,php,go}', '**/node_modules/**');
      let totalIssues = 0;

      for (const file of files) {
        const document = await vscode.workspace.openTextDocument(file);
        const issues = scanDocument(document);
        totalIssues += issues;
      }

      vscode.window.showInformationMessage(`OneStop: Workspace scan complete! Found ${totalIssues} security issues.`);
    })
  );

  // Show welcome message
  vscode.window.showInformationMessage('🛡️ OneStop CYworld Guardian activated! Your code is being protected.');
}

function scanDocument(document) {
  const diagnostics = [];
  const text = document.getText();
  const config = vscode.workspace.getConfiguration('onestop-cyworld');
  const minSeverity = config.get('severity');

  // Skip if file is too large (performance)
  if (text.length > 500000) {
    return 0;
  }

  // Scan with each pattern
  for (const pattern of SECURITY_PATTERNS) {
    const regex = new RegExp(pattern.pattern);
    const lines = text.split('\n');

    lines.forEach((line, lineIndex) => {
      regex.lastIndex = 0; // Reset regex
      let match;

      while ((match = regex.exec(line)) !== null) {
        // Check severity filter
        if (!shouldShowDiagnostic(pattern.severity, minSeverity)) {
          continue;
        }

        const startPos = new vscode.Position(lineIndex, match.index);
        const endPos = new vscode.Position(lineIndex, match.index + match[0].length);
        const range = new vscode.Range(startPos, endPos);

        const diagnostic = new vscode.Diagnostic(
          range,
          `${pattern.message} (${pattern.cwe})`,
          pattern.severity
        );

        diagnostic.code = pattern.id;
        diagnostic.source = 'OneStop CYworld';

        // Add quick fix suggestions
        diagnostic.relatedInformation = [
          new vscode.DiagnosticRelatedInformation(
            new vscode.Location(document.uri, range),
            `Learn more: https://cwe.mitre.org/data/definitions/${pattern.cwe.replace('CWE-', '')}.html`
          )
        ];

        diagnostics.push(diagnostic);
      }
    });
  }

  diagnosticCollection.set(document.uri, diagnostics);
  return diagnostics.length;
}

function shouldShowDiagnostic(severity, minSeverity) {
  if (minSeverity === 'all') return true;

  const severityLevels = {
    'critical': 0,
    'high': 1,
    'medium': 2,
    'low': 3
  };

  const diagnosticLevel = severity === vscode.DiagnosticSeverity.Error ? 0 : 1;
  const configLevel = severityLevels[minSeverity] || 3;

  return diagnosticLevel <= configLevel;
}

function deactivate() {
  if (diagnosticCollection) {
    diagnosticCollection.dispose();
  }
}

module.exports = {
  activate,
  deactivate
};
