/**
 * Nexus Security Pro — VS Code Extension
 *
 * Анализ кода в реальном времени через Diagnostics API.
 * Подсвечивает уязвимости волнистыми линиями при наборе и сохранении.
 *
 * Архитектура:
 *   - При изменении/сохранении файла запускается cli.py --format json
 *   - JSON-результат конвертируется в vscode.Diagnostic[]
 *   - Диагностики показываются в Problems-панели и подчёркиваются в коде
 *   - Quick Fix предлагает замену из поля fix_after
 *
 * Принципы качества:
 *   - Никаких синхронных файловых операций в обработчиках событий (не блокируем UI)
 *   - Один анализ на документ за раз: новый запуск отменяет предыдущий (нет гонок)
 *   - Временные файлы создаются в приватной случайной директории (mkdtemp)
 *   - Результат применяется только если документ не изменился во время анализа
 *   - Данные Quick Fix хранятся в WeakMap, а не в any-кастах диагностик
 */

import * as vscode from 'vscode';
import { execFile, execFileSync, ChildProcess } from 'child_process';
import * as path from 'path';
import * as fs from 'fs/promises';
import { existsSync } from 'fs';
import * as os from 'os';

// Все языки, которые анализирует движок Nexus (см. detect_language в движке).
// Используются официальные VS Code languageId.
const SUPPORTED_LANGS = [
  'python', 'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
  'go', 'java', 'kotlin', 'ruby', 'php', 'rust', 'csharp',
  'c', 'cpp', 'swift', 'scala', 'sql', 'shellscript',
  'css', 'scss', 'html', 'yaml',
];

let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;
let statusBar: vscode.StatusBarItem;
let extContext: vscode.ExtensionContext;

/** Результат последнего скана проекта (для журнала). */
let lastScan: { at: Date; results: NexusResult[]; total: number } | undefined;
let scanReportPanel: vscode.WebviewPanel | undefined;

/** Таймеры debounce по документу (ключ — uri.toString()). */
const debounceTimers = new Map<string, NodeJS.Timeout>();
/** Активные процессы анализа по документу — для отмены при новом запуске. */
const activeProcesses = new Map<string, ChildProcess>();
/** Хранилище данных Quick Fix: диагностика → исправление. Типобезопасно, без any. */
const fixData = new WeakMap<vscode.Diagnostic, { fix: string; ruleId: string }>();
// rule_id для каждой диагностики Nexus — нужно для подавления (# nexus:ignore[ID])
const ruleIdData = new WeakMap<vscode.Diagnostic, string>();

// ── Типы результата CLI ──────────────────────────────────────────────────────
interface NexusFinding {
  rule_id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe: string;
  category: string;
  file: string;
  line: number;
  col: number;
  snippet: string;
  desc: string;
  fix_before: string;
  fix_after: string;
  confidence: string;
}

interface NexusAntipattern {
  id: string;
  title: string;
  desc: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  file: string;
  line: number;
  snippet: string;
  example_before: string;
  example_after: string;
}

interface NexusFunction {
  name: string;
  line: number;
  cyclomatic_complexity: number;
  cognitive_complexity: number;
  line_count: number;
  issues: string[];
  refactor_priority: string;
}

interface NexusResult {
  filename: string;
  score: number;
  grade: string;
  findings: NexusFinding[];
  antipatterns?: NexusAntipattern[];
  functions?: NexusFunction[];
  summary: { critical: number; high: number; medium: number; low: number; total: number };
}

// ── Активация расширения ─────────────────────────────────────────────────────
export function activate(context: vscode.ExtensionContext) {
  extContext = context;
  diagnosticCollection = vscode.languages.createDiagnosticCollection('nexus');
  outputChannel = vscode.window.createOutputChannel('Nexus Security');
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'nexus.scanFile';
  context.subscriptions.push(diagnosticCollection, outputChannel, statusBar);

  context.subscriptions.push(
    vscode.commands.registerCommand('nexus.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) { void scanDocument(editor.document, true); }
      else { notify('info', 'Nexus Security: откройте файл, чтобы запустить анализ.'); }
    }),
    vscode.commands.registerCommand('nexus.scanWorkspace', scanWorkspace),
    vscode.commands.registerCommand('nexus.checkReadability', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) { void checkReadability(editor.document); }
    }),
    vscode.commands.registerCommand('nexus.applyRefactoring', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) { void applyRefactoring(editor.document); }
      else { notify('info', 'Nexus: откройте файл для применения автофиксов.'); }
    }),
    vscode.commands.registerCommand('nexus.applyRefactoringSelection', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) { void applyRefactoringSelection(editor); }
      else { notify('info', 'Nexus: откройте файл и выделите фрагмент.'); }
    }),
    vscode.commands.registerCommand('nexus.simplifyFunction', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) { void simplifyFunctionAtCursor(editor); }
      else { notify('info', 'Nexus: поставьте курсор внутрь функции.'); }
    }),
    vscode.commands.registerCommand('nexus.explainCode', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) { void explainCode(editor.document, context); }
      else { notify('info', 'Nexus: откройте файл для объяснения.'); }
    }),
    vscode.commands.registerCommand('nexus.addDocstrings', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) { void addDocstrings(editor.document); }
      else { notify('info', 'Nexus: откройте Python-файл.'); }
    }),
    vscode.commands.registerCommand('nexus.clearDiagnostics', () => {
      diagnosticCollection.clear();
      statusBar.hide();
    }),
    vscode.commands.registerCommand('nexus.openSettings', () => openSettingsPanel(context)),
    vscode.commands.registerCommand('nexus.showReport', () => {
      if (lastScan) { openScanReport(context); }
      else { notify('info', 'Nexus: сначала запустите «Сканировать проект».'); }
    }),
    vscode.commands.registerCommand('nexus.jumpTo', (file: string, line: number) => {
      vscode.workspace.openTextDocument(vscode.Uri.file(file)).then((doc) => {
        vscode.window.showTextDocument(doc).then((ed) => {
          const pos = new vscode.Position(Math.max(0, line - 1), 0);
          ed.selection = new vscode.Selection(pos, pos);
          ed.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
        });
      }, () => notify('warn', `Nexus: не удалось открыть ${file}`));
    })
  );

  // Когда пользователь доверяет папке — сразу анализируем активный файл
  context.subscriptions.push(
    vscode.workspace.onDidGrantWorkspaceTrust(() => {
      cliMissingNotified = false;
      const editor = vscode.window.activeTextEditor;
      if (editor && isSupported(editor.document)) { void scanDocument(editor.document); }
    })
  );

  // Анализ при сохранении
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const cfg = vscode.workspace.getConfiguration('nexus');
      if (cfg.get<boolean>('runOnSave', true) && isSupported(doc)) {
        void scanDocument(doc);
      }
    })
  );

  // Анализ при наборе (debounced, без блокировки UI)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const cfg = vscode.workspace.getConfiguration('nexus');
      if (!cfg.get<boolean>('runOnType', true)) { return; }
      if (!isSupported(event.document)) { return; }

      const key = event.document.uri.toString();
      const existing = debounceTimers.get(key);
      if (existing) { clearTimeout(existing); }
      const delay = cfg.get<number>('debounceMs', 800);
      debounceTimers.set(key, setTimeout(() => {
        debounceTimers.delete(key);
        void scanDocument(event.document);
      }, delay));
    })
  );

  // Очистка ресурсов при закрытии документа
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      const key = doc.uri.toString();
      const timer = debounceTimers.get(key);
      if (timer) { clearTimeout(timer); debounceTimers.delete(key); }
      cancelActive(key);
      diagnosticCollection.delete(doc.uri);
    })
  );

  // Обновляем статус-бар при смене активного редактора
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && isSupported(editor.document)) {
        void scanDocument(editor.document);
      } else {
        statusBar.hide();
      }
    })
  );

  // Quick Fix провайдер
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      SUPPORTED_LANGS,
      new NexusCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );

  // Сканируем активный файл при старте
  if (vscode.window.activeTextEditor) {
    void scanDocument(vscode.window.activeTextEditor.document);
  }

  outputChannel.appendLine('Nexus Security Pro активирован');
}

export function deactivate() {
  for (const timer of debounceTimers.values()) { clearTimeout(timer); }
  debounceTimers.clear();
  for (const proc of activeProcesses.values()) { proc.kill(); }
  activeProcesses.clear();
  diagnosticCollection?.clear();
}

// ── Утилиты ───────────────────────────────────────────────────────────────────
function isSupported(doc: vscode.TextDocument): boolean {
  return SUPPORTED_LANGS.includes(doc.languageId);
}

/** Отменяет активный процесс анализа для документа, если он есть. */
function cancelActive(key: string): void {
  const proc = activeProcesses.get(key);
  if (proc) {
    proc.kill();
    activeProcesses.delete(key);
  }
}

// ── Поиск cli.py ──────────────────────────────────────────────────────────────
function findCliPath(): string | undefined {
  const cfg = vscode.workspace.getConfiguration('nexus');
  const custom = cfg.get<string>('cliPath', '');
  if (custom && existsSync(custom)) { return custom; }

  const folders = vscode.workspace.workspaceFolders;
  if (folders) {
    for (const folder of folders) {
      const base = folder.uri.fsPath;
      // 1) конфиг, созданный install.py — самый надёжный источник
      for (const rel of ['nexus-config.json', 'engine/nexus-config.json']) {
        const cfgFile = path.join(base, rel);
        if (existsSync(cfgFile)) {
          try {
            const data = JSON.parse(require('fs').readFileSync(cfgFile, 'utf8'));
            if (data.cliPath && existsSync(data.cliPath)) { return data.cliPath; }
          } catch { /* битый конфиг — игнорируем */ }
        }
      }
      // 2) типовые расположения cli.py
      for (const rel of ['cli.py', 'engine/cli.py', 'nexus-engine/cli.py',
                         'nexus_core/cli.py', 'nexus_enterprise/cli.py']) {
        const candidate = path.join(base, rel);
        if (existsSync(candidate)) { return candidate; }
      }
    }
  }
  return undefined;
}

// Авто-определение рабочего Python: настройка → конфиг → перебор кандидатов.
// Кэшируется, чтобы не проверять при каждом анализе.
let resolvedPython: string | undefined;
function resolvePython(): string {
  const cfg = vscode.workspace.getConfiguration('nexus');
  const custom = cfg.get<string>('pythonPath', '');
  // явная настройка пользователя имеет приоритет (кроме старого дефолта 'python')
  if (custom && custom !== 'python') { return custom; }
  if (resolvedPython) { return resolvedPython; }

  // перебираем кандидатов, пока какой-то не ответит на --version
  const candidates = process.platform === 'win32'
    ? ['python', 'py', 'python3']
    : ['python3', 'python'];
  for (const cand of candidates) {
    try {
      execFileSync(cand, ['--version'], { timeout: 3000, stdio: 'ignore' });
      resolvedPython = cand;
      return cand;
    } catch { /* не этот — пробуем следующий */ }
  }
  return custom || 'python3';  // ничего не нашли — вернём разумный дефолт
}

// ── Видимые уведомления (с дедупликацией, чтобы не спамить при наборе) ─────────
let lastNotice = '';
let lastNoticeAt = 0;
function notify(kind: 'error' | 'warn' | 'info', msg: string, ...actions: string[]): Thenable<string | undefined> {
  const now = Date.now();
  // Дедупликация только для сообщений БЕЗ кнопок: интерактивные диалоги
  // (с действиями вроде «Применить?») глушить нельзя — пользователь их ждёт.
  if (actions.length === 0 && msg === lastNotice && now - lastNoticeAt < 8000) {
    return Promise.resolve(undefined);
  }
  lastNotice = msg; lastNoticeAt = now;
  outputChannel.appendLine(msg);
  const fn = kind === 'error' ? vscode.window.showErrorMessage
    : kind === 'warn' ? vscode.window.showWarningMessage
    : vscode.window.showInformationMessage;
  return fn(msg, ...actions);
}

// ── Проверка доверия к рабочей области (Workspace Trust) ──────────────────────
function ensureTrusted(): boolean {
  if (vscode.workspace.isTrusted) { return true; }
  notify('warn',
    'Nexus Security: анализ отключён — папка не доверенная. Нажмите «Доверять», чтобы разрешить запуск анализатора.',
    'Доверять папке'
  ).then((choice) => {
    if (choice === 'Доверять папке') {
      vscode.commands.executeCommand('workbench.action.manageTrust');
    }
  });
  return false;
}

// ── Понятная подсказка при ошибке запуска Python ──────────────────────────────
function explainPythonError(error: Error, python: string): string | null {
  if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
    return `Nexus Security: интерпретатор «${python}» не найден. Установите Python 3 ` +
      `или укажите путь в настройке nexus.pythonPath (на Linux обычно «python3»).`;
  }
  return null;
}

// Подсказать про отсутствие cli.py не чаще одного раза за сессию автоматического скана
let cliMissingNotified = false;
function noticeCliMissing(): void {
  notify('warn',
    'Nexus Security: файл cli.py не найден в рабочей области. Откройте папку проекта Nexus ' +
    'или укажите путь в настройке nexus.cliPath.',
    'Открыть настройки'
  ).then((c) => {
    if (c === 'Открыть настройки') {
      vscode.commands.executeCommand('workbench.action.openSettings', 'nexus.cliPath');
    }
  });
}

// ── Сканирование документа ────────────────────────────────────────────────────
async function scanDocument(doc: vscode.TextDocument, interactive = false): Promise<void> {
  if (!isSupported(doc)) { return; }

  // Workspace Trust: без доверия VS Code не даст запустить Python
  if (!vscode.workspace.isTrusted) {
    if (interactive) { ensureTrusted(); }
    return;
  }

  const cliPath = findCliPath();
  if (!cliPath) {
    // при автоскане не спамим, но один раз показываем; при ручном — всегда
    if (interactive) { noticeCliMissing(); }
    else if (!cliMissingNotified) { cliMissingNotified = true; noticeCliMissing(); }
    return;
  }

  const cfg = vscode.workspace.getConfiguration('nexus');
  const python = resolvePython();
  const depth = cfg.get<number>('depth', 2);

  const key = doc.uri.toString();
  cancelActive(key);
  const version = doc.version;

  let tmpDir: string;
  let tmpFile: string;
  try {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'nexus-'));
    tmpFile = path.join(tmpDir, 'src' + (path.extname(doc.fileName) || '.txt'));
    await fs.writeFile(tmpFile, doc.getText());
  } catch (e) {
    notify('error', `Nexus Security: не удалось подготовить временный файл: ${e}`);
    return;
  }

  const showStatus = vscode.workspace.getConfiguration('nexus').get<boolean>('showStatusBar', true);
  if (showStatus) {
    statusBar.text = '$(sync~spin) Nexus';
    statusBar.tooltip = 'Nexus: анализ...';
    statusBar.show();
  } else {
    statusBar.hide();
  }

  const child = execFile(
    python,
    [cliPath, tmpFile, '--format', 'json', '--depth', String(depth)],
    { timeout: 15000, maxBuffer: 10 * 1024 * 1024 },
    (error, stdout, stderr) => {
      activeProcesses.delete(key);
      void fs.rm(tmpDir, { recursive: true, force: true }).catch(() => { /* ignore */ });

      if (error && (error as NodeJS.ErrnoException).killed) { return; }

      if (error && !stdout) {
        const pyHint = explainPythonError(error, python);
        if (pyHint) {
          notify('error', pyHint, 'Открыть настройки').then((c) => {
            if (c === 'Открыть настройки') {
              vscode.commands.executeCommand('workbench.action.openSettings', 'nexus.pythonPath');
            }
          });
        } else {
          notify('error', `Nexus Security: ошибка анализа — ${stderr || error.message}`);
        }
        statusBar.text = '$(error) Nexus';
        statusBar.tooltip = 'Nexus: ошибка анализа';
        return;
      }

      const current = vscode.workspace.textDocuments.find((d) => d.uri.toString() === key);
      if (current && current.version !== version) { return; }

      try {
        const results: NexusResult[] = JSON.parse(stdout);
        if (results.length > 0) {
          updateDiagnostics(doc, results[0]);
        } else {
          statusBar.hide();
        }
      } catch (e) {
        notify('error', `Nexus Security: не удалось разобрать ответ анализатора (${e})`);
        statusBar.hide();
      }
    }
  );
  activeProcesses.set(key, child);
}

// ── Обновление диагностик ─────────────────────────────────────────────────────
function updateDiagnostics(doc: vscode.TextDocument, result: NexusResult): void {
  const cfg = vscode.workspace.getConfiguration('nexus');
  const minSev = cfg.get<string>('minSeverity', 'low');
  const sevOrder: Record<string, number> = {
    critical: 0, high: 1, medium: 2, low: 3, info: 4,
  };
  const threshold = sevOrder[minSev] ?? 3;

  const diagnostics: vscode.Diagnostic[] = [];

  const lineRangeFor = (line1: number, col?: number): vscode.Range => {
    const lineIdx = Math.min(Math.max(0, line1 - 1), Math.max(0, doc.lineCount - 1));
    const lineText = lineIdx < doc.lineCount ? doc.lineAt(lineIdx).text : '';
    const startCol = col != null ? Math.min(Math.max(0, col), lineText.length) : 0;
    const endCol = Math.max(startCol + 1, lineText.length);
    return new vscode.Range(lineIdx, startCol, lineIdx, endCol);
  };

  // настройки кастомизации текста находок
  const showRuleId = cfg.get<boolean>('showRuleId', true);
  const showCwe = cfg.get<boolean>('showCwe', true);

  // 1) Уязвимости безопасности (findings)
  for (const f of result.findings) {
    if ((sevOrder[f.severity] ?? 9) > threshold) { continue; }

    // собираем заголовок с опциональными метками [RULE-ID] и (CWE-XX)
    const tags: string[] = [];
    if (showRuleId && f.rule_id) { tags.push(`[${f.rule_id}]`); }
    if (showCwe && f.cwe) { tags.push(`(${f.cwe})`); }
    const titleLine = tags.length ? `${f.title} ${tags.join(' ')}` : f.title;

    const diagnostic = new vscode.Diagnostic(
      lineRangeFor(f.line, f.col),
      `${titleLine}\n${f.desc}`,
      mapSeverity(f.severity)
    );
    diagnostic.source = 'Nexus Security';
    const cweNum = (f.cwe || '').replace('CWE-', '');
    diagnostic.code = cweNum
      ? {
          value: f.cwe,
          target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${cweNum}.html`),
        }
      : undefined;

    if (f.fix_after) {
      fixData.set(diagnostic, { fix: f.fix_after, ruleId: f.rule_id });
    }
    if (f.rule_id) { ruleIdData.set(diagnostic, f.rule_id); }
    diagnostics.push(diagnostic);
  }

  // 2) Антипаттерны и проблемы качества кода (antipatterns)
  const includeQuality = cfg.get<boolean>('showAntipatterns', true);
  if (includeQuality && Array.isArray(result.antipatterns)) {
    for (const a of result.antipatterns) {
      if ((sevOrder[a.severity] ?? 9) > threshold) { continue; }
      const diagnostic = new vscode.Diagnostic(
        lineRangeFor(a.line),
        `${a.title}\n${a.desc}`,
        mapSeverity(a.severity)
      );
      diagnostic.source = 'Nexus Security';
      diagnostic.code = a.id;
      if (a.example_after) {
        fixData.set(diagnostic, { fix: a.example_after, ruleId: a.id });
      }
      if (a.id) { ruleIdData.set(diagnostic, a.id); }
      diagnostics.push(diagnostic);
    }
  }

  // 3) Проблемы сложности функций (functions[].issues) — уровень info/low
  if (includeQuality && Array.isArray(result.functions) && threshold >= sevOrder.low) {
    for (const fn of result.functions) {
      if (!fn.issues || !fn.issues.length) { continue; }
      const diagnostic = new vscode.Diagnostic(
        lineRangeFor(fn.line),
        `Функция «${fn.name}»:\n• ${fn.issues.join('\n• ')}`,
        vscode.DiagnosticSeverity.Information
      );
      diagnostic.source = 'Nexus Security';
      diagnostic.code = 'COMPLEXITY';
      ruleIdData.set(diagnostic, 'COMPLEXITY');
      diagnostics.push(diagnostic);
    }
  }

  diagnosticCollection.set(doc.uri, diagnostics);

  const s = result.summary;
  const totalShown = diagnostics.length;
  outputChannel.appendLine(
    `${path.basename(result.filename)}: ${result.grade} (${result.score}/100) — ` +
    `${s.critical} critical, ${s.high} high, ${s.medium} medium, всего показано ${totalShown}`
  );

  // Статус-бар: грейд и реальное число показанных проблем
  const icon = s.critical > 0 ? '$(error)' : s.high > 0 ? '$(warning)'
    : totalShown > 0 ? '$(info)' : '$(shield)';
  statusBar.text = `${icon} Nexus ${result.grade} (${totalShown})`;
  statusBar.tooltip = `Nexus Security: оценка ${result.score}/100, показано проблем: ${totalShown}`;
  if (vscode.workspace.getConfiguration('nexus').get<boolean>('showStatusBar', true)) {
    statusBar.show();
  } else {
    statusBar.hide();
  }
}

function mapSeverity(sev: string): vscode.DiagnosticSeverity {
  switch (sev) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

// ── Сканирование всего workspace ──────────────────────────────────────────────
async function scanWorkspace(): Promise<void> {
  if (!ensureTrusted()) { return; }
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) {
    notify('warn', 'Nexus Security: нет открытой папки. Откройте папку проекта (Файл → Открыть папку).');
    return;
  }

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'Nexus: сканирование workspace...' },
    async () => {
      const cliPath = findCliPath();
      if (!cliPath) {
        noticeCliMissing();
        return;
      }
      const cfg = vscode.workspace.getConfiguration('nexus');
      const python = resolvePython();

      return new Promise<void>((resolve) => {
        execFile(
          python,
          [cliPath, folders[0].uri.fsPath, '--recursive', '--format', 'json'],
          { timeout: 120000, maxBuffer: 50 * 1024 * 1024 },
          (error, stdout) => {
            if (error && !stdout) {
              const pyHint = explainPythonError(error, python);
              notify('error', pyHint || `Nexus Security: ошибка скана — ${error.message}`);
              resolve();
              return;
            }
            try {
              const results: NexusResult[] = JSON.parse(stdout);
              // ставим диагностики в файлы (для подчёркиваний)
              for (const r of results) {
                const uri = vscode.Uri.file(r.filename);
                vscode.workspace.openTextDocument(uri).then(
                  (doc) => updateDiagnostics(doc, r),
                  () => { /* файл недоступен — попадёт только в журнал */ }
                );
              }
              // считаем ВСЕ проблемы (findings + antipatterns + сложность), не только summary.total
              let total = 0;
              for (const r of results) {
                total += (r.findings?.length || 0);
                total += (r.antipatterns?.length || 0);
                total += (r.functions || []).filter((f) => f.issues && f.issues.length).length;
              }
              lastScan = { at: new Date(), results, total };
              notify('info', `Nexus: проанализировано ${results.length} файлов, найдено ${total} проблем.`);
              openScanReport(extContext);
            } catch (e) {
              notify('error', `Nexus Security: не удалось разобрать результат (${e})`);
            }
            resolve();
          }
        );
      });
    }
  );
}

// ── Проверка читаемости ───────────────────────────────────────────────────────
async function checkReadability(doc: vscode.TextDocument): Promise<void> {
  const cliPath = findCliPath();
  if (!cliPath) { return; }
  const cfg = vscode.workspace.getConfiguration('nexus');
  const python = resolvePython();
  const readabilityScript = path.join(path.dirname(cliPath), 'readability_cli.py');

  execFile(python, [readabilityScript, doc.fileName], { timeout: 15000 },
    (error, stdout) => {
      if (error && !stdout) {
        outputChannel.appendLine(`Readability: ${error.message}`);
        return;
      }
      outputChannel.show(true);
      outputChannel.appendLine('\n=== Readability Report ===');
      outputChannel.appendLine(stdout);
    });
}

// ── Применение рефакторинга ───────────────────────────────────────────────────
// Рефакторинг всего файла
// Рефакторинг всего файла (только Python — движок работает с Python AST)
async function applyRefactoring(doc: vscode.TextDocument): Promise<void> {
  if (doc.languageId !== 'python') {
    notify('info', 'Nexus: авто-рефакторинг доступен только для Python-файлов.');
    return;
  }
  const fullRange = new vscode.Range(doc.positionAt(0), doc.positionAt(doc.getText().length));
  await runRefactor(doc, doc.getText(), fullRange, 'файл');
}

// Рефакторинг выделенного блока
async function applyRefactoringSelection(editor: vscode.TextEditor): Promise<void> {
  if (editor.document.languageId !== 'python') {
    notify('info', 'Nexus: авто-рефакторинг доступен только для Python-файлов.');
    return;
  }
  const sel = editor.selection;
  if (sel.isEmpty) {
    notify('info', 'Nexus: выделите фрагмент кода для исправления (или используйте «Применить автофиксы ко всему файлу»).');
    return;
  }
  const text = editor.document.getText(sel);
  await runRefactor(editor.document, text, sel, 'выделение');
}

// Упростить функцию, внутри которой стоит курсор (guard clauses + extract condition)
async function simplifyFunctionAtCursor(editor: vscode.TextEditor): Promise<void> {
  const doc = editor.document;
  if (doc.languageId !== 'python') {
    notify('info', 'Nexus: упрощение функций доступно только для Python-файлов.');
    return;
  }
  const cursorLine = editor.selection.active.line;
  const range = findEnclosingFunction(doc, cursorLine);
  if (!range) {
    notify('info', 'Nexus: поставьте курсор внутрь функции (строка с def …).');
    return;
  }
  const text = doc.getText(range);
  await runRefactor(doc, text, range, 'функцию');
}

// Объяснение кода: структурный разбор файла и функций (без ИИ)
async function explainCode(doc: vscode.TextDocument, context: vscode.ExtensionContext): Promise<void> {
  if (!ensureTrusted()) { return; }
  const cliPath = findCliPath();
  if (!cliPath) { noticeCliMissing(); return; }
  const explainScript = path.join(path.dirname(cliPath), 'explain_cli.py');
  if (!existsSync(explainScript)) {
    notify('error', 'Nexus: explain_cli.py не найден рядом с cli.py.');
    return;
  }
  const python = resolvePython();
  let tmpDir: string; let tmpFile: string;
  try {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'nexus-explain-'));
    tmpFile = path.join(tmpDir, 'src' + (path.extname(doc.fileName) || '.py'));
    await fs.writeFile(tmpFile, doc.getText());
  } catch (e) {
    notify('error', `Nexus: не удалось подготовить файл (${e})`);
    return;
  }

  execFile(python, [explainScript, tmpFile], { timeout: 15000 }, (error, stdout) => {
    void fs.rm(tmpDir, { recursive: true, force: true }).catch(() => { /* ignore */ });
    if (error && !stdout) {
      notify('error', explainPythonError(error, python) || `Nexus: ошибка объяснения — ${error.message}`);
      return;
    }
    let res: { summary?: string; functions?: Array<{ name: string; line: number; behavior: string; has_docstring: boolean }>; error?: string };
    try { res = JSON.parse(stdout); } catch (e) {
      notify('error', `Nexus: не удалось разобрать ответ (${e})`); return;
    }
    if (res.error) { notify('warn', `Nexus: ${res.error}`); return; }

    // показываем объяснение в webview-панели
    const panel = vscode.window.createWebviewPanel(
      'nexusExplain', 'Nexus: объяснение кода', vscode.ViewColumn.Beside,
      { enableScripts: false }
    );
    panel.webview.html = explainHtml(res.summary || '', res.functions || []);
  });
}

function explainHtml(summary: string, functions: Array<{ name: string; line: number; behavior: string; has_docstring: boolean }>): string {
  const esc = (s: string) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c] || c));
  const rows = functions.map((f) =>
    `<tr><td class="fn">${esc(f.name)}</td><td>${esc(f.behavior)}</td>` +
    `<td class="${f.has_docstring ? 'ok' : 'no'}">${f.has_docstring ? 'есть' : 'нет'}</td></tr>`
  ).join('');
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
    body { font-family: var(--vscode-font-family); padding: 16px; color: var(--vscode-foreground); }
    h2 { font-size: 1.1em; } .sum { background: var(--vscode-textBlockQuote-background); padding: 10px 14px; border-radius: 6px; margin-bottom: 16px; }
    table { border-collapse: collapse; width: 100%; } th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--vscode-panel-border); vertical-align: top; }
    .fn { font-family: monospace; font-weight: bold; white-space: nowrap; } .ok { color: #3fb950; } .no { color: #d29922; }
    th { font-size: .85em; opacity: .8; }
  </style></head><body>
    <h2>Обзор файла</h2><div class="sum">${esc(summary)}</div>
    ${functions.length ? `<h2>Функции (${functions.length})</h2>
    <table><tr><th>Функция</th><th>Что делает</th><th>Docstring</th></tr>${rows}</table>` : '<p>Функции не найдены.</p>'}
    <p style="margin-top:16px;opacity:.7;font-size:.85em">Объяснение построено по структуре кода (AST), без ИИ. Чтобы добавить заготовки docstring — команда «Nexus: добавить docstring-заготовки».</p>
  </body></html>`;
}

// Добавление docstring-заготовок во все функции без них
async function addDocstrings(doc: vscode.TextDocument): Promise<void> {
  if (doc.languageId !== 'python') {
    notify('info', 'Nexus: docstring-заготовки доступны только для Python.');
    return;
  }
  if (!ensureTrusted()) { return; }
  const cliPath = findCliPath();
  if (!cliPath) { noticeCliMissing(); return; }
  const explainScript = path.join(path.dirname(cliPath), 'explain_cli.py');
  if (!existsSync(explainScript)) {
    notify('error', 'Nexus: explain_cli.py не найден рядом с cli.py.');
    return;
  }
  const python = resolvePython();
  let tmpDir: string; let tmpFile: string;
  try {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'nexus-doc-'));
    tmpFile = path.join(tmpDir, 'src.py');
    await fs.writeFile(tmpFile, doc.getText());
  } catch (e) {
    notify('error', `Nexus: не удалось подготовить файл (${e})`);
    return;
  }
  const version = doc.version;

  execFile(python, [explainScript, tmpFile, '--docstrings'], { timeout: 15000 }, (error, stdout) => {
    void fs.rm(tmpDir, { recursive: true, force: true }).catch(() => { /* ignore */ });
    if (error && !stdout) {
      notify('error', explainPythonError(error, python) || `Nexus: ошибка — ${error.message}`);
      return;
    }
    let res: { refactored?: string; added?: number; changed?: boolean };
    try { res = JSON.parse(stdout); } catch (e) {
      notify('error', `Nexus: не удалось разобрать ответ (${e})`); return;
    }
    if (!res.changed || !res.refactored) {
      notify('info', 'Nexus: все функции уже имеют docstring.');
      return;
    }
    notify('info',
      `Nexus: добавить ${res.added} docstring-заготовок? Их нужно будет дополнить (поля помечены TODO).`,
      'Добавить', 'Отмена'
    ).then((choice) => {
      if (choice !== 'Добавить') { return; }
      const editor = vscode.window.activeTextEditor;
      if (!editor || editor.document.version !== version) {
        notify('warn', 'Nexus: файл изменился, повторите.');
        return;
      }
      const fullRange = new vscode.Range(
        editor.document.positionAt(0),
        editor.document.positionAt(editor.document.getText().length)
      );
      const edit = new vscode.WorkspaceEdit();
      edit.replace(editor.document.uri, fullRange, res.refactored!);
      void vscode.workspace.applyEdit(edit).then((ok) => {
        if (ok) { notify('info', `Nexus: добавлено ${res.added} заготовок. Заполните поля TODO.`); }
      });
    });
  });
}

// Находит диапазон функции (def … и её тело по отступам), охватывающей строку line
function findEnclosingFunction(doc: vscode.TextDocument, line: number): vscode.Range | undefined {
  const defRe = /^(\s*)(async\s+)?def\s+/;
  // ищем строку def на текущем или выше уровне, поднимаясь вверх
  let defLine = -1;
  let defIndent = -1;
  for (let i = line; i >= 0; i--) {
    const m = doc.lineAt(i).text.match(defRe);
    if (m) {
      defLine = i;
      defIndent = m[1].length;
      break;
    }
  }
  if (defLine === -1) { return undefined; }

  // конец функции: первая непустая строка с отступом <= defIndent после тела
  let endLine = doc.lineCount - 1;
  for (let i = defLine + 1; i < doc.lineCount; i++) {
    const t = doc.lineAt(i).text;
    if (t.trim() === '') { continue; }
    const indent = t.match(/^\s*/)?.[0].length ?? 0;
    if (indent <= defIndent) { endLine = i - 1; break; }
  }
  // обрезаем хвостовые пустые строки
  while (endLine > defLine && doc.lineAt(endLine).text.trim() === '') { endLine--; }

  return new vscode.Range(
    new vscode.Position(defLine, 0),
    new vscode.Position(endLine, doc.lineAt(endLine).text.length)
  );
}

// Общий движок: рефакторит переданный текст и заменяет указанный диапазон
async function runRefactor(
  doc: vscode.TextDocument, sourceText: string, replaceRange: vscode.Range, what: string
): Promise<void> {
  if (!ensureTrusted()) { return; }
  const cliPath = findCliPath();
  if (!cliPath) { noticeCliMissing(); return; }

  const cfg = vscode.workspace.getConfiguration('nexus');
  const python = resolvePython();
  const refactorScript = path.join(path.dirname(cliPath), 'refactor_pro_cli.py');
  if (!existsSync(refactorScript)) {
    notify('error', 'Nexus: файл refactor_pro_cli.py не найден рядом с cli.py — автофиксы недоступны.');
    return;
  }

  const version = doc.version;
  let tmpDir: string;
  let tmpFile: string;
  try {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'nexus-refactor-'));
    tmpFile = path.join(tmpDir, 'src.py');
    await fs.writeFile(tmpFile, sourceText);
  } catch (e) {
    notify('error', `Nexus: не удалось подготовить временный файл (${e})`);
    return;
  }

  const refLevel = cfg.get<number>('refactorLevel', 1);
  const useBlack = cfg.get<boolean>('refactorFormatBlack', false);
  const refArgs = [refactorScript, tmpFile, '--level', String(refLevel)];
  if (useBlack) { refArgs.push('--black'); }

  execFile(python, refArgs, { timeout: 15000 },
    (error, stdout) => {
      void fs.rm(tmpDir, { recursive: true, force: true }).catch(() => { /* ignore */ });
      if (error && !stdout) {
        const pyHint = explainPythonError(error, python);
        notify('error', pyHint || `Nexus: ошибка рефакторинга — ${error.message}`);
        return;
      }
      let result: {
        changed?: boolean; error?: string; refactored?: string;
        changes?: Array<{ category: string }>;
        metrics?: { before: { branches: number; max_depth: number }; after: { branches: number; max_depth: number } };
      };
      try {
        result = JSON.parse(stdout);
      } catch (e) {
        notify('error', `Nexus: не удалось разобрать ответ рефакторинга (${e})`);
        return;
      }

      if (result.error) {
        notify('warn',
          `Nexus: не удалось применить автофиксы к ${what} — фрагмент должен быть синтаксически целым ` +
          `(полная функция/блок). Попробуйте выделить больше или применить ко всему файлу.`);
        return;
      }
      if (!result.changed || !result.refactored) {
        notify('info', `Nexus: в ${what} нечего улучшать — код уже чистый.`);
        return;
      }

      const changes = result.changes || [];
      const byCat: Record<string, number> = {};
      for (const c of changes) { byCat[c.category] = (byCat[c.category] || 0) + 1; }
      const summary = Object.entries(byCat).map(([cat, n]) => `${cat}: ${n}`).join(', ');

      // Сообщаем эффект по метрикам, если сложность снизилась
      let metricNote = '';
      if (result.metrics) {
        const b = result.metrics.before, a = result.metrics.after;
        if (a.max_depth < b.max_depth || a.branches < b.branches) {
          metricNote = ` Вложенность ${b.max_depth}→${a.max_depth}, ветвлений ${b.branches}→${a.branches}.`;
        }
      }

      notify('info',
        `Nexus: найдено ${changes.length} безопасных улучшений (${summary}).${metricNote} Применить к ${what}?`,
        'Применить', 'Отмена'
      ).then((choice) => {
        if (choice !== 'Применить') { return; }
        if (doc.version !== version) {
          notify('warn', 'Nexus: файл изменился после анализа — автофиксы отменены, запустите заново.');
          return;
        }
        const edit = new vscode.WorkspaceEdit();
        edit.replace(doc.uri, replaceRange, result.refactored!);
        void vscode.workspace.applyEdit(edit).then((ok) => {
          if (ok) { notify('info', `Nexus: применено ${changes.length} улучшений.`); }
        });
      });
    });
}

// ── Quick Fix провайдер ───────────────────────────────────────────────────────
class NexusCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const nosecDone = new Set<number>();  // строки, для которых уже добавлен # nosec
    // Символ комментария зависит от языка: # для Python/Ruby/YAML, /* */ для CSS, // для C-подобных
    const hashLangs = ['python', 'ruby', 'shellscript', 'yaml'];
    const isCss = ['css', 'scss'].includes(document.languageId);
    const cmt = hashLangs.includes(document.languageId) ? '#' : '//';
    const wrap = (text: string) => isCss ? `/* ${text} */` : `${cmt} ${text}`;

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'Nexus Security') { continue; }
      const lineIdx = diagnostic.range.start.line;
      if (lineIdx >= document.lineCount) { continue; }
      const lineRange = document.lineAt(lineIdx).range;
      const ruleId = ruleIdData.get(diagnostic);

      // 1) Быстрое исправление (если для находки есть предложенный фикс)
      const data = fixData.get(diagnostic);
      if (data) {
        const fix = new vscode.CodeAction('Nexus: применить исправление', vscode.CodeActionKind.QuickFix);
        fix.diagnostics = [diagnostic];
        fix.isPreferred = true;
        fix.edit = new vscode.WorkspaceEdit();
        const lineText = document.lineAt(lineIdx).text;
        const indent = lineText.match(/^\s*/)?.[0] ?? '';
        const fixFirstLine = data.fix.split('\n')[0].replace(/^\s*/, '');
        fix.edit.replace(document.uri, lineRange, indent + fixFirstLine);
        actions.push(fix);
      }

      // 2) Подавление этого правила на текущей строке
      if (ruleId) {
        const lineText = document.lineAt(lineIdx).text;
        if (!/(#|\/\/|\/\*)\s*nexus:\s*ignore/i.test(lineText)) {
          const supLine = new vscode.CodeAction(
            `Nexus: игнорировать ${ruleId} на этой строке`,
            vscode.CodeActionKind.QuickFix
          );
          supLine.diagnostics = [diagnostic];
          supLine.edit = new vscode.WorkspaceEdit();
          supLine.edit.insert(document.uri, new vscode.Position(lineIdx, lineText.length),
            `  ${wrap(`nexus:ignore[${ruleId}]`)}`);
          actions.push(supLine);
        }
      }

      // 3) Подавление всех находок на строке (# nosec) — один раз на строку
      const lt = document.lineAt(lineIdx).text;
      if (!nosecDone.has(lineIdx) && !/(#|\/\/|\/\*)\s*nosec\b/i.test(lt)) {
        nosecDone.add(lineIdx);
        const supAll = new vscode.CodeAction(
          'Nexus: игнорировать все находки на этой строке (nosec)',
          vscode.CodeActionKind.QuickFix
        );
        supAll.edit = new vscode.WorkspaceEdit();
        supAll.edit.insert(document.uri, new vscode.Position(lineIdx, lt.length), `  ${wrap('nosec')}`);
        actions.push(supAll);
      }
    }

    return actions;
  }
}

// ── Страница настроек (webview) ───────────────────────────────────────────────
let settingsPanel: vscode.WebviewPanel | undefined;

// Описание всех настроек: ключ, подпись, тип, варианты
const SETTING_DEFS: Array<{
  key: string; label: string; type: 'boolean' | 'string' | 'number' | 'enum';
  options?: string[]; hint?: string;
}> = [
  { key: 'pythonPath', label: 'Путь к Python', type: 'string', hint: 'на Linux обычно python3' },
  { key: 'cliPath', label: 'Путь к cli.py', type: 'string', hint: 'пусто = искать в проекте' },
  { key: 'runOnSave', label: 'Анализ при сохранении', type: 'boolean' },
  { key: 'runOnType', label: 'Анализ при наборе', type: 'boolean' },
  { key: 'debounceMs', label: 'Задержка при наборе (мс)', type: 'number' },
  { key: 'depth', label: 'Глубина анализа', type: 'enum', options: ['1', '2', '3'], hint: '1=быстро, 2=стандарт, 3=параноик' },
  { key: 'minSeverity', label: 'Минимальный уровень', type: 'enum', options: ['critical', 'high', 'medium', 'low'] },
  { key: 'showAntipatterns', label: 'Показывать антипаттерны и сложность', type: 'boolean' },
  { key: 'refactorLevel', label: 'Глубина рефакторинга', type: 'enum', options: ['1', '2', '3'], hint: '1=безопасно, 2=стандарт, 3=агрессивно' },
  { key: 'refactorFormatBlack', label: 'Форматировать black при рефакторинге', type: 'boolean' },
  // ── Кастомизация ──
  { key: 'showRuleId', label: 'Показывать ID правила в подсказке', type: 'boolean', hint: 'напр. [PY-SSTI-001] в тексте находки' },
  { key: 'showStatusBar', label: 'Значок со счётчиком в статус-баре', type: 'boolean' },
  { key: 'showCwe', label: 'Показывать ссылку на CWE', type: 'boolean', hint: 'напр. CWE-89 для SQL-инъекции' },
];

function openSettingsPanel(context: vscode.ExtensionContext): void {
  if (settingsPanel) { settingsPanel.reveal(); return; }
  settingsPanel = vscode.window.createWebviewPanel(
    'nexusSettings', 'Nexus Security — Настройки',
    vscode.ViewColumn.Active, { enableScripts: true, retainContextWhenHidden: true }
  );
  settingsPanel.onDidDispose(() => { settingsPanel = undefined; }, null, context.subscriptions);

  const render = () => {
    const cfg = vscode.workspace.getConfiguration('nexus');
    const values: Record<string, unknown> = {};
    for (const d of SETTING_DEFS) { values[d.key] = cfg.get(d.key); }
    settingsPanel!.webview.html = settingsHtml(values);
  };
  render();

  settingsPanel.webview.onDidReceiveMessage(async (msg) => {
    const cfg = vscode.workspace.getConfiguration('nexus');
    if (msg.type === 'set') {
      let val: unknown = msg.value;
      if (msg.vtype === 'number') { val = Number(val); }
      if (msg.vtype === 'boolean') { val = Boolean(val); }
      await cfg.update(msg.key, val, vscode.ConfigurationTarget.Global);
      // Настройки, влияющие на показ находок, требуют пересканировать активный файл,
      // иначе изменение не видно до следующего сохранения/открытия.
      const display = ['minSeverity', 'showAntipatterns', 'depth', 'showRuleId', 'showCwe'];
      if (display.includes(msg.key)) {
        const editor = vscode.window.activeTextEditor;
        if (editor && isSupported(editor.document)) { void scanDocument(editor.document); }
      }
    } else if (msg.type === 'action') {
      const editor = vscode.window.activeTextEditor;
      if (msg.action === 'scanFile' && editor) { void scanDocument(editor.document, true); }
      if (msg.action === 'scanWorkspace') { void scanWorkspace(); }
      if (msg.action === 'showReport') { void vscode.commands.executeCommand('nexus.showReport'); }
      if (msg.action === 'fixFile' && editor) { void applyRefactoring(editor.document); }
      if (msg.action === 'clear') { diagnosticCollection.clear(); statusBar.hide(); }
      if (msg.action === 'vscodeSettings') {
        void vscode.commands.executeCommand('workbench.action.openSettings', 'nexus');
      }
    }
  }, null, context.subscriptions);
}

function settingsHtml(v: Record<string, unknown>): string {
  const esc = (s: unknown) => String(s ?? '').replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));

  const rows = SETTING_DEFS.map((d) => {
    const val = v[d.key];
    let control = '';
    if (d.type === 'boolean') {
      control = `<label class="switch"><input type="checkbox" data-key="${d.key}" data-vtype="boolean" ${val ? 'checked' : ''}><span class="slider"></span></label>`;
    } else if (d.type === 'enum') {
      control = `<select data-key="${d.key}" data-vtype="${(d.key === 'depth' || d.key === 'refactorLevel') ? 'number' : 'string'}">` +
        (d.options || []).map((o) => `<option value="${o}" ${String(val) === o ? 'selected' : ''}>${o}</option>`).join('') +
        `</select>`;
    } else if (d.type === 'number') {
      control = `<input type="number" data-key="${d.key}" data-vtype="number" value="${esc(val)}">`;
    } else {
      control = `<input type="text" data-key="${d.key}" data-vtype="string" value="${esc(val)}" placeholder="${esc(d.hint || '')}">`;
    }
    return `<div class="row"><div class="meta"><div class="lbl">${esc(d.label)}</div>${d.hint ? `<div class="hint">${esc(d.hint)}</div>` : ''}</div><div class="ctl">${control}</div></div>`;
  }).join('');

  return `<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><style>
    :root{--accent:#2dd4bf;--ink:var(--vscode-foreground);--bg:var(--vscode-editor-background);--border:var(--vscode-panel-border,#333);}
    *{box-sizing:border-box;margin:0;padding:0;}
    body{font-family:var(--vscode-font-family);color:var(--ink);padding:0;font-size:13px;}
    .wrap{max-width:680px;margin:0 auto;padding:28px 24px 60px;}
    .head{display:flex;align-items:center;gap:11px;margin-bottom:6px;}
    .head svg{color:var(--accent);}
    .head h1{font-size:20px;font-weight:600;}
    .sub{color:var(--vscode-descriptionForeground);font-size:12.5px;margin-bottom:26px;}
    h2{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--accent);margin:26px 0 10px;padding-bottom:7px;border-bottom:1px solid var(--border);}
    .row{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:11px 0;border-bottom:1px solid var(--border);}
    .row:last-child{border-bottom:none;}
    .lbl{font-size:13.5px;}
    .hint{font-size:11.5px;color:var(--vscode-descriptionForeground);margin-top:2px;}
    .ctl input[type=text],.ctl input[type=number],.ctl select{background:var(--vscode-input-background);color:var(--vscode-input-foreground);border:1px solid var(--vscode-input-border,var(--border));border-radius:5px;padding:5px 9px;font:inherit;min-width:180px;}
    .ctl select{min-width:120px;cursor:pointer;}
    .switch{position:relative;display:inline-block;width:40px;height:22px;}
    .switch input{opacity:0;width:0;height:0;}
    .slider{position:absolute;inset:0;background:var(--vscode-input-background);border:1px solid var(--border);border-radius:22px;cursor:pointer;transition:.2s;}
    .slider:before{content:"";position:absolute;height:14px;width:14px;left:3px;top:3px;background:var(--vscode-descriptionForeground);border-radius:50%;transition:.2s;}
    input:checked+.slider{background:var(--accent);border-color:var(--accent);}
    input:checked+.slider:before{transform:translateX(18px);background:#04221e;}
    .actions{display:flex;flex-wrap:wrap;gap:9px;margin-top:14px;}
    .btn{display:inline-flex;align-items:center;gap:7px;padding:8px 14px;border-radius:6px;font:inherit;font-size:12.5px;cursor:pointer;border:1px solid var(--border);background:transparent;color:var(--ink);}
    .btn:hover{border-color:var(--accent);color:var(--accent);}
    .btn.primary{background:var(--accent);color:#04221e;border-color:var(--accent);font-weight:600;}
    .btn.primary:hover{background:#3ee6d2;color:#04221e;}
    .saved{color:var(--accent);font-size:11.5px;opacity:0;transition:opacity .3s;margin-left:8px;}
    .saved.show{opacity:1;}
    .note{margin-top:20px;padding:12px 14px;border:1px solid var(--border);border-radius:7px;font-size:12px;color:var(--vscode-descriptionForeground);line-height:1.6;}
  </style></head><body><div class="wrap">
    <div class="head">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7z"/><path d="M9 12l2 2 4-4"/></svg>
      <h1>Nexus Security</h1><span class="saved" id="saved">сохранено</span>
    </div>
    <div class="sub">Все настройки расширения в одном месте. Изменения применяются сразу.</div>

    <h2>Движок и анализ</h2>
    ${rows}

    <h2>Действия</h2>
    <div class="actions">
      <button class="btn primary" data-act="scanFile">Анализировать файл</button>
      <button class="btn" data-act="scanWorkspace">Сканировать проект</button>
      <button class="btn" data-act="showReport">Журнал находок</button>
      <button class="btn" data-act="fixFile">Автофиксы файла</button>
      <button class="btn" data-act="clear">Очистить подсветку</button>
    </div>

    <div class="note">
      Подавление находок: наведите курсор на подчёркивание в коде и нажмите <b>Ctrl+.</b> →
      «Игнорировать правило на этой строке». Расширение само вставит комментарий
      <code>#&nbsp;nexus:ignore[ID]</code>.<br><br>
      Тема, шрифт и раскладка самого VS Code меняются в его собственных настройках:
      <button class="btn" data-act="vscodeSettings" style="margin-top:8px">Открыть настройки VS Code</button>
    </div>
  </div>
  <script>
    const vscode = acquireVsCodeApi();
    const saved = document.getElementById('saved');
    function flash(){ saved.classList.add('show'); setTimeout(()=>saved.classList.remove('show'),1200); }
    document.querySelectorAll('[data-key]').forEach(el=>{
      const ev = (el.type==='checkbox'||el.tagName==='SELECT')?'change':'input';
      el.addEventListener(ev, ()=>{
        const value = el.type==='checkbox' ? el.checked : el.value;
        vscode.postMessage({type:'set', key:el.dataset.key, vtype:el.dataset.vtype, value});
        flash();
      });
    });
    document.querySelectorAll('[data-act]').forEach(b=>{
      b.addEventListener('click', ()=> vscode.postMessage({type:'action', action:b.dataset.act}));
    });
  </script></body></html>`;
}

// ── Журнал результатов сканирования (webview) ─────────────────────────────────
function openScanReport(context: vscode.ExtensionContext): void {
  if (!lastScan) { return; }
  if (!scanReportPanel) {
    scanReportPanel = vscode.window.createWebviewPanel(
      'nexusScanReport', 'Nexus — Журнал находок',
      vscode.ViewColumn.Active, { enableScripts: true, retainContextWhenHidden: true }
    );
    scanReportPanel.onDidDispose(() => { scanReportPanel = undefined; }, null, context.subscriptions);
    scanReportPanel.webview.onDidReceiveMessage((msg) => {
      if (msg.type === 'open') {
        vscode.commands.executeCommand('nexus.jumpTo', msg.file, msg.line);
      }
    }, null, context.subscriptions);
  }
  scanReportPanel.webview.html = scanReportHtml(lastScan);
  scanReportPanel.reveal();
}

interface ReportItem {
  file: string; line: number; severity: string; title: string; kind: string; rule: string;
}

function scanReportHtml(scan: { at: Date; results: NexusResult[]; total: number }): string {
  const esc = (s: unknown) => String(s ?? '').replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));

  // Собираем плоский список всех находок
  const items: ReportItem[] = [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of scan.results) {
    for (const f of (r.findings || [])) {
      items.push({ file: r.filename, line: f.line, severity: f.severity, title: f.title, kind: 'Безопасность', rule: f.cwe || f.rule_id || '' });
      if (f.severity in counts) { (counts as Record<string, number>)[f.severity]++; }
    }
    for (const a of (r.antipatterns || [])) {
      items.push({ file: r.filename, line: a.line, severity: a.severity, title: a.title, kind: 'Качество', rule: a.id || '' });
      if (a.severity in counts) { (counts as Record<string, number>)[a.severity]++; }
    }
    for (const fn of (r.functions || [])) {
      if (fn.issues && fn.issues.length) {
        items.push({ file: r.filename, line: fn.line, severity: 'low', title: `Функция «${fn.name}»: ${fn.issues[0]}`, kind: 'Сложность', rule: 'COMPLEXITY' });
        counts.low++;
      }
    }
  }

  const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  items.sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9) || a.file.localeCompare(b.file) || a.line - b.line);

  const base = (p: string) => p.split('/').pop() || p;
  const sevColor: Record<string, string> = { critical: '#f14c4c', high: '#cca700', medium: '#3794ff', low: '#888' };

  const rows = items.map((it) => `
    <div class="row" data-file="${esc(it.file)}" data-line="${it.line}">
      <span class="dot" style="background:${sevColor[it.severity] || '#888'}"></span>
      <span class="sev" style="color:${sevColor[it.severity] || '#888'}">${esc(it.severity)}</span>
      <span class="title">${esc(it.title)}</span>
      <span class="kind">${esc(it.kind)}</span>
      <span class="rule">${esc(it.rule)}</span>
      <span class="loc">${esc(base(it.file))}:${it.line}</span>
    </div>`).join('');

  const when = scan.at.toLocaleString('ru-RU');
  return `<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><style>
    :root{--accent:#2dd4bf;--ink:var(--vscode-foreground);--border:var(--vscode-panel-border,#333);--muted:var(--vscode-descriptionForeground);}
    *{box-sizing:border-box;margin:0;padding:0;}
    body{font-family:var(--vscode-font-family);color:var(--ink);font-size:13px;}
    .wrap{padding:20px 22px 60px;}
    .head{display:flex;align-items:center;gap:10px;margin-bottom:4px;}
    .head svg{color:var(--accent);}
    .head h1{font-size:18px;font-weight:600;}
    .sub{color:var(--muted);font-size:12px;margin-bottom:16px;}
    .stats{display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap;}
    .chip{padding:5px 11px;border-radius:6px;border:1px solid var(--border);font-size:12px;display:flex;gap:7px;align-items:center;}
    .chip b{font-size:13px;}
    .filterbar{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap;}
    .fbtn{padding:3px 10px;border-radius:5px;border:1px solid var(--border);background:transparent;color:var(--muted);font:inherit;font-size:11.5px;cursor:pointer;}
    .fbtn.on,.fbtn:hover{border-color:var(--accent);color:var(--accent);}
    .row{display:grid;grid-template-columns:14px 64px 1fr auto auto auto;gap:10px;align-items:center;padding:7px 10px;border-bottom:1px solid var(--border);cursor:pointer;}
    .row:hover{background:var(--vscode-list-hoverBackground,#2a2d2e);}
    .dot{width:8px;height:8px;border-radius:50%;}
    .sev{font-size:11px;text-transform:uppercase;letter-spacing:.04em;}
    .title{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
    .kind{font-size:11px;color:var(--muted);padding:1px 7px;border:1px solid var(--border);border-radius:10px;}
    .rule{font-family:var(--vscode-editor-font-family,monospace);font-size:11px;color:var(--muted);}
    .loc{font-family:var(--vscode-editor-font-family,monospace);font-size:11px;color:var(--accent);}
    .empty{padding:40px;text-align:center;color:var(--muted);}
  </style></head><body><div class="wrap">
    <div class="head">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7z"/></svg>
      <h1>Журнал находок</h1>
    </div>
    <div class="sub">${esc(scan.results.length)} файлов · ${esc(scan.total)} проблем · ${esc(when)}</div>
    <div class="stats">
      <span class="chip"><b style="color:#f14c4c">${counts.critical}</b> critical</span>
      <span class="chip"><b style="color:#cca700">${counts.high}</b> high</span>
      <span class="chip"><b style="color:#3794ff">${counts.medium}</b> medium</span>
      <span class="chip"><b style="color:#888">${counts.low}</b> low</span>
    </div>
    <div class="filterbar">
      <button class="fbtn on" data-f="all">Все</button>
      <button class="fbtn" data-f="critical">Critical</button>
      <button class="fbtn" data-f="high">High</button>
      <button class="fbtn" data-f="medium">Medium</button>
      <button class="fbtn" data-f="low">Low</button>
    </div>
    <div id="list">${rows || '<div class="empty">Проблем не найдено — проект чист.</div>'}</div>
  </div>
  <script>
    const vscode = acquireVsCodeApi();
    document.querySelectorAll('.row').forEach(r=>{
      r.addEventListener('click', ()=> vscode.postMessage({type:'open', file:r.dataset.file, line:Number(r.dataset.line)}));
    });
    document.querySelectorAll('.fbtn').forEach(b=>{
      b.addEventListener('click', ()=>{
        document.querySelectorAll('.fbtn').forEach(x=>x.classList.remove('on'));
        b.classList.add('on');
        const f=b.dataset.f;
        document.querySelectorAll('.row').forEach(r=>{
          const sev=r.querySelector('.sev').textContent.trim();
          r.style.display = (f==='all'||sev===f)?'':'none';
        });
      });
    });
  </script></body></html>`;
}
