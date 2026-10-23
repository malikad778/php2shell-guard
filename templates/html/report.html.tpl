<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{TITLE}} - Runtime Exposure &amp; Remediation Report</title>
  <style>
    :root {
      --bg: #f8fafc;
      --card: #ffffff;
      --text: #0f172a;
      --muted: #475569;
      --border: #e2e8f0;
      --accent: #0f766e;
      --crit: #b91c1c;
      --crit-bg: #fef2f2;
      --warn: #b45309;
      --warn-bg: #fffbeb;
      --ok: #15803d;
      --ok-bg: #f0fdf4;
    }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 32px 16px; line-height: 1.5; }
    .container { max-width: 1040px; margin: 0 auto; }
    header { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 24px; margin-bottom: 24px; }
    h1 { margin: 0 0 8px 0; font-size: 24px; }
    h2 { font-size: 18px; margin-top: 28px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
    .meta { color: var(--muted); font-size: 14px; }
    .notice { background: var(--warn-bg); border-left: 4px solid var(--warn); padding: 12px 16px; border-radius: 4px; margin: 16px 0; font-size: 14px; }
    table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 20px; }
    th, td { text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--border); font-size: 14px; vertical-align: top; }
    th { background: #f1f5f9; font-weight: 600; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; font-family: monospace; }
    .badge-ok { background: var(--ok-bg); color: var(--ok); }
    .badge-vuln { background: var(--crit-bg); color: var(--crit); }
    .badge-warn { background: var(--warn-bg); color: var(--warn); }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
    pre { background: #0f172a; color: #f8fafc; padding: 14px; border-radius: 6px; overflow-x: auto; }
    footer { margin-top: 32px; padding: 20px; background: var(--card); border: 1px solid var(--border); border-radius: 8px; font-size: 14px; color: var(--muted); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>{{BRAND_NAME}} Runtime Exposure &amp; Remediation Report</h1>
      <div class="meta">Generated: {{GENERATED_AT}} | Advisory DB: {{DB_DATE}} | Mode: Read-Only Audit</div>
      <div class="notice">
        <strong>Scope &amp; Honest Limitations:</strong> This report classifies detected runtimes as PATCHED, PATCHED_BACKPORT, PATCHED_NOT_RESTARTED, VULNERABLE_PATCH_AVAILABLE, EOL_NO_OFFICIAL_RELEASE, UNKNOWN_BACKPORT_POSSIBLE, or UNKNOWN. It never claims a host is "safe", "clean", or "not compromised". Configuration mitigations reduce exposure while an upgrade is prepared; patching and restarting all workers is the only complete defense.
      </div>
    </header>
    {{CONTENT}}
    {{CTA_FOOTER}}
  </div>
</body>
</html>
