<?php

namespace Malikad\Php2ShellGuard\Report;

class Html
{
    public function render(array $reportData, array $options = array())
    {
        $brandName = isset($options['brand_name']) && !empty($options['brand_name']) ? htmlspecialchars($options['brand_name'], ENT_QUOTES, 'UTF-8') : 'php2shell-guard';
        $brandLogo = isset($options['brand_logo']) && !empty($options['brand_logo']) ? $options['brand_logo'] : null;
        $brandContact = isset($options['brand_contact']) && !empty($options['brand_contact']) ? htmlspecialchars($options['brand_contact'], ENT_QUOTES, 'UTF-8') : null;
        $noCta = !empty($options['no_cta']);

        $host = htmlspecialchars(isset($reportData['host']) ? $reportData['host'] : (isset($reportData['target']) ? $reportData['target'] : 'localhost'), ENT_QUOTES, 'UTF-8');
        $dbDate = htmlspecialchars(isset($reportData['advisory_db_date']) ? $reportData['advisory_db_date'] : '2026-10-23', ENT_QUOTES, 'UTF-8');
        $toolVersion = htmlspecialchars(isset($reportData['version']) ? $reportData['version'] : '0.3.1', ENT_QUOTES, 'UTF-8');
        $runtimes = isset($reportData['runtimes']) && is_array($reportData['runtimes']) ? $reportData['runtimes'] : array();
        $indicators = htmlspecialchars(isset($reportData['indicators']['status']) ? $reportData['indicators']['status'] : 'no indicator found in the logs available (rotation and retention limits apply)', ENT_QUOTES, 'UTF-8');
        $iocCount = isset($reportData['indicators']['count']) ? (int) $reportData['indicators']['count'] : 0;

        $patchedCount = 0;
        $vulnCount = 0;
        $eolCount = 0;
        $unknownCount = 0;

        foreach ($runtimes as $rt) {
            $st = isset($rt['status']) ? $rt['status'] : 'UNKNOWN';
            if ($st === 'PATCHED' || $st === 'PATCHED_BACKPORT') {
                $patchedCount++;
            } elseif ($st === 'VULNERABLE_PATCH_AVAILABLE' || $st === 'PATCHED_NOT_RESTARTED') {
                $vulnCount++;
            } elseif ($st === 'EOL_NO_OFFICIAL_RELEASE') {
                $eolCount++;
            } else {
                $unknownCount++;
            }
        }

        ob_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $brandName; ?> - Security Exposure & Audit Report</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --muted: #94a3b8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --info: #38bdf8;
            --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }
        @media print {
            body { background: #fff !important; color: #000 !important; }
            .card { border: 1px solid #ccc !important; background: #fff !important; }
            .no-print { display: none !important; }
        }
        body {
            margin: 0;
            padding: 24px;
            font-family: var(--font);
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 28px;
        }
        .brand-title {
            font-size: 24px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .brand-logo {
            max-height: 40px;
        }
        .meta-badges {
            display: flex;
            gap: 10px;
            font-size: 13px;
        }
        .meta-badge {
            background: var(--surface);
            border: 1px solid var(--border);
            padding: 4px 10px;
            border-radius: 6px;
            color: var(--muted);
        }
        .grid-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }
        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }
        .stat-val {
            font-size: 28px;
            font-weight: 800;
            margin-bottom: 4px;
        }
        .stat-lbl {
            font-size: 13px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }
        h2 {
            font-size: 18px;
            margin-top: 0;
            margin-bottom: 16px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--border);
        }
        th {
            color: var(--muted);
            font-weight: 600;
            background: rgba(0,0,0,0.15);
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge-danger { background: rgba(239,68,68,0.2); color: #fca5a5; border: 1px solid rgba(239,68,68,0.4); }
        .badge-warning { background: rgba(245,158,11,0.2); color: #fde68a; border: 1px solid rgba(245,158,11,0.4); }
        .badge-success { background: rgba(16,185,129,0.2); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.4); }
        .badge-info { background: rgba(56,189,248,0.2); color: #bae6fd; border: 1px solid rgba(56,189,248,0.4); }
        .alert {
            padding: 14px 18px;
            border-radius: 6px;
            margin-bottom: 16px;
            font-size: 14px;
        }
        .alert-warning {
            background: rgba(245,158,11,0.1);
            border-left: 4px solid var(--warning);
            color: #fde68a;
        }
        .alert-danger {
            background: rgba(239,68,68,0.1);
            border-left: 4px solid var(--danger);
            color: #fca5a5;
        }
        .alert-info {
            background: rgba(56,189,248,0.1);
            border-left: 4px solid var(--info);
            color: #bae6fd;
        }
        footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            text-align: center;
            font-size: 13px;
            color: var(--muted);
        }
        footer a { color: var(--info); text-decoration: none; }
        footer a:hover { text-decoration: underline; }
    </style>
</head>
<body>
<div class="container">
    <header>
        <div>
            <div class="brand-title">
                <?php if ($brandLogo): ?>
                    <img src="<?php echo htmlspecialchars($brandLogo, ENT_QUOTES, 'UTF-8'); ?>" alt="Logo" class="brand-logo" />
                <?php endif; ?>
                <span><?php echo $brandName; ?> Audit Report</span>
            </div>
            <div style="font-size:13px; color:var(--muted); margin-top:4px;">
                Target Host: <strong><?php echo $host; ?></strong>
                <?php if ($brandContact): ?> | Contact: <strong><?php echo $brandContact; ?></strong><?php endif; ?>
            </div>
        </div>
        <div class="meta-badges">
            <span class="meta-badge">DB: <?php echo $dbDate; ?></span>
            <span class="meta-badge">v<?php echo $toolVersion; ?></span>
        </div>
    </header>

    <div class="grid-stats">
        <div class="stat-card">
            <div class="stat-val" style="color:var(--danger);"><?php echo $vulnCount; ?></div>
            <div class="stat-lbl">Vulnerable / Not Restarted</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color:var(--warning);"><?php echo $eolCount; ?></div>
            <div class="stat-lbl">EOL Runtimes</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color:var(--success);"><?php echo $patchedCount; ?></div>
            <div class="stat-lbl">Patched Upstreams</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color:<?php echo $iocCount > 0 ? 'var(--danger)' : 'var(--info)'; ?>;"><?php echo $iocCount; ?></div>
            <div class="stat-lbl">Compromise Indicators</div>
        </div>
    </div>

    <div class="card">
        <h2>Executive Summary & Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Component</th>
                    <th>Traffic</th>
                    <th>Detected Version</th>
                    <th>Status</th>
                    <th>Fixed Release</th>
                    <th>Advisories</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($runtimes as $rt):
                $st = isset($rt['status']) ? $rt['status'] : 'UNKNOWN';
                $badgeClass = 'badge-info';
                if ($st === 'VULNERABLE_PATCH_AVAILABLE' || $st === 'PATCHED_NOT_RESTARTED') {
                    $badgeClass = 'badge-danger';
                } elseif ($st === 'EOL_NO_OFFICIAL_RELEASE' || $st === 'UNKNOWN_BACKPORT_POSSIBLE') {
                    $badgeClass = 'badge-warning';
                } elseif ($st === 'PATCHED' || $st === 'PATCHED_BACKPORT') {
                    $badgeClass = 'badge-success';
                }
                $cves = isset($rt['cves']) && is_array($rt['cves']) ? implode(', ', $rt['cves']) : '-';
            ?>
                <tr>
                    <td><strong><?php echo htmlspecialchars(isset($rt['component']) ? $rt['component'] : 'unknown', ENT_QUOTES, 'UTF-8'); ?></strong></td>
                    <td><?php echo !empty($rt['serves_traffic']) ? '<span style="color:var(--danger);font-weight:600;">Yes</span>' : '<span style="color:var(--muted);">No</span>'; ?></td>
                    <td><code><?php echo htmlspecialchars(isset($rt['detected_version']) ? $rt['detected_version'] : 'none', ENT_QUOTES, 'UTF-8'); ?></code></td>
                    <td><span class="badge <?php echo $badgeClass; ?>"><?php echo htmlspecialchars($st, ENT_QUOTES, 'UTF-8'); ?></span></td>
                    <td><code><?php echo htmlspecialchars(isset($rt['fixed_version']) ? $rt['fixed_version'] : 'none', ENT_QUOTES, 'UTF-8'); ?></code></td>
                    <td><small><?php echo htmlspecialchars($cves, ENT_QUOTES, 'UTF-8'); ?></small></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Compromise Indicators (IOC Log & Process Audit)</h2>
        <div class="alert <?php echo $iocCount > 0 ? 'alert-danger' : 'alert-info'; ?>">
            <strong>Indicator Status:</strong> <?php echo $indicators; ?>
        </div>
        <p style="font-size:13px; color:var(--muted); margin:0;">
            Note: Absence of log indicators does not prove absence of compromise. Attackers exploiting memory corruption may bypass standard application error logging. If compromise is suspected, preserve volatile system state prior to service restart.
        </p>
    </div>

    <div class="card">
        <h2>Remediation Plan & Engineering Effort</h2>
        <div class="alert alert-warning">
            <strong>Mandatory Rule:</strong> Stopgaps reduce exposure only. Patching packages to >= 8.2.35, 8.3.36, 8.4.27, or 8.5.12 and <em>restarting every web worker</em> is the only complete mitigation.
        </div>
        <ol style="font-size:14px; padding-left:20px;">
            <li><strong>Step 1: Emergency Exposure Reduction</strong> - Apply administrative INI/FPM directives (`memory_limit=-1`, `session.upload_progress.enabled=0`).</li>
            <li><strong>Step 2: Upstream Patching</strong> - Update system packages or base Dockerfile images to patched upstream releases.</li>
            <li><strong>Step 3: Worker Restart & Image Rebuild</strong> - Old workers maintain vulnerable state in memory until restarted (`systemctl restart php-fpm`, `docker compose up -d --build`).</li>
        </ol>
    </div>

    <?php if (!$noCta): ?>
    <footer>
        Need emergency patching or a controlled PHP migration? <a href="https://github.com/malikad778/php2shell-guard?utm_source=html_report" target="_blank">Contact <?php echo $brandName; ?> Engineering</a>
    </footer>
    <?php endif; ?>
</div>
</body>
</html>
<?php
        return ob_get_clean();
    }
}
