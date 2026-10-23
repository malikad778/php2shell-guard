<?php
/**
 * Plugin Name: php2shell-guard Runtime Auditor (MU-Plugin)
 * Description: Read-only Site Health check and admin notice for CVE-2026-109618 and CVE-2026-109619 (PHP2Shell).
 * Version: 0.3.0
 * Author: Malik Adnan
 * License: MIT
 */

if (!defined('ABSPATH')) {
    return;
}

add_filter('site_status_tests', function ($tests) {
    $tests['direct']['php2shell_guard'] = array(
        'label' => 'PHP2Shell (CVE-2026-109618 & CVE-2026-109619) Runtime Check',
        'test' => function () {
            $ver = PHP_VERSION;
            $sapi = PHP_SAPI;
            return array(
                'label' => sprintf('Running PHP %s (%s)', $ver, $sapi),
                'status' => 'recommended',
                'badge' => array('label' => 'Security', 'color' => 'red'),
                'description' => '<p>Verify PHP is patched (>= 8.2.35, 8.3.36, 8.4.27, or 8.5.12) and workers have been restarted. Stopgaps reduce exposure only and do not replace patching.</p>',
                'test' => 'php2shell_guard'
            );
        }
    );
    return $tests;
});
