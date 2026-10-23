<?php

namespace Malikad\Php2ShellGuard\Ioc;

class IndicatorScanner
{
    public function scanLogText($logText)
    {
        $hits = array();
        $lines = preg_split('/\r?\n/', (string) $logText);
        foreach ($lines as $idx => $line) {
            if (preg_match('/Allowed memory size of [0-9]+ bytes exhausted \(tried to allocate ([0-9]+) bytes\) in Unknown on line 0/i', $line, $m)) {
                $hits[] = array(
                    'id' => 'IOC1_UNKNOWN_LINE_0_OOM',
                    'line' => $idx + 1,
                    'allocated_bytes' => (int) $m[1],
                    'evidence' => trim($line)
                );
            }
            if (preg_match('/AH00052:.*child pid [0-9]+ exit signal Segmentation fault \(11\)/i', $line)) {
                $hits[] = array(
                    'id' => 'IOC2_APACHE_AH00052_SEGFAULT',
                    'line' => $idx + 1,
                    'evidence' => trim($line)
                );
            }
        }

        $statusText = count($hits) > 0
            ? 'indicator found (' . count($hits) . ' match(es); preserve volatile evidence before restarting workers)'
            : 'no indicator found in the logs available (rotation and retention limits apply)';

        return array(
            'indicators_found' => count($hits) > 0,
            'count' => count($hits),
            'status' => $statusText,
            'hits' => $hits
        );
    }

    public function scanProcessTree($psText)
    {
        $hits = array();
        $lines = preg_split('/\r?\n/', (string) $psText);
        foreach ($lines as $idx => $line) {
            if (preg_match('/(php-fpm|apache2|httpd|frankenphp|lsphp|php-cgi).*(?:\s|\/)(sh|bash|dash|nc|ncat|curl|wget|python[23]?)\b/i', $line)) {
                $hits[] = array(
                    'id' => 'IOC4_WEB_WORKER_CHILD_SHELL',
                    'line' => $idx + 1,
                    'evidence' => trim($line)
                );
            }
        }
        return $hits;
    }

    public function scanPath($targetPath = '.')
    {
        $discovery = new LogDiscovery();
        $logs = $discovery->discover($targetPath);
        $allHits = array();
        $logsInspected = 0;

        foreach ($logs as $logFile) {
            if (is_file($logFile) && is_readable($logFile)) {
                $logsInspected++;
                $content = @file_get_contents($logFile);
                if ($content !== false) {
                    $res = $this->scanLogText($content);
                    foreach ($res['hits'] as $hit) {
                        $hit['file'] = $logFile;
                        $allHits[] = $hit;
                    }
                }
            }
        }

        // Check running processes if ps available
        $procHits = array();
        if (function_exists('exec') && (PHP_OS_FAMILY === 'Linux' || PHP_OS_FAMILY === 'Darwin' || PHP_OS_FAMILY === 'BSD')) {
            $psOutput = @shell_exec('ps -eo pid,ppid,comm,args 2>/dev/null');
            if (!empty($psOutput)) {
                $procHits = $this->scanProcessTree($psOutput);
                foreach ($procHits as $ph) {
                    $allHits[] = $ph;
                }
            }
        }

        $totalCount = count($allHits);
        if ($totalCount > 0) {
            $statusText = 'indicator found (' . $totalCount . ' match(es) across ' . $logsInspected . ' log(s); preserve volatile evidence before restarting workers)';
        } elseif ($logsInspected > 0) {
            $statusText = 'no indicator found in the ' . $logsInspected . ' log(s) available (rotation and retention limits apply)';
        } else {
            $statusText = 'no indicator found in the logs available (0 logs discovered in standard paths; rotation and retention limits apply)';
        }

        return array(
            'indicators_found' => $totalCount > 0,
            'count' => $totalCount,
            'logs_inspected' => $logsInspected,
            'status' => $statusText,
            'hits' => $allHits
        );
    }
}

