<?php

namespace Malikad\Php2ShellGuard\Detect;

class StaleWorkerDetector
{
    public function hasStaleWorkers($procLinks = array(), array $context = array())
    {
        $res = $this->detectStaleWorkers($procLinks, $context);
        return $res['is_stale'];
    }

    public function detectStaleWorkers($procLinks = array(), array $context = array())
    {
        if (getenv('PHP2SHELL_MOCK_STALE_WORKER') === '1') {
            return array(
                'is_stale' => true,
                'reason' => 'Mock environment flag PHP2SHELL_MOCK_STALE_WORKER=1',
                'evidence' => 'env:PHP2SHELL_MOCK_STALE_WORKER'
            );
        }

        // 1. Check /proc/*/exe (deleted) links
        foreach ($procLinks as $linkTarget) {
            if (strpos($linkTarget, '(deleted)') !== false) {
                return array(
                    'is_stale' => true,
                    'reason' => 'Process executable link marked deleted on disk (/proc/*/exe -> (deleted))',
                    'evidence' => $linkTarget
                );
            }
        }

        // 2. Check needrestart -b if available
        if (function_exists('exec') && PHP_OS_FAMILY === 'Linux') {
            $nrOut = @shell_exec('command -v needrestart >/dev/null 2>&1 && needrestart -b 2>/dev/null');
            if ($nrOut && (strpos($nrOut, 'NEEDRESTART-SVC: php') !== false || strpos($nrOut, 'NEEDRESTART-SVC: apache') !== false || strpos($nrOut, 'NEEDRESTART-SVC: nginx') !== false)) {
                return array(
                    'is_stale' => true,
                    'reason' => 'needrestart reported pending web worker restart',
                    'evidence' => trim($nrOut)
                );
            }
        }

        // 3. Process start time vs binary modification time
        if (isset($context['process_start_time']) && isset($context['binary_mtime'])) {
            if ($context['process_start_time'] < $context['binary_mtime']) {
                return array(
                    'is_stale' => true,
                    'reason' => 'Process was started before the current binary on disk was installed/modified',
                    'evidence' => "process_start={$context['process_start_time']} < binary_mtime={$context['binary_mtime']}"
                );
            }
        }

        // 4. Container running older image ID than current tag
        if (isset($context['container_image_id']) && isset($context['latest_image_id'])) {
            if ($context['container_image_id'] !== $context['latest_image_id']) {
                return array(
                    'is_stale' => true,
                    'reason' => 'Container is running an older image ID than the current image tag ID on host',
                    'evidence' => "running={$context['container_image_id']} != tag={$context['latest_image_id']}"
                );
            }
        }

        // 5. Inspect real /proc on Linux if procLinks was empty
        if (empty($procLinks) && is_dir('/proc')) {
            $glob = @glob('/proc/[0-9]*/exe');
            if ($glob) {
                foreach ($glob as $exe) {
                    $target = @readlink($exe);
                    if ($target && strpos($target, '(deleted)') !== false) {
                        if (preg_match('/(php|node|apache|httpd|frankenphp)/i', $target)) {
                            return array(
                                'is_stale' => true,
                                'reason' => 'Live worker process executable link is marked (deleted) on disk',
                                'evidence' => "{$exe} -> {$target}"
                            );
                        }
                    }
                }
            }
        }

        return array(
            'is_stale' => false,
            'reason' => 'No stale worker processes or deleted binary links detected',
            'evidence' => 'proc:clean'
        );
    }
}
