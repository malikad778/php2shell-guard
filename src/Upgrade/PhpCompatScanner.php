<?php

namespace Malikad\Php2ShellGuard\Upgrade;

class PhpCompatScanner
{
    public function getCommand($targetPhp = '8.3', $path = '.')
    {
        return sprintf('vendor/bin/phpcs -p %s --standard=PHPCompatibility --runtime-set testVersion %s-', escapeshellarg($path), escapeshellarg($targetPhp));
    }

    public function runScan($projectPath = '.', $targetPhp = '8.3')
    {
        $bin = rtrim($projectPath, '/\\') . '/vendor/bin/phpcs';
        if (file_exists($bin) && is_executable($bin) && function_exists('exec')) {
            $cmd = sprintf('%s -p %s --standard=PHPCompatibility --runtime-set testVersion %s- --report=json 2>/dev/null', escapeshellarg($bin), escapeshellarg($projectPath), escapeshellarg($targetPhp));
            $output = array();
            $ret = 0;
            @exec($cmd, $output, $ret);
            $raw = implode("\n", $output);
            $json = json_decode($raw, true);
            if ($json && isset($json['totals'])) {
                return array(
                    'executed' => true,
                    'errors' => $json['totals']['errors'],
                    'warnings' => $json['totals']['warnings'],
                    'files' => $json['files']
                );
            }
        }

        return array(
            'executed' => false,
            'command' => $this->getCommand($targetPhp, $projectPath),
            'note' => "PHPCompatibility standard can be run via: " . $this->getCommand($targetPhp, $projectPath)
        );
    }
}
