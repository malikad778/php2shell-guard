<?php

namespace Malikad\Php2ShellGuard\Fleet;

class Ssh
{
    private $whitelistCommands = array(
        'php -v',
        'php-fpm -v',
        'node -v',
        'ps -eo pid,ppid,comm,args',
        'audit.sh scan --format json --no-cta'
    );

    public function getReadOnlyCommands()
    {
        return $this->whitelistCommands;
    }

    public function scanHost($host, $remoteCommand = null, $sshOptions = array())
    {
        $cmdToRun = $remoteCommand ?: 'audit.sh scan --format json --no-cta';
        $port = isset($sshOptions['port']) ? (int) $sshOptions['port'] : 22;
        $user = isset($sshOptions['user']) ? $sshOptions['user'] . '@' : '';
        $timeout = isset($sshOptions['timeout']) ? (int) $sshOptions['timeout'] : 8;

        $target = $user . $host;
        $sshCmd = sprintf(
            'ssh -p %d -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=%d %s %s 2>&1',
            $port,
            $timeout,
            escapeshellarg($target),
            escapeshellarg($cmdToRun)
        );

        $output = array();
        $ret = 0;
        @exec($sshCmd, $output, $ret);
        $rawOutput = implode("\n", $output);

        $json = json_decode($rawOutput, true);
        if ($json && isset($json['runtimes'])) {
            return array(
                'host' => $host,
                'success' => true,
                'exit_code' => $ret,
                'data' => $json
            );
        }

        return array(
            'host' => $host,
            'success' => ($ret === 0),
            'exit_code' => $ret,
            'raw_output' => $rawOutput
        );
    }

    public function scanHosts(array $hosts, $remoteCommand = null, $sshOptions = array())
    {
        $results = array();
        foreach ($hosts as $host) {
            $h = trim($host);
            if ($h === '' || $h[0] === '#') {
                continue;
            }
            $results[$h] = $this->scanHost($h, $remoteCommand, $sshOptions);
        }
        return $results;
    }
}
