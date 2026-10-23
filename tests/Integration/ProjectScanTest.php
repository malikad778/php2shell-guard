<?php

namespace Malikad\Php2ShellGuard\Tests\Integration;

use Malikad\Php2ShellGuard\Project\DockerfileScanner;

class ProjectScanTest
{
    public function run()
    {
        $scanner = new DockerfileScanner();
        $vulnDf = file_get_contents(__DIR__ . '/../fixtures/Dockerfile.vulnerable');
        $findings = $scanner->scan($vulnDf);
        if (count($findings) !== 1 || !$findings[0]['digest_pinned']) {
            throw new \RuntimeException('Expected 1 digest-pinned finding on Dockerfile.vulnerable');
        }
        return true;
    }
}
