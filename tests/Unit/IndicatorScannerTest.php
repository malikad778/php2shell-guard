<?php

namespace Malikad\Php2ShellGuard\Tests\Unit;

use Malikad\Php2ShellGuard\Ioc\IndicatorScanner;

class IndicatorScannerTest
{
    public function run()
    {
        $scanner = new IndicatorScanner();
        $errLog = file_get_contents(__DIR__ . '/../fixtures/php-error.log');
        $res = $scanner->scanLogText($errLog);
        if (!$res['indicators_found'] || $res['count'] !== 1) {
            throw new \RuntimeException('Expected IOC1 match on php-error.log fixture');
        }
        if (stripos($res['status'], 'clean') !== false || stripos($res['status'], 'safe') !== false) {
            throw new \RuntimeException('IOC status must never say clean or safe');
        }

        // Test scanPath on clean repository root (must not hit fixtures)
        $cleanPathRes = $scanner->scanPath(__DIR__ . '/../..');
        if ($cleanPathRes['indicators_found'] || $cleanPathRes['count'] > 0) {
            throw new \RuntimeException('scanPath on repo root unexpectedly matched fixtures: ' . json_encode($cleanPathRes));
        }
        if (stripos($cleanPathRes['status'], 'clean') !== false || stripos($cleanPathRes['status'], 'safe') !== false) {
            throw new \RuntimeException('IOC status must never say clean or safe');
        }

        // Test scanPath on explicit fixture log file
        $fixtureRes = $scanner->scanPath(__DIR__ . '/../fixtures/php-error.log');
        if (!$fixtureRes['indicators_found'] || $fixtureRes['count'] !== 1) {
            throw new \RuntimeException('scanPath failed to detect IOC on php-error.log fixture');
        }

        return true;
    }
}

