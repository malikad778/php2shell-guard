<?php

require_once __DIR__ . '/../src/Autoloader.php';
require_once __DIR__ . '/Unit/VersionComparatorTest.php';
require_once __DIR__ . '/Unit/ConfigAuditTest.php';
require_once __DIR__ . '/Unit/IndicatorScannerTest.php';
require_once __DIR__ . '/Unit/ConfigApplierTest.php';
require_once __DIR__ . '/Unit/ReportRenderersTest.php';
require_once __DIR__ . '/Unit/BackportEngineTest.php';
require_once __DIR__ . '/Integration/ProjectScanTest.php';

$tests = array(
    new \Malikad\Php2ShellGuard\Tests\Unit\VersionComparatorTest(),
    new \Malikad\Php2ShellGuard\Tests\Unit\ConfigAuditTest(),
    new \Malikad\Php2ShellGuard\Tests\Unit\IndicatorScannerTest(),
    new \Malikad\Php2ShellGuard\Tests\Unit\ConfigApplierTest(),
    new \Malikad\Php2ShellGuard\Tests\Unit\ReportRenderersTest(),
    new \Malikad\Php2ShellGuard\Tests\Unit\BackportEngineTest(),
    new \Malikad\Php2ShellGuard\Tests\Integration\ProjectScanTest(),
);

foreach ($tests as $test) {
    $test->run();
}

echo "All PHP unit and integration tests passed.\n";
