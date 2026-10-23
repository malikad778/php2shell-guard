#!/usr/bin/env php
<?php
/*
 * php2shell-guard PHAR compiler script (bin/build-phar.php)
 * Builds standalone, zero-dependency executable PHAR archive.
 */

if (ini_get('phar.readonly') && ini_get('phar.readonly') !== '0') {
    echo "Warning: phar.readonly is 1. If building fails, run with: php -d phar.readonly=0 bin/build-phar.php\n";
}

$pharPath = dirname(__DIR__) . '/php2shell-guard.phar';
if (file_exists($pharPath)) {
    @unlink($pharPath);
}

try {
    $phar = new Phar($pharPath, 0, 'php2shell-guard.phar');
    $phar->startBuffering();

    $rootDir = realpath(dirname(__DIR__));
    $dirsToInclude = array('src', 'data', 'templates');

    foreach ($dirsToInclude as $sub) {
        $fullSub = $rootDir . DIRECTORY_SEPARATOR . $sub;
        if (!is_dir($fullSub)) continue;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($fullSub, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $filePath = $file->getPathname();
                $relPath = str_replace($rootDir . DIRECTORY_SEPARATOR, '', $filePath);
                $relPath = str_replace('\\', '/', $relPath);
                $phar->addFile($filePath, $relPath);
            }
        }
    }

    $stub = <<<'STUB'
#!/usr/bin/env php
<?php
Phar::mapPhar('php2shell-guard.phar');
require_once 'phar://php2shell-guard.phar/src/Autoloader.php';
$app = new \Malikad\Php2ShellGuard\Cli\Application();
exit($app->run($argv));
__HALT_COMPILER();
STUB;

    $phar->setStub($stub);
    $phar->stopBuffering();

    chmod($pharPath, 0755);
    echo "Successfully generated php2shell-guard.phar (" . filesize($pharPath) . " bytes).\n";
} catch (Exception $e) {
    echo "Notice: Could not compile PHAR in current environment (" . $e->getMessage() . ").\n";
    echo "Use 'php -d phar.readonly=0 bin/build-phar.php' to build PHAR.\n";
}
