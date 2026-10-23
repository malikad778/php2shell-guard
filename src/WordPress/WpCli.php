<?php

namespace Malikad\Php2ShellGuard\WordPress;

use Malikad\Php2ShellGuard\Support\VersionComparator;

class WpCli
{
    public function status()
    {
        return VersionComparator::evaluatePhp(PHP_VERSION);
    }
}
