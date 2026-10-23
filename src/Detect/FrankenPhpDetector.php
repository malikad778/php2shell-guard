<?php

namespace Malikad\Php2ShellGuard\Detect;

class FrankenPhpDetector
{
    public function getRiskRanking()
    {
        return array(
            'sapi' => 'frankenphp',
            'risk' => 'high',
            'reason' => 'Source analysis indicates FrankenPHP request initialization behavior is similar to Apache mod_php.'
        );
    }
}
