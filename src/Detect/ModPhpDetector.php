<?php

namespace Malikad\Php2ShellGuard\Detect;

class ModPhpDetector
{
    public function getRiskRanking()
    {
        return array(
            'sapi' => 'mod_php',
            'risk' => 'highest',
            'reason' => 'PHP advisory rates risk highest for Apache mod_php: attack runs during request startup before application code under default memory and input limits.'
        );
    }
}
