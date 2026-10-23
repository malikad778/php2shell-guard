<?php

namespace Malikad\Php2ShellGuard\Detect;

class CoolifyDetector
{
    private $fixedByLine = array(
        '4.0' => '4.0.1',
        '4.1' => '4.1.3',
        '4.2' => '4.2.1',
        '4.3' => '4.3.24',
        '4.4' => '4.4.7',
    );

    public function evaluateCoolifyVersion($version)
    {
        $clean = ltrim(trim($version), 'v');
        $parts = explode('.', $clean);
        if (count($parts) < 3) {
            return array('vulnerable' => true, 'fixed' => '4.4.7', 'warning' => 'Unrecognized Coolify version');
        }
        $line = $parts[0] . '.' . $parts[1];
        $fixed = isset($this->fixedByLine[$line]) ? $this->fixedByLine[$line] : '4.4.7';
        $isBelow = version_compare($clean, $fixed, '<');
        return array(
            'version' => $clean,
            'fixed_for_line' => $fixed,
            'below_fixed' => $isBelow,
            'critical_note' => 'Updating or isolating Coolify does NOT rebuild or isolate the PHP/Laravel/WordPress/Node application containers it deployed. Rebuild every deployed application container.'
        );
    }
}
