<?php

namespace Malikad\Php2ShellGuard\Report;

class Json
{
    public function render(array $reportData, array $options = array())
    {
        return json_encode($reportData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    }
}
