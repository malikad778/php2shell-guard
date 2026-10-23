<?php

namespace Malikad\Php2ShellGuard\Project;

class CiScanner
{
    public function scanWorkflow($yamlText)
    {
        $findings = array();
        if (preg_match_all('/php-version:\s*\[([^\]]+)\]/i', $yamlText, $matches)) {
            foreach ($matches[1] as $list) {
                if (preg_match('/(7\.4|8\.0|8\.1)/', $list)) {
                    $findings[] = array(
                        'id' => 'C5_CI_EOL_PHP',
                        'message' => 'GitHub Actions matrix includes EOL PHP branch (' . trim($list) . ').'
                    );
                }
            }
        }
        return $findings;
    }
}
