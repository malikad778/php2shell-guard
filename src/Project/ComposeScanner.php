<?php

namespace Malikad\Php2ShellGuard\Project;

class ComposeScanner
{
    public function scan($composeYaml)
    {
        $findings = array();
        if (preg_match('/ulimits:\s*(?:.|\n)*?\b(as|data):/i', $composeYaml)) {
            $findings[] = array(
                'id' => 'B9_COMPOSE_RLIMIT',
                'mitigation' => 'M3',
                'message' => 'docker-compose defines ulimits.as or ulimits.data (RLIMIT_AS/RLIMIT_DATA). Use mem_limit instead.'
            );
        }
        return $findings;
    }
}
