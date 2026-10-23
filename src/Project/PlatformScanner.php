<?php

namespace Malikad\Php2ShellGuard\Project;

class PlatformScanner
{
    public function scan($platformConfigText)
    {
        $findings = array();
        if (preg_match('/php:(7\.[0-9]|8\.[01])/i', $platformConfigText, $m)) {
            $findings[] = array(
                'id' => 'C8_PLATFORM_EOL_PHP',
                'runtime' => $m[0],
                'message' => 'Platform configuration specifies EOL PHP runtime ' . $m[0]
            );
        }
        return $findings;
    }
}
