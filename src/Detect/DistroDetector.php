<?php

namespace Malikad\Php2ShellGuard\Detect;

class DistroDetector
{
    public function parseOsRelease($content)
    {
        $id = 'unknown';
        $versionId = 'unknown';
        if (preg_match('/^ID="?([^"\n]+)"?/m', $content, $m)) {
            $id = strtolower(trim($m[1]));
        }
        if (preg_match('/^VERSION_ID="?([^"\n]+)"?/m', $content, $m)) {
            $versionId = trim($m[1]);
        }
        return array('id' => $id, 'version_id' => $versionId);
    }
}
