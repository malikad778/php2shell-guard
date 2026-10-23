<?php

namespace Malikad\Php2ShellGuard\Detect;

class BunDetector
{
    public function detectVersion($rawVersion)
    {
        return array(
            'component' => 'bun',
            'detected_version' => $rawVersion,
            'recommended_minimum' => '1.4.4',
            'note' => 'Verify against Bun official security advisory for bundled Brotli status.'
        );
    }
}
