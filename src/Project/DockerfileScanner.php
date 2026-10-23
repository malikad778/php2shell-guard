<?php

namespace Malikad\Php2ShellGuard\Project;

use Malikad\Php2ShellGuard\Support\Status;
use Malikad\Php2ShellGuard\Support\VersionComparator;

class DockerfileScanner
{
    public function scan($dockerfileText)
    {
        $findings = array();
        $lines = preg_split('/\r?\n/', $dockerfileText);
        foreach ($lines as $idx => $line) {
            if (preg_match('/^\s*FROM\s+php:([^\s]+)/i', $line, $m)) {
                $tag = $m[1];
                $digestPinned = strpos($tag, '@sha256:') !== false;
                $sem = VersionComparator::extractSemver($tag);
                if ($sem !== '') {
                    $eval = VersionComparator::evaluatePhp($sem);
                } elseif (preg_match('/^([0-9]+\.[0-9]+)/', $tag, $bm)) {
                    $eval = VersionComparator::evaluatePhp($bm[1] . '.0');
                } else {
                    $eval = array(
                        'status' => Status::UNKNOWN,
                        'fixed' => '8.3.36 / 8.4.27',
                        'notes' => 'Floating php tag; pin to >= 8.3.36 or 8.4.27'
                    );
                }
                $findings[] = array(
                    'line' => $idx + 1,
                    'image' => 'php:' . $tag,
                    'digest_pinned' => $digestPinned,
                    'status' => $eval['status'],
                    'fixed' => $eval['fixed'],
                    'notes' => $eval['notes']
                );
            }
        }
        return $findings;
    }
}
