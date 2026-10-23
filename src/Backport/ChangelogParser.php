<?php

namespace Malikad\Php2ShellGuard\Backport;

class ChangelogParser
{
    public function hasPhp2ShellFixes($changelogText)
    {
        $has109618 = stripos($changelogText, 'CVE-2026-109618') !== false;
        $has109619 = stripos($changelogText, 'CVE-2026-109619') !== false;
        $has111497 = stripos($changelogText, 'CVE-2026-111497') !== false;
        return array(
            'CVE-2026-109618' => $has109618,
            'CVE-2026-109619' => $has109619,
            'CVE-2026-111497' => $has111497,
            'fully_patched' => ($has109618 && $has109619)
        );
    }

    public function hasCveFix($changelogText, $cveId)
    {
        return stripos($changelogText, trim($cveId)) !== false;
    }
}

