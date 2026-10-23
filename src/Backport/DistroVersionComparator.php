<?php

namespace Malikad\Php2ShellGuard\Backport;

class DistroVersionComparator
{
    public static function compareDebian($ver1, $ver2)
    {
        if (function_exists('exec') && (PHP_OS_FAMILY === 'Linux')) {
            $cmd = sprintf('dpkg --compare-versions %s ge %s 2>/dev/null', escapeshellarg($ver1), escapeshellarg($ver2));
            $ret = 0;
            @exec($cmd, $o, $ret);
            if ($ret === 0) {
                return 1;
            }
        }
        return self::compareVersionTokens($ver1, $ver2);
    }

    public static function compareAlpine($ver1, $ver2)
    {
        $p1 = explode('-r', $ver1);
        $p2 = explode('-r', $ver2);

        $up1 = $p1[0];
        $up2 = $p2[0];
        $vc = version_compare($up1, $up2);
        if ($vc !== 0) {
            return $vc;
        }

        $r1 = isset($p1[1]) ? (int) $p1[1] : 0;
        $r2 = isset($p2[1]) ? (int) $p2[1] : 0;
        if ($r1 === $r2) return 0;
        return $r1 > $r2 ? 1 : -1;
    }

    public static function compareRhel($ver1, $ver2)
    {
        $p1 = explode('-', $ver1);
        $p2 = explode('-', $ver2);
        $vc = version_compare($p1[0], $p2[0]);
        if ($vc !== 0) {
            return $vc;
        }
        $rel1 = isset($p1[1]) ? $p1[1] : '';
        $rel2 = isset($p2[1]) ? $p2[1] : '';
        return self::compareVersionTokens($rel1, $rel2);
    }

    public static function compareVersionTokens($a, $b)
    {
        if ($a === $b) return 0;

        // Tilde handling: tilde sorts before empty string
        $lenA = strlen($a);
        $lenB = strlen($b);
        $i = 0;
        $j = 0;

        while ($i < $lenA || $j < $lenB) {
            $charA = $i < $lenA ? $a[$i] : '';
            $charB = $j < $lenB ? $b[$j] : '';

            if ($charA === '~' || $charB === '~') {
                if ($charA !== '~') return 1;
                if ($charB !== '~') return -1;
                $i++;
                $j++;
                continue;
            }

            // Parse digit chunks
            if (ctype_digit($charA) && ctype_digit($charB)) {
                $numA = '';
                $numB = '';
                while ($i < $lenA && ctype_digit($a[$i])) {
                    $numA .= $a[$i++];
                }
                while ($j < $lenB && ctype_digit($b[$j])) {
                    $numB .= $b[$j++];
                }
                $valA = (int) $numA;
                $valB = (int) $numB;
                if ($valA !== $valB) {
                    return $valA > $valB ? 1 : -1;
                }
                continue;
            }

            // Alpha chunks
            if ($charA !== $charB) {
                return $charA > $charB ? 1 : -1;
            }
            $i++;
            $j++;
        }
        return 0;
    }
}
