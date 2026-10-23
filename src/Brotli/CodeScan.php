<?php

namespace Malikad\Php2ShellGuard\Brotli;

class CodeScan
{
    public function scanSource($jsCode)
    {
        $hits = array();
        if (preg_match('/\b(brotliDecompress|brotliDecompressSync|createBrotliDecompress)\b/', $jsCode, $m)) {
            $hits[] = array(
                'id' => 'D1_ZLIB_BROTLI',
                'api' => $m[1],
                'note' => 'Direct Node.js zlib Brotli decompression call (CVE-2026-111497 exposure hint).'
            );
        }
        return $hits;
    }
}
