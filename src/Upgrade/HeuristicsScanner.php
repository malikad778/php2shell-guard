<?php

namespace Malikad\Php2ShellGuard\Upgrade;

class HeuristicsScanner
{
    private $rules = array(
        array(
            'id' => 'DOLLAR_BRACE_INTERPOLATION',
            'pattern' => '/\$\{[a-zA-Z0-9_]+\}/',
            'since' => '8.2',
            'message' => '${var} string interpolation is deprecated in PHP 8.2; use {$var} instead.'
        ),
        array(
            'id' => 'DEPRECATED_UTF8_FUNCTIONS',
            'pattern' => '/\b(utf8_encode|utf8_decode)\s*\(/i',
            'since' => '8.2',
            'message' => 'utf8_encode() and utf8_decode() are deprecated in PHP 8.2; use mb_convert_encoding() or UConverter.'
        ),
        array(
            'id' => 'REMOVED_PHP80_FUNCTIONS',
            'pattern' => '/\b(create_function|each|get_magic_quotes_gpc|get_magic_quotes_runtime|money_format|hebrevc)\s*\(/i',
            'since' => '8.0',
            'message' => 'Function was removed in PHP 8.0 and will trigger fatal error.'
        ),
        array(
            'id' => 'OPTIONAL_PARAM_BEFORE_REQUIRED',
            'pattern' => '/function\s+[a-zA-Z0-9_]+\s*\([^)]*\$[a-zA-Z0-9_]+\s*=[^,)]+,[^)]*\$[a-zA-Z0-9_]+\s*(\)|,)/i',
            'since' => '8.0',
            'message' => 'Optional parameter declared before required parameter is deprecated in PHP 8.0.'
        ),
        array(
            'id' => 'DEPRECATED_FILTER_FLAGS',
            'pattern' => '/\b(FILTER_FLAG_SCHEME_REQUIRED|FILTER_FLAG_HOST_REQUIRED)\b/',
            'since' => '8.0',
            'message' => 'FILTER_FLAG_SCHEME_REQUIRED and FILTER_FLAG_HOST_REQUIRED are deprecated in PHP 8.0.'
        ),
        array(
            'id' => 'NULL_TO_INTERNAL_FUNCS',
            'pattern' => '/\b(strlen|substr|trim|ltrim|rtrim|explode|strpos|str_replace)\s*\(\s*null\s*[,)]/i',
            'since' => '8.1',
            'message' => 'Passing null to non-nullable internal function arguments is deprecated in PHP 8.1.'
        ),
        array(
            'id' => 'DEPRECATED_MHASH',
            'pattern' => '/\b(mhash|mhash_count|mhash_get_block_size|mhash_get_hash_name)\s*\(/i',
            'since' => '8.1',
            'message' => 'mhash*() functions are deprecated in PHP 8.1; use hash*() instead.'
        ),
        array(
            'id' => 'SWITCH_CASE_SEMICOLON',
            'pattern' => '/\bcase\s+[^:;]+;\s*$/m',
            'since' => '8.2',
            'message' => 'Using a semicolon instead of a colon after a switch case is deprecated in PHP 8.2.'
        )
    );

    public function scanPhpCode($code)
    {
        $issues = array();
        foreach ($this->rules as $rule) {
            if (preg_match_all($rule['pattern'], $code, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $matchedText = $match[0];
                    $offset = $match[1];
                    $lineNum = substr_count(substr($code, 0, $offset), "\n") + 1;

                    $issues[] = array(
                        'type' => $rule['id'],
                        'since' => $rule['since'],
                        'line' => $lineNum,
                        'matched' => trim($matchedText),
                        'message' => $rule['message']
                    );
                }
            }
        }
        return $issues;
    }
}
