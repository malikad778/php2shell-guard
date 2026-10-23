<?php

namespace Malikad\Php2ShellGuard\Brotli;

class DependencyScan
{
    private $watched = array('undici', 'node-fetch', 'axios', 'got', 'superagent', 'iltorb', 'brotli', 'compression');

    public function scanPackageJson($jsonText)
    {
        $data = json_decode($jsonText, true);
        if (!is_array($data)) {
            return array();
        }
        $deps = array_merge(
            isset($data['dependencies']) ? $data['dependencies'] : array(),
            isset($data['devDependencies']) ? $data['devDependencies'] : array()
        );
        $hits = array();
        foreach ($this->watched as $pkg) {
            if (isset($deps[$pkg])) {
                $hits[] = array(
                    'id' => 'D2_BROTLI_PACKAGE',
                    'package' => $pkg,
                    'version' => $deps[$pkg],
                    'note' => 'Dependency may decode Brotli streams automatically (CVE-2026-111497 exposure hint).'
                );
            }
        }
        return $hits;
    }
}
