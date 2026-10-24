<?php

namespace Malikad\Php2ShellGuard\Mitigate;

class SnippetRenderer
{
    private $rootDir;

    public function __construct($rootDir = null)
    {
        $this->rootDir = $rootDir ?: dirname(dirname(__DIR__));
    }

    public function render($target, $includeWeak = false)
    {
        $map = array(
            'php-ini' => 'templates/php-ini/99-php2shell-mitigation.ini',
            'fpm' => 'templates/fpm/zz-php2shell-pool.conf',
            'nginx' => 'templates/nginx/php2shell-mitigation.conf',
            'apache' => 'templates/apache/php2shell-mitigation.conf',
            'modsecurity' => 'templates/apache/modsecurity-php2shell.conf',
            'docker' => 'templates/docker/Dockerfile.patched',
            'compose' => 'templates/docker/docker-compose.override.yml',
            'k8s' => 'templates/k8s/kustomize-patch.yaml',
            'cloudflare' => 'templates/cloudflare/waf-custom-rule.txt',
            'systemd' => 'templates/systemd/php-fpm-mitigation.conf',
            'ansible' => 'templates/ansible/remediate-php2shell.yml',
        );
        if (!isset($map[$target])) {
            throw new \InvalidArgumentException('Unsupported mitigation target: ' . $target);
        }
        $text = file_get_contents($this->rootDir . '/' . $map[$target]);
        if ($includeWeak && $target === 'nginx') {
            $text .= "\n" .
                "# [N3 - Last Resort / Weak] Reject inbound Content-Encoding: br (reduces exposure only)\n" .
                'if ($http_content_encoding ~* "br") { return 415; }' . "\n";
        }
        return $text;
    }
}
