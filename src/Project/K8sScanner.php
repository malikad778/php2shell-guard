<?php

namespace Malikad\Php2ShellGuard\Project;

class K8sScanner
{
    public function scanManifest($yamlText)
    {
        $findings = array();
        if (strpos($yamlText, 'image: php:') !== false && strpos($yamlText, 'memory:') === false) {
            $findings[] = array(
                'id' => 'B8_K8S_MEMORY_LIMIT',
                'mitigation' => 'M3',
                'message' => 'Kubernetes manifest with PHP container does not specify resources.limits.memory (M3).'
            );
        }
        return $findings;
    }
}
