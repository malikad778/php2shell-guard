<?php

namespace Malikad\Php2ShellGuard\Upgrade;

class RectorRunner
{
    public function getRecommendedConfig($targetPhp = '8.3')
    {
        $num = str_replace('.', '', $targetPhp);
        return <<<PHP
<?php

use Rector\Config\RectorConfig;
use Rector\Set\ValueObject\LevelSetList;

return static function (RectorConfig \$rectorConfig): void {
    \$rectorConfig->paths([__DIR__ . '/app', __DIR__ . '/src']);
    \$rectorConfig->sets([
        LevelSetList::UP_TO_PHP_{$num},
    ]);
};
PHP;
    }

    public function getCommand($targetPhp = '8.3')
    {
        return "vendor/bin/rector process --dry-run";
    }

    public function runDryRun($projectPath, $targetPhp = '8.3')
    {
        $bin = rtrim($projectPath, '/\\') . '/vendor/bin/rector';
        if (file_exists($bin) && is_executable($bin) && function_exists('exec')) {
            $cmd = sprintf('%s process --dry-run --output-format=json 2>/dev/null', escapeshellarg($bin));
            $output = array();
            $ret = 0;
            @exec($cmd, $output, $ret);
            $raw = implode("\n", $output);
            $json = json_decode($raw, true);
            if ($json) {
                return array(
                    'executed' => true,
                    'file_diffs_count' => isset($json['file_diffs']) ? count($json['file_diffs']) : 0,
                    'file_diffs' => isset($json['file_diffs']) ? $json['file_diffs'] : array()
                );
            }
        }

        return array(
            'executed' => false,
            'command' => $this->getCommand($targetPhp),
            'note' => "Rector binary not found in vendor/bin/rector. Run 'composer require --dev rector/rector' and preview changes with: " . $this->getCommand($targetPhp)
        );
    }
}
