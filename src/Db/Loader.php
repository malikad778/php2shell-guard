<?php

namespace Malikad\Php2ShellGuard\Db;

class Loader
{
    private $dataDir;

    public function __construct($dataDir = null)
    {
        $this->dataDir = $dataDir ?: realpath(__DIR__ . '/../../data') ?: (dirname(dirname(__DIR__)) . '/data');
    }

    public function loadAdvisory($id)
    {
        $filename = basename($id);
        if (substr($filename, -5) !== '.json') {
            $filename .= '.json';
        }
        $path = $this->dataDir . '/advisories/' . $filename;
        if (!file_exists($path)) {
            throw new \RuntimeException('Advisory file not found: ' . $path);
        }
        return json_decode(file_get_contents($path), true);
    }

    public function loadAllAdvisories()
    {
        $advDir = $this->dataDir . '/advisories';
        if (!is_dir($advDir)) {
            return array();
        }

        $files = scandir($advDir);
        $advisories = array();
        foreach ($files as $file) {
            if (substr($file, -5) === '.json') {
                $content = @file_get_contents($advDir . '/' . $file);
                if ($content !== false) {
                    $decoded = json_decode($content, true);
                    if ($decoded && isset($decoded['id'])) {
                        $advisories[$decoded['id']] = $decoded;
                    }
                }
            }
        }
        return $advisories;
    }

    public function getAdvisoriesForProduct($product)
    {
        $all = $this->loadAllAdvisories();
        $matched = array();
        foreach ($all as $adv) {
            if (isset($adv['product']) && strtolower($adv['product']) === strtolower($product)) {
                $matched[] = $adv;
            }
        }
        return $matched;
    }

    public function getEffectiveRulesForProduct($product)
    {
        $advisories = $this->getAdvisoriesForProduct($product);
        $branches = array();
        $allCves = array();

        foreach ($advisories as $adv) {
            if (isset($adv['cves']) && is_array($adv['cves'])) {
                $allCves = array_merge($allCves, $adv['cves']);
            }

            if (isset($adv['branches']) && is_array($adv['branches'])) {
                foreach ($adv['branches'] as $b) {
                    $brName = (string) $b['branch'];
                    if (!isset($branches[$brName])) {
                        $branches[$brName] = array(
                            'branch' => $brName,
                            'fixed' => null,
                            'eol' => false,
                            'has_source_backport' => false,
                            'cves' => array()
                        );
                    }

                    if (!empty($b['fixed'])) {
                        if ($branches[$brName]['fixed'] === null || version_compare($b['fixed'], $branches[$brName]['fixed'], '>')) {
                            $branches[$brName]['fixed'] = $b['fixed'];
                        }
                    }

                    if (!empty($b['eol'])) {
                        $branches[$brName]['eol'] = true;
                    }

                    if (isset($b['has_source_backport']) && $b['has_source_backport']) {
                        $branches[$brName]['has_source_backport'] = true;
                    } elseif (in_array($brName, array('7.4', '8.0', '8.1'), true)) {
                        $branches[$brName]['has_source_backport'] = true;
                    }

                    if (isset($adv['cves']) && is_array($adv['cves'])) {
                        $branches[$brName]['cves'] = array_values(array_unique(array_merge($branches[$brName]['cves'], $adv['cves'])));
                    }
                }
            }
        }

        return array(
            'product' => $product,
            'advisories_count' => count($advisories),
            'cves' => array_values(array_unique($allCves)),
            'branches' => $branches
        );
    }
}
