<?php

namespace Malikad\Php2ShellGuard\Report;

class Csv
{
    public function render(array $reportData, array $options = array())
    {
        $fp = fopen('php://temp', 'r+');
        fputcsv($fp, array(
            'host',
            'component',
            'serves_traffic',
            'detected_version',
            'status',
            'fixed_version',
            'cves',
            'evidence',
            'notes'
        ), ',', '"', "\\");

        $host = isset($reportData['host']) ? $reportData['host'] : (isset($reportData['target']) ? $reportData['target'] : 'localhost');
        $runtimes = isset($reportData['runtimes']) && is_array($reportData['runtimes']) ? $reportData['runtimes'] : array();

        foreach ($runtimes as $rt) {
            $cves = '';
            if (isset($rt['cves']) && is_array($rt['cves'])) {
                $cves = implode(';', $rt['cves']);
            }

            fputcsv($fp, array(
                $host,
                isset($rt['component']) ? $rt['component'] : '',
                !empty($rt['serves_traffic']) ? 'true' : 'false',
                isset($rt['detected_version']) ? $rt['detected_version'] : '',
                isset($rt['status']) ? $rt['status'] : '',
                isset($rt['fixed_version']) ? $rt['fixed_version'] : '',
                $cves,
                isset($rt['evidence']) ? $rt['evidence'] : '',
                isset($rt['notes']) ? $rt['notes'] : ''
            ), ',', '"', "\\");
        }

        rewind($fp);
        $csv = stream_get_contents($fp);
        fclose($fp);

        return $csv;
    }
}
