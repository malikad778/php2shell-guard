<?php

namespace Malikad\Php2ShellGuard\Fleet;

class GithubOrg
{
    private $token;

    public function __construct($token = null)
    {
        $this->token = $token ?: getenv('GITHUB_TOKEN');
    }

    public function getReadOnlyCommands()
    {
        return array(
            'GET /orgs/{org}/repos',
            'GET /repos/{owner}/{repo}/contents/composer.json',
            'GET /repos/{owner}/{repo}/contents/Dockerfile'
        );
    }

    public function scanOrg($org, $maxRepos = 50)
    {
        $url = sprintf('https://api.github.com/orgs/%s/repos?per_page=%d&type=all', rawurlencode($org), $maxRepos);
        $headers = array('User-Agent: php2shell-guard');
        if (!empty($this->token)) {
            $headers[] = 'Authorization: Bearer ' . $this->token;
        }

        $opts = array(
            'http' => array(
                'method' => 'GET',
                'header' => implode("\r\n", $headers),
                'timeout' => 15,
                'ignore_errors' => true
            )
        );

        $context = stream_context_create($opts);
        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            return array(
                'success' => false,
                'error' => "Failed to connect to GitHub API for org: {$org}",
                'repositories' => array()
            );
        }

        $repos = json_decode($response, true);
        if (!is_array($repos) || isset($repos['message'])) {
            $errMsg = isset($repos['message']) ? $repos['message'] : 'Invalid response from GitHub API';
            return array(
                'success' => false,
                'error' => $errMsg,
                'repositories' => array()
            );
        }

        $findings = array();
        foreach ($repos as $r) {
            if (!empty($r['name']) && empty($r['archived'])) {
                $findings[] = array(
                    'repo' => $r['full_name'],
                    'html_url' => $r['html_url'],
                    'default_branch' => isset($r['default_branch']) ? $r['default_branch'] : 'main'
                );
            }
        }

        return array(
            'success' => true,
            'org' => $org,
            'scanned_repos_count' => count($findings),
            'repositories' => $findings
        );
    }
}
