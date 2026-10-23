<?php

namespace Malikad\Php2ShellGuard\Laravel;

class Notifications
{
    public function formatSlackPayload(array $scanResult)
    {
        return array(
            'text' => '[php2shell-guard] Runtime status report: exit_code=' . (isset($scanResult['exit_code']) ? $scanResult['exit_code'] : 0)
        );
    }
}
