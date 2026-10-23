<?php

namespace Malikad\Php2ShellGuard\Upgrade;

class EffortEstimator
{
    public function estimate($blockerCount, $heuristicIssueCount)
    {
        $score = ($blockerCount * 3) + $heuristicIssueCount;
        if ($score === 0) {
            return array('size' => 'S', 'hours' => '4-8 hours');
        }
        if ($score <= 6) {
            return array('size' => 'M', 'hours' => '12-24 hours');
        }
        if ($score <= 15) {
            return array('size' => 'L', 'hours' => '24-48 hours');
        }
        return array('size' => 'XL', 'hours' => '48-80+ hours');
    }
}
