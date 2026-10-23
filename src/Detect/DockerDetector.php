<?php

namespace Malikad\Php2ShellGuard\Detect;

class DockerDetector
{
    public function checkContainerImageStale($runningImageId, $tagImageId)
    {
        return $runningImageId !== '' && $tagImageId !== '' && $runningImageId !== $tagImageId;
    }
}
