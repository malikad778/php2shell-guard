<?php

namespace Malikad\Php2ShellGuard\Tests\Unit;

use Malikad\Php2ShellGuard\Mitigate\SnippetRenderer;

class SnippetRendererTest
{
    public function run()
    {
        $renderer = new SnippetRenderer();

        // 1. Test basic nginx template rendering
        $nginx = $renderer->render('nginx', false);
        if (strpos($nginx, 'php2shell') === false) {
            throw new \RuntimeException('SnippetRenderer failed to render nginx template');
        }
        if (strpos($nginx, 'http_content_encoding') !== false) {
            throw new \RuntimeException('SnippetRenderer should not include weak rule when includeWeak is false');
        }

        // 2. Test weak rule inclusion for nginx
        $nginxWeak = $renderer->render('nginx', true);
        if (strpos($nginxWeak, 'http_content_encoding ~* "br"') === false) {
            throw new \RuntimeException('SnippetRenderer failed to include weak rule for nginx');
        }

        // 3. Test php-ini and fpm
        $ini = $renderer->render('php-ini', false);
        if (strpos($ini, 'max_input_vars') === false) {
            throw new \RuntimeException('SnippetRenderer failed to render php-ini template');
        }

        $fpm = $renderer->render('fpm', false);
        if (strpos($fpm, 'pm.max_requests') === false) {
            throw new \RuntimeException('SnippetRenderer failed to render fpm template');
        }
    }
}
