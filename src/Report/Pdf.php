<?php

namespace Malikad\Php2ShellGuard\Report;

class Pdf
{
    private $htmlRenderer;

    public function __construct($htmlRenderer = null)
    {
        $this->htmlRenderer = $htmlRenderer ?: new Html();
    }

    public function render(array $reportData, array $options = array())
    {
        // Produce print-optimized HTML designed for PDF rendering
        $html = $this->htmlRenderer->render($reportData, $options);

        // Inject PDF print page setup CSS
        $printCss = '
<style>
@page {
    size: A4 portrait;
    margin: 15mm 15mm 15mm 15mm;
}
@media print {
    body {
        background: #ffffff !important;
        color: #111827 !important;
        font-size: 11pt !important;
    }
    .card, .stat-card {
        border: 1px solid #e5e7eb !important;
        background: #f9fafb !important;
        box-shadow: none !important;
        break-inside: avoid;
    }
    .meta-badge {
        border: 1px solid #d1d5db !important;
        color: #374151 !important;
    }
    footer, .no-print {
        display: none !important;
    }
}
</style>
<script>
if (typeof window !== "undefined" && window.location.search.indexOf("print=1") !== -1) {
    window.addEventListener("load", function() { window.print(); });
}
</script>
';
        return str_replace('</head>', $printCss . '</head>', $html);
    }
}
