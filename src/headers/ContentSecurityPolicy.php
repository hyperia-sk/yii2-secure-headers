<?php

namespace hyperia\security\headers;

class ContentSecurityPolicy implements PolicyInterface
{
    private $directives;
    private $reportUri;
    private $requireSriForScript;
    private $requireSriForStyle;
    private $blockAllMixedContent;
    private $upgradeInsecureRequests;
    private $reportOnlyMode;
    private $defaultDirectives = [
        'connect-src' => "'self'",
        'font-src' => "'self'",
        'frame-src' => "'self'",
        'img-src' => "'self' data:",
        'manifest-src' => "'self'",
        'object-src' => "'self'",
        'prefetch-src' => "'self'",
        'script-src' => "'self' 'unsafe-inline'",
        'style-src' => "'self' 'unsafe-inline'",
        'media-src' => "'self'",
        'form-action' => "'self'",
        'worker-src' => "'self'",
    ];

    private $defaultCsp = [
        'default-src' => "'none'"
    ];

    public function __construct(array $directives, array $params, string $reportUri)
    {
        $this->directives = $directives;
        $this->reportUri = $reportUri;
        $this->requireSriForScript = $params['requireSriForScript'] ?? false;
        $this->requireSriForStyle = $params['requireSriForStyle'] ?? false;
        $this->blockAllMixedContent = $params['blockAllMixedContent'] ?? false;
        $this->upgradeInsecureRequests = $params['upgradeInsecureRequests'] ?? false;
        $this->reportOnlyMode = $params['reportOnlyMode'] ?? false;
    }

    public function getName(): string
    {
        return $this->reportOnlyMode ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
    }

    public function getValue(): string
    {
        $result = '';
        $cspDirectives = $this->buildPolicyArray();

        foreach ($cspDirectives as $directive => $value) {
            $result .= $directive . ' ' . $value . '; ';
        }

        if ($this->blockAllMixedContent) {
            $result .= 'block-all-mixed-content; ';
        }

        if ($this->upgradeInsecureRequests) {
            $result .= 'upgrade-insecure-requests; ';
        }

        return trim($result, '; ');
    }

    public function isValid(): bool
    {
        return true;
    }

    private function getCspReportUri(): array
    {
        $report = [];
        if (!empty($this->reportUri)) {
            $report = [
                'report-uri' => $this->reportUri . '/r/d/csp/enforce'
            ];
        }

        return $report;
    }

    private function getCspSubresourceIntegrity(): array
    {
        $result = [];

        if ($this->requireSriForScript) {
            $values[] = 'script';
        }

        if ($this->requireSriForStyle) {
            $values[] = 'style';
        }

        if (!empty($values)) {
            $result = [
                'require-sri-for' => implode(' ', $values)
            ];
        }

        return $result;
    }

    private function buildPolicyArray(): array
    {
        return array_merge(
            $this->defaultCsp,
            $this->defaultDirectives,
            $this->directives,
            $this->getCspSubresourceIntegrity(),
            $this->getCspReportUri()
        );
    }
}
