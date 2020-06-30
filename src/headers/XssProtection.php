<?php

namespace hyperia\security\headers;

class XssProtection implements PolicyInterface
{
    private $value;
    private $reportUri;

    public function __construct(bool $value, string $reportUri)
    {
        $this->value = $value;
        $this->reportUri = $reportUri;
    }

    public function getName(): string
    {
        return 'X-XSS-Protection';
    }

    public function getValue(): string
    {
        return '1; mode=block;' . $this->getXssProtectionReportPart();
    }

    public function isValid(): bool
    {
        return $this->value === true;
    }

    private function getXssProtectionReportPart(): string
    {
        $report = '';
        if (!empty($this->reportUri)) {
            $report = ' report=' . $this->reportUri . '/r/d/xss/enforce';
        }

        return $report;
    }
}
