<?php

namespace hyperia\security\headers;

class StrictTransportSecurity implements PolicyInterface
{
    private $maxAge;
    private $preload;
    private $includeSubdomains;

    public function __construct(array $value)
    {
        $this->maxAge = $value['max-age'] ?? 0;
        $this->preload = $value['preload'] ?? false;
        $this->includeSubdomains = $value['includeSubDomains'] ?? false;
    }

    public function getName(): string
    {
        return 'Strict-Transport-Security';
    }

    public function getValue(): string
    {
        $directives = [
            'max-age=' . $this->maxAge,
            $this->preload ? 'preload' : '',
            $this->includeSubdomains ? 'includeSubDomains' : ''
        ];

        return implode('; ', array_filter($directives));
    }

    public function isValid(): bool
    {
        return $this->maxAge > 0 && is_bool($this->preload) && is_bool($this->includeSubdomains);
    }
}
