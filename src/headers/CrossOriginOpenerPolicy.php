<?php

namespace hyperia\security\headers;

class CrossOriginOpenerPolicy implements PolicyInterface
{
    private $value;

    private $allowDirectives = [
        'unsafe-none',
        'same-origin-allow-popups',
        'same-origin',
        'noopener-allow-popups'
    ];

    public function __construct(string $value)
    {
        $this->value = trim($value);
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function getName(): string
    {
        return 'Cross-Origin-Opener-Policy';
    }

    public function isValid(): bool
    {
        if (!empty($this->value)) {
            // allow optional parameters, e.g. `same-origin; report-to="coop-endpoint"`
            $directive = trim(explode(';', $this->value, 2)[0]);

            return in_array($directive, $this->allowDirectives, true);
        }

        return false;
    }
}
