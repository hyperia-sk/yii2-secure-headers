<?php

namespace hyperia\security\headers;

class ReferrerPolicy implements PolicyInterface
{
    private $value;

    private $allowDirectives = [
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "origin",
        "strict-origin",
        "origin-when-cross-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url"
    ];

    public function __construct(string $value)
    {
        $this->value = $value;
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function getName(): string
    {
        return 'Referrer-Policy';
    }

    public function isValid(): bool
    {
        return in_array($this->value, $this->allowDirectives);
    }
}
