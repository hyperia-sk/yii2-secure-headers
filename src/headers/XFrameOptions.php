<?php

namespace hyperia\security\headers;

class XFrameOptions implements PolicyInterface
{
    private $value;

    private $allowDirectives = [
        'DENY',
        'SAMEORIGIN'
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
        return 'X-Frame-Options';
    }

    public function isValid(): bool
    {
        return in_array($this->value, $this->allowDirectives);
    }
}
