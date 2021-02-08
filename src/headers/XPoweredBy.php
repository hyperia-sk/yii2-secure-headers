<?php

namespace hyperia\security\headers;

class XPoweredBy implements PolicyInterface
{
    private $value;

    public function __construct(string $value)
    {
        $this->value = $value;
    }

    public function getName(): string
    {
        return 'X-Powered-By';
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function isValid(): bool
    {
        return !empty($this->value);
    }
}
