<?php

namespace hyperia\security\headers;

class XContentTypeOptions implements PolicyInterface
{
    private $value;

    public function __construct(bool $value)
    {
        $this->value = $value;
    }

    public function getValue(): string
    {
        return 'nosniff';
    }

    public function getName(): string
    {
        return 'X-Content-Type-Options';
    }

    public function isValid(): bool
    {
        return $this->value === true;
    }
}
