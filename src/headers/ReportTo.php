<?php

namespace hyperia\security\headers;

class ReportTo implements PolicyInterface
{
    private $groups;

    public function __construct(array $groups)
    {
        $this->groups = $groups;
    }

    public function getName(): string
    {
        return 'Report-To';
    }

    public function getValue(): string
    {
        return json_encode($this->groups);
    }

    public function isValid(): bool
    {
        return true;
    }
}
