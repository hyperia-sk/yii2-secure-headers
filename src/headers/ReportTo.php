<?php

namespace hyperia\security\headers;

class ReportTo implements PolicyInterface
{
    private $groups;
    private $enabled;

    public function __construct(array $groups, bool $enabled = true)
    {
        $this->groups = $groups;
        $this->enabled = $enabled;
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
        return $this->enabled === true;
    }
}
