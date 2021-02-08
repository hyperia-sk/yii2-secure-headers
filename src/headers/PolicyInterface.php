<?php

namespace hyperia\security\headers;

interface PolicyInterface
{
    public function getValue(): string;

    public function getName(): string;

    public function isValid(): bool;
}
