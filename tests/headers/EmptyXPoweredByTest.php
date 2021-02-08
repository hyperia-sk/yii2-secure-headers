<?php

namespace hyperia\security\tests\headers;

use hyperia\security\headers\XPoweredBy;
use hyperia\security\tests\TestCase;

class EmptyXPoweredByTest extends TestCase
{
    /**
     * @var XPoweredBy
     */
    private $header;

    public function setUp(): void
    {
        $this->header = new XPoweredBy('');
    }

    public function testGetValue(): void
    {
        $this->assertSame('', $this->header->getValue());
    }

    public function testIsValid(): void
    {
        $this->assertNotTrue($this->header->isValid());
    }
}