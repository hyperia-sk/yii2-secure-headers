<?php

namespace hyperia\security\tests\headers;

use hyperia\security\headers\XssProtection;
use hyperia\security\tests\TestCase;

class XssProtectionTest extends TestCase
{
    /**
     * @var XssProtection
     */
    private $header;

    public function setUp(): void
    {
        $this->header = new XssProtection(true, 'example.com/r/d/xss/enforce');
    }

    public function testGetValue(): void
    {
        $this->assertSame('1; mode=block; report=example.com/r/d/xss/enforce', $this->header->getValue());
    }

    public function testGetName(): void
    {
        $this->assertSame('X-XSS-Protection', $this->header->getName());
    }

    public function testIsValid(): void
    {
        $this->assertTrue($this->header->isValid());
    }
}
