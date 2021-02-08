<?php

namespace hyperia\security\tests\headers;

use hyperia\security\headers\XContentTypeOptions;
use hyperia\security\tests\TestCase;

class XContentTypeOptionsTest extends TestCase
{
    /**
     * @var XContentTypeOptions
     */
    private $header;

    public function setUp(): void
    {
        $this->header = new XContentTypeOptions(true);
    }

    public function testGetValue(): void
    {
        $this->assertSame('nosniff', $this->header->getValue());
    }

    public function testGetName(): void
    {
        $this->assertSame('X-Content-Type-Options', $this->header->getName());
    }

    public function testIsValid(): void
    {
        $this->assertTrue($this->header->isValid());
    }
}
