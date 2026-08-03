<?php

namespace hyperia\security\tests\headers;

use hyperia\security\headers\ReportTo;
use hyperia\security\tests\TestCase;

class ReportToTest extends TestCase
{
    /**
     * @var ReportTo
     */
    private $header;

    public function setUp(): void
    {
        $this->header = new ReportTo([
            [
                'group' => 'groupName',
                'max_age' => 10886400,
                'endpoints' => [
                    [
                        'name' => 'endpointName',
                        'url' => 'https://example.com',
                        'failures' => 1
                    ]
                ]
            ]
        ]);
    }

    public function testGetValue(): void
    {
        $this->assertSame(json_encode([
            [
                'group' => 'groupName',
                'max_age' => 10886400,
                'endpoints' => [
                    [
                        'name' => 'endpointName',
                        'url' => 'https://example.com',
                        'failures' => 1
                    ]
                ]
            ]
        ]), $this->header->getValue());
    }

    public function testGetName(): void
    {
        $this->assertSame('Report-To', $this->header->getName());
    }

    public function testIsValid(): void
    {
        $this->assertTrue($this->header->isValid());
    }

    public function testDisabled(): void
    {
        $policy = new ReportTo([], false);

        $this->assertFalse($policy->isValid());
    }
}