<?php

namespace hyperia\security\tests\headers;

use hyperia\security\headers\StrictTransportSecurity;
use hyperia\security\tests\TestCase;

class StrictTransportSecurityTest extends TestCase
{
    /**
     * @var StrictTransportSecurity
     */
    private $header;

    public function setUp(): void
    {
        $this->header = new StrictTransportSecurity([
            'max-age' => 100,
            'preload' => true
        ]);
    }

    public function testGetValue(): void
    {
        $this->assertSame('max-age=100; preload', $this->header->getValue());
    }

    public function testGetName(): void
    {
        $this->assertSame('Strict-Transport-Security', $this->header->getName());
    }

    public function dataProvider(): array
    {
        return [
            [false, ['max-age' => 100, 'preload' => 'true']],
            [false, ['max-age' => -1, 'preload' => true]],
            [true, ['max-age' => 1, 'includeSubDomains' => true]]
        ];
    }

    /**
     * @param bool $expected
     * @param array $config
     *
     * @dataProvider dataProvider
     */
    public function testValid(bool $expected, array $config): void
    {
        $policy = new StrictTransportSecurity($config);

        $this->assertSame($expected, $policy->isValid());
    }
}
