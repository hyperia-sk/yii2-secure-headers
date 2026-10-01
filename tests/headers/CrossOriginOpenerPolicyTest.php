<?php

namespace hyperia\security\tests\headers;

use hyperia\security\headers\CrossOriginOpenerPolicy;
use hyperia\security\tests\TestCase;

class CrossOriginOpenerPolicyTest extends TestCase
{
    /**
     * @var CrossOriginOpenerPolicy
     */
    private $header;

    public function setUp(): void
    {
        $this->header = new CrossOriginOpenerPolicy('same-origin');
    }

    public function testGetValue(): void
    {
        $this->assertSame('same-origin', $this->header->getValue());
    }

    public function testGetName(): void
    {
        $this->assertSame('Cross-Origin-Opener-Policy', $this->header->getName());
    }

    public function testEmptyValue(): void
    {
        $policy = new CrossOriginOpenerPolicy('');

        $this->assertSame('', $policy->getValue());
        $this->assertFalse($policy->isValid());
    }

    public function dataProvider(): array
    {
        return [
            [false, ''],
            [false, '   '],
            [false, ';'],
            [false, '; report-to="coop-endpoint"'],
            [false, 'none'],
            [false, 'SAME-ORIGIN'],
            [true, 'unsafe-none'],
            [true, 'same-origin'],
            [true, 'same-origin-allow-popups'],
            [true, 'noopener-allow-popups'],
            [true, 'same-origin; report-to="coop-endpoint"'],
            [false, 'invalid; report-to="coop-endpoint"'],
        ];
    }

    /**
     * @param bool $expected
     * @param string $directive
     *
     * @dataProvider dataProvider
     */
    public function testValid(bool $expected, string $directive): void
    {
        $policy = new CrossOriginOpenerPolicy($directive);

        $this->assertSame($expected, $policy->isValid());
    }
}
