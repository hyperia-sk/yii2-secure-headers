<?php

namespace hyperia\security\tests\headers;

use hyperia\security\headers\ContentSecurityPolicy;
use hyperia\security\tests\TestCase;

class ContentSecurityPolicyTest extends TestCase
{
    /**
     * @var ContentSecurityPolicy
     */
    private $header;

    public function setUp(): void
    {
        $this->header = new ContentSecurityPolicy([
            'object-src' => "'self'",
            'media-src' => "'self'",
            'form-action' => "'self'",
            'frame-src' => "'self'"
        ], [
            'upgradeInsecureRequests' => false,
            'blockAllMixedContent' => true
        ], 'https://www.example.com');
    }

    public function testGetValue(): void
    {
        $this->assertSame("default-src 'none'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self' data:; manifest-src 'self'; object-src 'self'; prefetch-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self'; form-action 'self'; worker-src 'self'; report-uri https://www.example.com/r/d/csp/enforce; block-all-mixed-content", $this->header->getValue());
    }

    public function testGetName(): void
    {
        $this->assertSame('Content-Security-Policy', $this->header->getName());
    }

    public function testIsValid(): void
    {
        $this->assertTrue($this->header->isValid());
    }
}
