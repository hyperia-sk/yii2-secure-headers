<?php

namespace hyperia\security\tests\headers;

use hyperia\security\headers\ContentSecurityPolicy;
use hyperia\security\tests\TestCase;

class ContentSecurityPolicyTest extends TestCase
{
    public function testCommon(): void
    {
        $policy = new ContentSecurityPolicy([
            'object-src' => "'self'",
            'media-src' => "'self'",
            'form-action' => "'self'",
            'frame-src' => "'self'"
        ], [
            'upgradeInsecureRequests' => false,
            'blockAllMixedContent' => true
        ], 'https://www.example.com');

        $this->assertSame("default-src 'none'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self' data:; manifest-src 'self'; object-src 'self'; prefetch-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self'; form-action 'self'; worker-src 'self'; report-uri https://www.example.com/r/d/csp/enforce; block-all-mixed-content", $policy->getValue());
        $this->assertSame('Content-Security-Policy', $policy->getName());
        $this->assertTrue($policy->isValid());
    }

    public function testWithSubresourceIntegrity()
    {
        $policy = new ContentSecurityPolicy([
            'object-src' => "'self'",
            'media-src' => "'self'",
            'form-action' => "'self'"
        ], [
            'requireSriForScript' => true,
            'requireSriForStyle' => true
        ], 'https://www.example.com');

        $this->assertTrue($policy->isValid());
        $this->assertSame("default-src 'none'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self' data:; manifest-src 'self'; object-src 'self'; prefetch-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self'; form-action 'self'; worker-src 'self'; require-sri-for script style; report-uri https://www.example.com/r/d/csp/enforce", $policy->getValue());
    }

    public function testDefaultSrc(): void
    {
        $policy = new ContentSecurityPolicy([
            'default-src' => "*",
        ], [
            'upgradeInsecureRequests' => false,
            'blockAllMixedContent' => true
        ], 'https://www.example.com');

        $this->assertSame("default-src *; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self' data:; manifest-src 'self'; object-src 'self'; prefetch-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self'; form-action 'self'; worker-src 'self'; report-uri https://www.example.com/r/d/csp/enforce; block-all-mixed-content", $policy->getValue());
        $this->assertTrue($policy->isValid());

        // 'self'
        $policy = new ContentSecurityPolicy([
            'default-src' => "'self'",
        ], [
            'upgradeInsecureRequests' => false,
            'blockAllMixedContent' => true
        ], 'https://www.example.com');

        $this->assertSame("default-src 'self'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self' data:; manifest-src 'self'; object-src 'self'; prefetch-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self'; form-action 'self'; worker-src 'self'; report-uri https://www.example.com/r/d/csp/enforce; block-all-mixed-content", $policy->getValue());
        $this->assertTrue($policy->isValid());
    }

    public function testWithChildSrc(): void
    {
        $policy = new ContentSecurityPolicy([
            'child-src' => "'self'"
        ], [
            'upgradeInsecureRequests' => false,
            'blockAllMixedContent' => true
        ], 'https://www.example.com');

        $this->assertNotTrue($policy->isValid());
        $this->assertSame("default-src 'none'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self' data:; manifest-src 'self'; object-src 'self'; prefetch-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self'; form-action 'self'; worker-src 'self'; child-src 'self'; report-uri https://www.example.com/r/d/csp/enforce; block-all-mixed-content", $policy->getValue());
    }
}
