<?php

namespace hyperia\security\tests\headers;

use hyperia\security\headers\PermissionsPolicy;
use hyperia\security\tests\TestCase;

class PermissionsPolicyTest extends TestCase
{
    /**
     * @var PermissionsPolicy
     */
    private $header;

    public function setUp(): void
    {
        $this->header = new PermissionsPolicy([
            'payment' => '*',
            'picture-in-picture' => 'none'
        ]);
    }

    public function testGetValue(): void
    {
        $this->assertSame("accelerometer=(self), ambient-light-sensor=(self), autoplay=(self), battery=(self), camera=(self), display-capture=(self), document-domain=(self), encrypted-media=(self), fullscreen=(self), geolocation=(self), gyroscope=(self), layout-animations=(self), magnetometer=(self), microphone=(self), midi=(self), oversized-images=(self), payment=(*), picture-in-picture=(), publickey-credentials-get=(self), sync-xhr=(self), usb=(self), wake-lock=(self), xr-spatial-tracking=(self)", $this->header->getValue());
    }

    public function testGetName(): void
    {
        $this->assertSame('Permissions-Policy', $this->header->getName());
    }

    public function testIsValid(): void
    {
        $this->assertTrue($this->header->isValid());
    }

    public function testDisabled(): void
    {
        $policy = new PermissionsPolicy([
            'payment' => '*',
            'picture-in-picture' => 'none'
        ], false);

        $this->assertFalse($policy->isValid());
    }
}