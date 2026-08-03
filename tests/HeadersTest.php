<?php

namespace hyperia\security\tests;

use Yii;
use yii\base\Application;
use hyperia\security\Headers;

/**
 * Headers test
 */
class HeadersTest extends TestCase
{
    /**
     * @var Headers
     */
    private $headers;

    /**
     * Set Up
     */
    protected function setUp(): void
    {
        parent::setUp();

        // run web application
        $this->mockApplication(require(__DIR__ . '/config/config.php'), 'yii\web\Application');

        // trigger event
        Yii::$app->trigger(Application::EVENT_BEFORE_REQUEST);

        // init extension
        $this->headers = new Headers();
    }

    /**
     * Data provider - default headers
     */
    public function defaultHeaders(): array
    {
        return [
            ['x-powered-by', 'Hyperia'],
            ['x-frame-options', 'DENY'],
            ['content-security-policy', "default-src 'none'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self' data:; manifest-src 'self'; object-src 'self'; prefetch-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self'; form-action 'self'; worker-src 'self'; block-all-mixed-content; upgrade-insecure-requests"],
            ['strict-transport-security', 'max-age=10; includeSubDomains'],
            ['x-content-type-options', 'nosniff'],
            ['x-xss-protection', '1; mode=block;'],
            ['referrer-policy', 'no-referrer-when-downgrade'],
            ['feature-policy', "accelerometer 'self'; ambient-light-sensor 'self'; autoplay 'self'; battery 'self'; camera 'self'; display-capture 'self'; document-domain 'self'; encrypted-media 'self'; fullscreen 'self'; geolocation 'self'; gyroscope 'self'; layout-animations 'self'; magnetometer 'self'; microphone 'self'; midi 'self'; oversized-images 'self'; payment 'self'; picture-in-picture *; publickey-credentials-get 'self'; sync-xhr 'self'; usb 'self'; wake-lock 'self'; xr-spatial-tracking 'self'"],
            ['permissions-policy', "accelerometer=(self), ambient-light-sensor=(self), autoplay=(self), battery=(self), camera=(self), display-capture=(self), document-domain=(self), encrypted-media=(self), fullscreen=(self), geolocation=(self), gyroscope=(self), layout-animations=(self), magnetometer=(self), microphone=(self), midi=(self), oversized-images=(self), payment=(self), picture-in-picture=(*), publickey-credentials-get=(self), sync-xhr=(self), usb=(self), wake-lock=(self), xr-spatial-tracking=(self)"],
            ['report-to', '[]'],
        ];
    }

    /**
     * @param string $a
     * @param string $b
     * @dataProvider defaultHeaders
     */
    public function testHeaders(string $a, string $b): void
    {
        $defaultHeaders = Yii::$app->response->getHeaders();

        $this->assertNotEmpty($defaultHeaders);
        $this->assertCount(10, $defaultHeaders);
        $this->assertArrayHasKey($a, $defaultHeaders);
        $this->assertSame($b, $defaultHeaders[$a]);
    }

    /**
     * Feature-Policy, Permissions-Policy and Report-To can be turned off individually
     */
    public function testDisabledHeaders(): void
    {
        $config = require(__DIR__ . '/config/config.php');
        $config['components']['headers']['enableFeaturePolicy'] = false;
        $config['components']['headers']['enablePermissionsPolicy'] = false;
        $config['components']['headers']['enableReportTo'] = false;

        $this->mockApplication($config, 'yii\web\Application');

        Yii::$app->trigger(Application::EVENT_BEFORE_REQUEST);

        $defaultHeaders = Yii::$app->response->getHeaders();

        $this->assertCount(7, $defaultHeaders);
        $this->assertFalse($defaultHeaders->has('feature-policy'));
        $this->assertFalse($defaultHeaders->has('permissions-policy'));
        $this->assertFalse($defaultHeaders->has('report-to'));
    }
}