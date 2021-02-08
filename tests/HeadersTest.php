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
            ['x-xss-protection', '1; mode=block;']
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
        $this->assertCount(8, $defaultHeaders);
        $this->assertArrayHasKey($a, $defaultHeaders);
        $this->assertSame($b, $defaultHeaders[$a]);
    }
}
