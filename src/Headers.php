<?php

namespace hyperia\security;

use Yii;
use yii\base\BootstrapInterface;
use yii\base\Application;
use yii\base\Component;

/**
 * Secure Headers Component
 *
 * @package hyperia\security
 */
class Headers extends Component implements BootstrapInterface
{

    /**
     * Insecure request
     *
     * @access public
     * @var boolean
     */
    public $upgradeInsecureRequests = true;

    /**
     * Block disable mixed content
     *
     * @access public
     * @var boolean
     */
    public $blockAllMixedContent = true;

    /**
     * Strict Transport Security
     *
     * @access public
     * @var integer
     */
    public $stsMaxAge = '';

    /**
     * X Frame Options
     *
     * @access public
     * @var string
     */
    public $xFrameOptions = 'DENY';

    /**
     * Content Security Policy directive
     *
     * @access public
     * @var array
     */
    public $cspDirectives = [];

    /**
     * Content Security Policy directive
     *
     * @access public
     * @var array
     */
    public $featurePolicyDirectives = [];

    /**
     * Powered By
     *
     * @access public
     * @var string
     */
    public $xPoweredBy = 'Hyperia';

    /**
     * Report URI
     *
     * @access public
     * @var string
     */
    public $reportUri = '';

    /**
     * Public Key Pins
     *
     * @access public
     * @var string
     */
    public $publicKeyPins = '';

    /**
     * Require Subresource Integrity for script
     *
     * @access public
     * @var bool
     */
    public $requireSriForScript = false;

    /**
     * Require Subresource Integrity for style
     *
     * @access public
     * @var bool
     */
    public $requireSriForStyle = false;

    /**
     * X-XSS-Protection
     *
     * @access public
     * @var boolean
     */
    public $xssProtection = true;

    /**
     * Referrer policy header
     *
     * @access public
     * @var string
     */
    public $referrerPolicy = 'no-referrer-when-downgrade';

    /**
     * X-Content-Type-Options
     *
     * @access public
     * @var boolean
     */
    public $contentTypeOptions = true;

    /**
     * Default Content Security Policy directives
     *
     * @access private
     * @var array
     */
    private $defaultCspDirectives = [
        'script-src' => "'self' 'unsafe-inline'",
        'style-src' => "'self' 'unsafe-inline'",
        'img-src' => "'self' data:",
        'connect-src' => "'self'",
        'font-src' => "'self'",
        'object-src' => "'self'",
        'media-src' => "'self'",
        'form-action' => "'self'",
        'frame-src' => "'self'",
        'child-src' => "'self'",
        'worker-src' => "'self'"
    ];

    /**
     * Default Feature Policy directives
     *
     * @access private
     * @var array
     */
    private $defaultFeaturePolicyDirectives = [
        'accelerometer' => "'self'",
        'ambient-light-sensor' => "'self'",
        'autoplay' => "'self'",
        'camera' => "'self'",
        'encrypted-media' => "'self'",
        'fullscreen' => "'self'",
        'geolocation' => "'self'",
        'gyroscope' => "'self'",
        'magnetometer' => "'self'",
        'microphone' => "'self'",
        'midi' => "'self'",
        'payment' => "'self'",
        'picture-in-picture' => "*",
        'speaker' => "'self'",
        'usb' => "'self'",
        'vr' => "'self'"
    ];

    /**
     * Default Content Security Policy
     *
     * @access private
     * @var array
     */
    private $defaultCsp = [
        'default-src' => "'none'"
    ];


    /**
     * Bootstrap (set up before request event)
     *
     * @access public
     * @param \yii\web\Application $app
     * @return void
     */
    public function bootstrap($app)
    {
        $app->on(Application::EVENT_BEFORE_REQUEST, function () {
            if (is_a(Yii::$app, 'yii\web\Application')) {
                $headers = Yii::$app->response->headers;

                $headers->set('X-Powered-By', $this->xPoweredBy);

                if (!empty($this->xFrameOptions)) {
                    $headers->set('X-Frame-Options', $this->xFrameOptions);
                }

                $content_security_policy = $this->getContentSecurityPolicyDirectives();
                if (!empty($content_security_policy)) {
                    $headers->set('Content-Security-Policy', $content_security_policy);
                }

                $feature_policy = $this->getFeaturePolicyDirectives();
                if (!empty($feature_policy)) {
                    $headers->set('Feature-Policy', $feature_policy);
                }

                if (!empty($this->stsMaxAge)) {
                    $headers->set('Strict-Transport-Security', 'max-age=' . $this->stsMaxAge . ';');
                }

                if ($this->contentTypeOptions) {
                    $headers->set('X-Content-Type-Options', 'nosniff');
                }

                if ($this->xssProtection) {
                    $headers->set('X-XSS-Protection', '1; mode=block;' . $this->getXssProtectionReportPart());
                }

                if (!empty($this->publicKeyPins)) {
                    $headers->set('Public-Key-Pins', $this->publicKeyPins);
                }

                if ($this->isValidReferrerPolicyValue($this->referrerPolicy)) {
                    $headers->set('Referrer-Policy', $this->referrerPolicy);
                }
            }
        });
    }

    /**
     * Get report part for X-XSS-Protection header
     *
     * @access private
     * @return string
     */
    private function getXssProtectionReportPart()
    {
        $report = '';
        if (!empty($this->reportUri)) {
            $report = ' report=' . $this->reportUri . '/';
        }

        return $report;
    }

    /**
     * CSP report uri
     *
     * @access private
     * @return array
     */
    private function getCspReportUri()
    {
        $report = [];
        if (!empty($this->reportUri)) {
            $report = [
                'report-uri' => $this->reportUri . '/r/default/csp/enforce'
            ];
        }

        return $report;
    }

    /**
     * CSP subresource integrity
     *
     * @access private
     * @return array
     */
    private function getCspSubresourceIntegrity()
    {
        $result = [];

        if ($this->requireSriForScript) {
            $values[] = 'script';
        }

        if ($this->requireSriForStyle) {
            $values[] = 'style';
        }

        if (!empty($values)) {
            $result = [
                'require-sri-for' => implode(' ', $values)
            ];
        }

        return $result;
    }

    /**
     * Build array with directive as key and parameter as value
     *
     * @access private
     * @return array
     */
    private function buildCspArray()
    {
        $csp_directives = $this->defaultCspDirectives;

        if (!empty($this->cspDirectives) && is_array($this->cspDirectives)) {
            foreach ($this->cspDirectives as $directive => $value) {
                if (isset($this->defaultCspDirectives[$directive])) {
                    $csp_directives[$directive] = $value;
                }
            }
        }

        return array_merge($this->defaultCsp, $csp_directives, $this->getCspSubresourceIntegrity(), $this->getCspReportUri());
    }

    /**
     * Build array with directive as key and parameter as value
     *
     * @access private
     * @return array
     */
    private function buildFuturePolicyArray()
    {
        $feature_directives = $this->defaultFeaturePolicyDirectives;

        if (!empty($this->featurePolicyDirectives) && is_array($this->featurePolicyDirectives)) {
            foreach ($this->featurePolicyDirectives as $directive => $value) {
                if (isset($this->defaultFeaturePolicyDirectives[$directive])) {
                    $feature_directives[$directive] = $value;
                }
            }
        }

        return array_merge($this->defaultFeaturePolicyDirectives, $feature_directives);
    }

    /**
     * Get feature policy directives
     *
     * @access private
     * @return string
     */
    private function getFeaturePolicyDirectives()
    {
        $result = '';
        $directives = $this->buildFuturePolicyArray();

        foreach ($directives as $directive => $value) {
            $result .= $directive . ' ' . $value . '; ';
        }

        return trim($result, '; ');
    }

    /**
     * Get content security policy directives
     *
     * @access private
     * @return string
     */
    private function getContentSecurityPolicyDirectives()
    {
        $result = '';
        $csp_directives = $this->buildCspArray();

        foreach ($csp_directives as $directive => $value) {
            $result .= $directive . ' ' . $value . '; ';
        }

        if ($this->blockAllMixedContent) {
            $result .= 'block-all-mixed-content; ';
        }

        if ($this->upgradeInsecureRequests) {
            $result .= 'upgrade-insecure-requests; ';
        }

        return trim($result, '; ');
    }

    /**
     * @param $value
     * @return bool
     */
    private function isValidReferrerPolicyValue($value)
    {
        $allowed_values = [
            "",
            "no-referrer",
            "no-referrer-when-downgrade",
            "same-origin",
            "origin",
            "strict-origin",
            "origin-when-cross-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url"
        ];

        return in_array($value, $allowed_values);
    }
}