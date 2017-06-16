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
     * Insecure requesth
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
    public $reportUri = 'https://hyperia.report-uri.io';

    /**
     * Public Key Pins
     * 
     * @access public
     * @var string
     */
    public $publicKeyPins = '';

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
        $app->on(Application::EVENT_BEFORE_REQUEST, function() {
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

                if (!empty($this->stsMaxAge)) {
                    $headers->set('Strict-Transport-Security', 'max-age=' . $this->stsMaxAge . ';');
                }

                $headers->set('X-Content-Type-Options', 'nosniff');

                $headers->set('X-XSS-Protection', '1; mode=block; report=' . $this->reportUri . '/');

                if (!empty($this->publicKeyPins)) {
                    $headers->set('Public-Key-Pins', $this->publicKeyPins);
                }
            }
        });
    }
    
    /**
     * CSP report uri
     * 
     * @access private
     * @return array
     */
    private function getCspReportUri() 
    {
        return [
            'report-uri' => $this->reportUri . '/r/default/csp/enforce'
        ];
    }

    /**
     * Get content security policy directives
     * 
     * @acccess private
     * @return string
     */
    private function getContentSecurityPolicyDirectives() 
    {
        $csp_directives = $this->defaultCspDirectives;
        $result = [];

        if (!empty($this->cspDirectives) && is_array($this->cspDirectives)) {
            foreach ($this->cspDirectives as $directive => $value) {
                if (isset($this->defaultCspDirectives[$directive])) {
                    $csp_directives[$directive] = $value;
                }
            }
        }

        $csp_directives = array_merge($csp_directives, $this->getCspReportUri());
        $csp_directives = array_merge($this->defaultCsp, $csp_directives);

        foreach ($csp_directives as $directive => $value) {
            $result[] = $directive . ' ' . $value;
        }

        $result = implode('; ', $result) . '; ';

        if ($this->blockAllMixedContent) {
            $result .= 'block-all-mixed-content; ';
        }

        if ($this->upgradeInsecureRequests) {
            $result .= 'upgrade-insecure-requests; ';
        }

        return trim($result, '; ');
    }

}
