<?php

namespace hyperia\security;

use hyperia\security\headers\ContentSecurityPolicy;
use hyperia\security\headers\FeaturePolicy;
use hyperia\security\headers\ReferrerPolicy;
use hyperia\security\headers\StrictTransportSecurity;
use hyperia\security\headers\XContentTypeOptions;
use hyperia\security\headers\XFrameOptions;
use hyperia\security\headers\XPoweredBy;
use hyperia\security\headers\XssProtection;
use hyperia\security\headers\ReportTo;
use hyperia\security\headers\PermissionsPolicy;
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
     * @var array
     */
    public $strictTransportSecurity = [];

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
     * Feature Policy directive
     *
     * @access public
     * @var array
     */
    public $featurePolicyDirectives = [];

    /**
     * Permissions Policy directive
     *
     * @access public
     * @var array
     */
    public $permissionsPolicyDirectives = [];

    /**
     * Powered By
     *
     * @access public
     * @var string
     */
    public $xPoweredBy = '';

    /**
     * Report URI
     *
     * @access public
     * @var string
     */
    public $reportUri = '';

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
     * Content-Security-Policy-Report-Only
     *
     * @access public
     * @var boolean
     */
    public $reportOnlyMode = false;

    /**
     * Report To policy
     *
     * @access public
     * @var array
     */
    public $reportTo = [];

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

                $headerPolicy = [
                    new XPoweredBy($this->xPoweredBy),
                    new XFrameOptions($this->xFrameOptions),
                    new XContentTypeOptions($this->contentTypeOptions),
                    new StrictTransportSecurity($this->strictTransportSecurity),
                    new FeaturePolicy($this->featurePolicyDirectives),
                    new PermissionsPolicy($this->permissionsPolicyDirectives),
                    new ReferrerPolicy($this->referrerPolicy),
                    new XssProtection($this->xssProtection, $this->reportUri),
                    new ReportTo($this->reportTo),
                    new ContentSecurityPolicy($this->cspDirectives, [
                        'requireSriForScript' => $this->requireSriForScript,
                        'requireSriForStyle' => $this->requireSriForStyle,
                        'blockAllMixedContent' => $this->blockAllMixedContent,
                        'upgradeInsecureRequests' => $this->upgradeInsecureRequests,
                        'reportOnlyMode' => $this->reportOnlyMode
                    ], $this->reportUri)
                ];

                foreach ($headerPolicy as $policy) {
                    if ($policy->isValid() && !$headers->has($policy->getName())) {
                        $headers->set($policy->getName(), $policy->getValue());
                    }
                }
            }
        });
    }
}
