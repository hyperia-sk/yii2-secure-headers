<?php
namespace hyperia\security;

use \yii\base\BootstrapInterface;
use \yii\base\Application;
use \yii\base\Component;
use Yii;

/**
 * Implementácia bezpečnostných hlavičiek
 *
 * ```php
 * 'bootstrap'  => [..., 'headers'],
 * 'components' => [
 * 		...
 * 		'headers' => [
 * 			'class'                   => '\hyperia\security\Headers',
 *          'upgradeInsecureRequests' => true,
 *          'blockAllMixedContent'    => true,
 *          'stsMaxAge'               => 10,
 *          'xFrameOptions'           => 'DENY',
 *          'xPoweredBy'              => 'Hyperia',
 *          'server'                  => 'Hyperia Server',
 *          'publicKeyPins'           => '',
 *          'cspDirectives'           => [
 *               'script-src'  => "'self' 'unsafe-inline'",
 *               'style-src'   => "'self' 'unsafe-inline'",
 *               'img-src'     => "'self' data:",
 *               'connect-src' => "'self'",
 *               'font-src'    => "'self'",
 *               'object-src'  => "'self'",
 *               'media-src'   => "'self'",
 *               'form-action' => "'self'",
 *               'frame-src'   => "'self'",
 *               'child-src'   => "'self'"
 *          ]
 *      ]
 * ]
 *
 * ```
 */

class Headers extends Component implements BootstrapInterface
{
    /**
     * Pokúsi sa opraviť nezabezpečené požiadavky
     * @var bool
     */
    public $upgradeInsecureRequests = true;

    /**
     * Zablokuje zmiešaný obsah (http:// v kombinácii s https://)
     * @var bool
     */
    public $blockAllMixedContent = true;

    /**
     * Strict Transport Security
     * @var int
     */
    public $stsMaxAge = '';

    /**
     * X Frame Options
     * @var string
     */
    public $xFrameOptions = 'DENY';

    /**
     * Content Security Policy direktívy
     * @var array
     */
    public $cspDirectives = [];
    
    /**
     * Powered By
     * @var string
     */
    public $xPoweredBy = 'Hyperia';
    
    /**
     * Server
     * @var string
     */
    public $server = 'Hyperia Server';
    
    /**
     * Report URI
     * @var string
     */
    public $reportUri = 'https://hyperia.report-uri.io';
    
    /**
     * Public Key Pins
     * @var string
     */
    public $publicKeyPins = '';

    /**
     * Prednastavené Content Security Policy direktívy
     * @var array
     */
    private $defaultCspDirectives = [
        'script-src'  => "'self' 'unsafe-inline'",
        'style-src'   => "'self' 'unsafe-inline'",
        'img-src'     => "'self' data:",
        'connect-src' => "'self'",
        'font-src'    => "'self'",
        'object-src'  => "'self'",
        'media-src'   => "'self'",
        'form-action' => "'self'",
        'frame-src'   => "'self'",
        'child-src'   => "'self'",
    ];
    
    /**
     * URL adresa na zbieranie reportov
     * @var string
     */
    private $cspReportUri = ['report-uri' => 'https://hyperia.report-uri.io/r/default/csp/enforce'];
    
    /**
     * Prednastavené nastavenie pre Content Security Policy
     * @var array
     */
    private $defaultCsp = ['default-src' => "'none'"];

    public function bootstrap($app)
    {
        $app->on(Application::EVENT_BEFORE_REQUEST, function()
        {
            if(is_a(Yii::$app, 'yii\web\Application'))
            {
                $headers = Yii::$app->response->headers;
    
                $headers->set('X-Powered-By', $this->xPoweredBy);
    
                $headers->set('Server', $this->server);
                
                if(!empty($this->xFrameOptions))
                {
                    $headers->set('X-Frame-Options', $this->xFrameOptions);
                }
    
                $content_security_policy = $this->getContentSecurityPolicyDirectives();
                if(!empty($content_security_policy))
                {
                    $headers->set('Content-Security-Policy', $content_security_policy);
                }
    
                if(!empty($this->stsMaxAge))
                {
                    $headers->set('Strict-Transport-Security', 'max-age='.$this->stsMaxAge.';');
                }
                
                $headers->set('X-Content-Type-Options', 'nosniff');
                
                $headers->set('X-XSS-Protection', '1; mode=block; report='.$this->reportUri.'/');
    
                if(!empty($this->publicKeyPins))
                {
                    $headers->set('Public-Key-Pins', $this->publicKeyPins);
                }
            }
        });
    }

    /**
     * Vráti direktívy pre Content Security Policy
     * @return string
     */
    private function getContentSecurityPolicyDirectives()
    {
        $csp_directives = $this->defaultCspDirectives;
        $result         = '';

        if(!empty($this->cspDirectives) && is_array($this->cspDirectives))
        {
            foreach($this->cspDirectives as $directive => $value)
            {
                if(isset($this->defaultCspDirectives[$directive]))
                {
                    $csp_directives[$directive] = $value;
                }
            }
        }
    
        $csp_directives = array_merge($csp_directives, $this->cspReportUri);
        $csp_directives = array_merge($this->defaultCsp, $csp_directives);

        foreach($csp_directives as $directive => $value)
        {
            $result[] = $directive.' '.$value;
        }
        
        $result = implode('; ', $result).'; ';
        
        if($this->blockAllMixedContent)
        {
            $result .= 'block-all-mixed-content; ';
        }

        if($this->upgradeInsecureRequests)
        {
            $result .= 'upgrade-insecure-requests; ';
        }

        return trim($result, '; ');
    }
}