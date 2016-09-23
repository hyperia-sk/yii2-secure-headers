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
 *          'cspDirectives'           => [
 *               'script-src'  => "'self' 'unsafe-inline'",
 *               'style-src'   => "'self' 'unsafe-inline'",
 *               'img-src'     => "'self' data:",
 *               'connect-src' => "'self'",
 *               'font-src'    => "'self'",
 *               'object-src'  => "'self'",
 *               'media-src'   => "'self'",
 *               'form-action' => "'self'",
 *               'frame-src'   => "'self'"
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
    public $stsMaxAge = 10;

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
        'frame-src'   => "'self'"
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
            if(is_callable(Yii::$app->response, 'headers'))
            {
                $headers = Yii::$app->response->headers;
        
                $headers->set('X-Powered-By', 'Hyperia');
        
                $headers->set('Server', 'Hyperia Server');
        
                // Zabezpečí, aby sa nemohol dáavať mailing do iframe
                $headers->set('X-Frame-Options', $this->xFrameOptions);
        
                // Definuje z akých zdrojov sa môžu načítavať zdroje
                $headers->set('Content-Security-Policy', $this->getContentSecurityPolicyDirectives());
        
                // Definuje ze sa stranka najbližších xy sekúnd bude načítavať cez HTTPS
                $headers->set('Strict-Transport-Security', 'max-age='.$this->stsMaxAge.';');
        
                // Zabezpeci aby prehliadac neprekladal subory ak maju napisane ze je to plan text ale detekuje v nom JS
                $headers->set('X-Content-Type-Options', 'nosniff');
        
                // Reflecting XSS útok
                $headers->set('X-XSS-Protection', '1; mode=block; report=https://hyperia.report-uri.io/');
        
                // Zatial nepouzivat
                //$headers->set('Public-Key-Pins', '');
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