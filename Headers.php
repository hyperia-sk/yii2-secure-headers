<?php
namespace hyperia\security;

use \yii\base\BootstrapInterface;
use \yii\base\Application;
use \yii\base\Component;
use Yii;

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
     * @var string
     */
    public $xFrameOptions = 'SAMEORIGIN';

    public $xContentTypeOptions = 'nosniff';

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
        'default-src'     => "'none'",
        'script-src'      => "'self' 'unsafe-inline'",
        'style-src'       => "'self' 'unsafe-inline'",
        'img-src'         => "'self' data:",
        'connect-src'     => "'self'",
        'font-src'        => "'self'",
        'object-src'      => "'self'",
        'media-src'       => "'self'",
        'report-uri'      => "'self'",
        'form-action'     => "'self'"
    ];

    public function bootstrap($app)
    {
        $app->on(Application::EVENT_BEFORE_REQUEST, function()
        {
            $headers = Yii::$app->response->headers;

            $headers->set('X-Powered-By', 'Hyperia');

            $headers->set('Server', 'Hyperia Server');

            $headers->set('X-Frame-Options', $this->xFrameOptions);

            // Definuje z akých zdrojov sa môžu načítavať zdroje
            $headers->set('Content-Security-Policy', $this->getContentSecurityPolicyDirectives());


            //https://plz.report-uri.io/r/default/csp/enforce

            // Definuje ze sa stranka najbližších xy sekúnd bude načítavať cez HTTPS
            $headers->set('Strict-Transport-Security', 'max-age='.$this->stsMaxAge.';');

            /**
             * Zabezpeci aby prehliadac neprekladal subory ak maju napisane ze je to plan text ale detekuje v nom JS
             */
            $headers->set('X-Content-Type-Options', $this->xContentTypeOptions);

            $headers->set('X-XSS-Protection', '1; mode=block; report=https://report-uri.io/');

            // Zatial nepouzivat
            //$headers->set('Public-Key-Pins', '');
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