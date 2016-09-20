<?php
namespace hyperia\security;

use \yii\base\BootstrapInterface;
use \yii\base\Application;
use \yii\base\Component;

class Headers extends Component implements BootstrapInterface
{
    public function bootstrap($app)
    {
        $app->on(Application::EVENT_AFTER_REQUEST, function ()
        {
            $this->headers->set('X-Powered-By', 'Hyperia');
        });
    }
}