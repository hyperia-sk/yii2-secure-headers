<?php
namespace hyperia\security;

use yii\base\BootstrapInterface;
use yii\base\Application;

class Headers implements BootstrapInterface
{
    public function bootstrap($app)
    {
        $app->on(Application::EVENT_AFTER_REQUEST, function ()
        {
            $this->headers->set('X-Powered-By', 'Hyperia');
        });
    }
}