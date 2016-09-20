<?php
namespace hyperia\security;

use \yii\base\BootstrapInterface;
use \yii\base\Application;
use \yii\base\Component;
use Yii;

class Headers extends Component implements BootstrapInterface
{
    public function bootstrap($app)
    {
        $app->on(Application::EVENT_BEFORE_REQUEST, function ($e)
        {
            
            Yii::$app->response->headers->set('X-Powered-By', 'Hyperia');
        });
    }
}