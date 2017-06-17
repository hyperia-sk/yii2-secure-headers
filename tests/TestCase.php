<?php

namespace hyperia\security\tests;

use Yii;
use yii\helpers\ArrayHelper;

class TestCase extends \PHPUnit_Framework_TestCase
{

    /**
     * Populates Yii::$app with a new application
     * The application will be destroyed on tearDown() automatically.
     * 
     * @access protected
     * @param array $config The application configuration, if needed
     * @param string $appClass name of the application class to create
     * @return void
     */
    protected function mockApplication($config = [], $appClass = '\yii\console\Application')
    {
        return new $appClass(ArrayHelper::merge([
            'id' => 'testapp',
            'basePath' => __DIR__,
            'vendorPath' => dirname(__DIR__) . '/vendor',
        ], $config));
    }

    /**
     * Call protected/private method of a class.
     *
     * @access protected
     * @param object &$object    Instantiated object that we will run method on.
     * @param string $methodName Method name to call
     * @param array  $parameters Array of parameters to pass into method.
     * @return mixed Method return.
     */
    protected function invokeMethod(&$object, $methodName, array $parameters = array())
    {
        $reflection = new \ReflectionClass(get_class($object));
        $method = $reflection->getMethod($methodName);
        $method->setAccessible(true);

        return $method->invokeArgs($object, $parameters);
    }

}