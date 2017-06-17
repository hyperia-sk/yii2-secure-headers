<?php

$_SERVER['SCRIPT_FILENAME'] = '/index.php';
$_SERVER['SCRIPT_NAME'] = '/index.php';

return [
    'bootstrap' => [
        'headers'
    ],
    'components' => [
        'headers' => [
            'class' => '\hyperia\security\Headers',
            'upgradeInsecureRequests' => true,
            'blockAllMixedContent' => true,
            'stsMaxAge' => 10,
            'xFrameOptions' => 'DENY',
            'xPoweredBy' => 'Hyperia',
            'publicKeyPins' => '',
            'cspDirectives' => [
                'script-src' => "'self' 'unsafe-inline'",
                'style-src' => "'self' 'unsafe-inline'",
                'img-src' => "'self' data:",
                'connect-src' => "'self'",
                'font-src' => "'self'",
                'object-src' => "'self'",
                'media-src' => "'self'",
                'form-action' => "'self'",
                'frame-src' => "'self'",
                'child-src' => "'self'"
            ]
        ]
    ]
];
