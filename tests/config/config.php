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
            'strictTransportSecurity' => [
                'max-age' => 10,
                'includeSubDomains' => true
            ],
            'xFrameOptions' => 'DENY',
            'xPoweredBy' => 'Hyperia',
            'cspDirectives' => [
                'script-src' => "'self' 'unsafe-inline'",
                'connect-src' => "'self'",
                'style-src' => "'self' 'unsafe-inline'",
                'img-src' => "'self' data:",
                'font-src' => "'self'",
                'object-src' => "'self'",
                'media-src' => "'self'",
                'form-action' => "'self'",
                'frame-src' => "'self'",
            ]
        ]
    ]
];
