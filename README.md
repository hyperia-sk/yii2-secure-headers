# Yii2 security headers extension

[![Build Status](https://travis-ci.org/hyperia-sk/yii2-secure-headers.svg?branch=master)](https://travis-ci.org/hyperia-sk/yii2-secure-headers) 
[![codecov](https://codecov.io/gh/hyperia-sk/yii2-secure-headers/branch/master/graph/badge.svg)](https://codecov.io/gh/hyperia-sk/yii2-secure-headers)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/hyperia-sk/yii2-secure-headers/master/LICENSE) 
[![Latest Stable Version](https://poser.pugx.org/hyperia/yii2-secure-headers/v/stable)](https://packagist.org/packages/hyperia/yii2-secure-headers)

> Add security related headers to HTTP response. The package includes extension for easy Yii2 integration.

## Installation

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```shell
composer require hyperia/yii2-secure-headers:"^1.0"
```

or add

```
"hyperia/yii2-secure-headers": "^1.0"
```

to the require section of your composer.json.

## Configuration (usage)

```php
'bootstrap'  => [..., 'headers'],
'components' => [
    ...
    'headers' => [
        'class' => '\hyperia\security\Headers',
        'upgradeInsecureRequests' => true,
        'blockAllMixedContent' => true,
        'requireSriForScript' => false,
        'requireSriForStyle' => false,
        'xssProtection' => true,
        'contentTypeOptions' => true,
        'stsMaxAge' => 10,
        'xFrameOptions' => 'DENY',
        'xPoweredBy' => 'Hyperia',
        'publicKeyPins' => '',
        'reportUri' => 'https://company.report-uri.io',
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
            'child-src' => "'self'",
            'worker-src' => "'self'"
        ]
    ]
]
```

## Parameter description

| Source Value       | Example                    | Description                                                                                                                                         |
|--------------------|----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| *                  | img-src *                  | Wildcard, allows any URL except data: blob: filesystem: schemes.                                                                                    |
| 'none'             | object-src 'none'          | Prevents loading resources from any source.                                                                                                         |
| 'self'             | script-src 'self'          | Allows loading resources from the same origin (same scheme, host and port).                                                                         |
| data:              | img-src 'self' data:       | Allows loading resources via the data scheme (eg Base64 encoded images).                                                                            |
| domain.example.com | img-src domain.example.com | Allows loading resources from the specified domain name.                                                                                            |
| *.example.com      | img-src *.example.com      | Allows loading resources from any subdomain under example.com.                                                                                      |
| https://cdn.com    | img-src https://cdn.com    | Allows loading resources only over HTTPS matching the given domain.                                                                                 |
| https:             | img-src https:             | Allows loading resources only over HTTPS on any domain.                                                                                             |
| 'unsafe-inline'    | script-src 'unsafe-inline' | Allows use of inline source elements such as style attribute, onclick, or script tag bodies (depends on the context of the source it is applied to) |
| 'unsafe-eval'      | script-src 'unsafe-eval'   | Allows unsafe dynamic code evaluation such as JavaScript eval()                                                                                     |

#### Policy

Each header has a reference link in config file, you should read it if you do not know the header. 
If you want to disable a string type header, just set to null or empty string.

#### Public Key Pinning

When hashes is empty array, this header will not add to http response.

#### Content Security Policy

We use paragonie/csp-builder to help us support csp header. 
If you want to disable csp header, set custom-csp to empty string.

#### Subresource Integrity

If you want to require subresource integrity for style and script sources set `requireSriForStyle` and `requireSriForScript` to `true`

#### Additional Resources

[Everything you need to know about HTTP security headers](https://blog.appcanary.com/2017/http-security-headers.html)

