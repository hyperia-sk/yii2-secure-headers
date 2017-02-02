# Bezpečnostné hlavičky
Každá aplikácia by mala obsahovať bezpečnostné hlavičky CSP (Content Security Policy). Tento komponent automaticky
implemntuje tieto hlavičky do každej požiadavky.

- **upgradeInsecureRequests** - pokúsi sa nadviatať nazabezpečneé spojenia cez HTTPS
- **blockAllMixedContent** - zablokovanie zmiešaného obsahu HTTP + HTTPS
- **stsMaxAge** - maximálna doba počas ktorej bude nadväzovať spojenie cez HTTPS. Pri prvotnej implementácii začínať radšej
opatrnejšie z menšími časmi a postupne zvyšovať
- **xFrameOptions** - určuje, či sa môže načítavať stránka cez iframe
- **xPoweredBy** - zmení hlavičku PoweredBy
- **publicKeyPins** - špeciálny verejný kľúč
- **cspDirectives** - direktívy Content Security Policy
  - script-src 
  - style-src
  - img-src
  - connect-src
  - font-src
  - object-src
  - media-src
  - form-action
  - frame-src
  - child-src


| Source Value       | Example                    | Description                                                                                                                                         |
|--------------------|----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------:|
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


### Implementácia bezpečnostných hlavičiek

```php
'bootstrap'  => [..., 'headers'],
'components' => [
		...
		'headers' => [
			'class'                   => '\hyperia\security\Headers',
         'upgradeInsecureRequests' => true,
         'blockAllMixedContent'    => true,
         'stsMaxAge'               => 10,
         'xFrameOptions'           => 'DENY',
         'xPoweredBy'              => 'Hyperia',
         'publicKeyPins'           => '',
         'cspDirectives'           => [
              'script-src'  => "'self' 'unsafe-inline'",
              'style-src'   => "'self' 'unsafe-inline'",
              'img-src'     => "'self' data:",
              'connect-src' => "'self'",
              'font-src'    => "'self'",
              'object-src'  => "'self'",
              'media-src'   => "'self'",
              'form-action' => "'self'",
              'frame-src'   => "'self'",
              'child-src'   => "'self'"
         ]
     ]
]
```