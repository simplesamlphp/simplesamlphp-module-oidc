<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Templates;

use SimpleSAML\Utils\HTTP;

class RedirectResponse
{
    /**
     * @var string
     */
    private $url;
    /**
     * @var array
     */
    private $parameters;

    public function __construct(string $url, array $parameters = [])
    {
        $this->url = $url;
        $this->parameters = $parameters;
    }

    public function show()
    {
        HTTP::redirectTrustedURL($this->url, $this->parameters);
    }
}
