<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker;

use Psr\Http\Message\ServerRequestInterface;

class RequestRulesManager
{
    /**
     * @var RequestRule[]
     */
    private $rules = [];

    public function __construct(array $rules = [])
    {
        foreach ($rules as $rule) {
            $this->add($rule);
        }
    }

    public function add(RequestRule $rule)
    {
        $this->rules[] = $rule;
    }

    public function check(ServerRequestInterface $request)
    {
        foreach ($this->rules as $rule) {
            $rule->checkRule($request);
        }
    }
}
