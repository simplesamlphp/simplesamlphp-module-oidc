<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\RequestRuleInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;

class RequestRulesManager
{
    /**
     * @var RequestRuleInterface[] $rules
     */
    private $rules = [];

    /**
     * @var ResultBagInterface $resultBag
     */
    protected $resultBag;

    public function __construct(array $rules = [])
    {
        foreach ($rules as $rule) {
            $this->add($rule);
        }

        $this->resultBag = new ResultBag();
    }

    public function add(RequestRuleInterface $rule)
    {
        $this->rules[] = $rule;
    }

    public function check(ServerRequestInterface $request): ResultBagInterface
    {
        foreach ($this->rules as $rule) {
            $result = $rule->checkRule($request, $this->resultBag);

            if ($result !== null) {
                $this->resultBag->add($result);
            }
        }

        return $this->resultBag;
    }
}
