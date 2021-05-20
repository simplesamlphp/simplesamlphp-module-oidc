<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\RequestRuleInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;

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

    /** @var array $data Which will be available during each check */
    protected $data = [];

    /**
     * RequestRulesManager constructor.
     * @param RequestRuleInterface[] $rules
     */
    public function __construct(array $rules = [])
    {
        foreach ($rules as $rule) {
            $this->add($rule);
        }

        $this->resultBag = new ResultBag();
    }

    public function add(RequestRuleInterface $rule)
    {
        $this->rules[$rule::getKey()] = $rule;
    }

    public function check(ServerRequestInterface $request): ResultBagInterface
    {
        foreach ($this->rules as $rule) {
            $result = $rule->checkRule($request, $this->resultBag, $this->data);

            if ($result !== null) {
                $this->resultBag->add($result);
            }
        }

        return $this->resultBag;
    }

    /**
     * Predefine (add) the existing result so it can be used by other checkers during check.
     * @param ResultInterface $result
     */
    public function predefineResult(ResultInterface $result): void
    {
        $this->resultBag->add($result);
    }

    /**
     * Set data which will be available in each check, using key value pair
     * @param $key
     * @param $value
     */
    public function setData($key, $value): void
    {
        $this->data[$key] = $value;
    }
}