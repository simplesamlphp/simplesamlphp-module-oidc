<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker;

use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\RequestRuleInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;

use function sprintf;

class RequestRulesManager
{
    /** @var \SimpleSAML\Module\oidc\Utils\Checker\Interfaces\RequestRuleInterface[] $rules */
    private array $rules = [];

    /** @var \SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface $resultBag */
    protected ResultBagInterface $resultBag;

    /** @var array $data Which will be available during each check */
    protected array $data = [];

    /**
     * RequestRulesManager constructor.
     * @param \SimpleSAML\Module\oidc\Utils\Checker\Interfaces\RequestRuleInterface[] $rules
     */
    public function __construct(array $rules = [], protected LoggerService $loggerService = new LoggerService())
    {
        foreach ($rules as $rule) {
            $this->add($rule);
        }

        $this->resultBag = new ResultBag();
    }

    public function add(RequestRuleInterface $rule): void
    {
        $this->rules[$rule->getKey()] = $rule;
    }

    /**
     * @param class-string[] $ruleKeysToExecute
     * @param bool $useFragmentInHttpErrorResponses Indicate that in case of HTTP error responses, params should be
     * returned in URI fragment instead of query.
     * @param string[] $allowedServerRequestMethods Indicate allowed HTTP methods used for request
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function check(
        ServerRequestInterface $request,
        array $ruleKeysToExecute,
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET'],
    ): ResultBagInterface {
        foreach ($ruleKeysToExecute as $ruleKey) {
            if (! isset($this->rules[$ruleKey])) {
                throw new LogicException(sprintf('Rule for key %s not defined.', $ruleKey));
            }

            $result = $this->rules[$ruleKey]->checkRule(
                $request,
                $this->resultBag,
                $this->loggerService,
                $this->data,
                $useFragmentInHttpErrorResponses,
                $allowedServerRequestMethods,
            );

            if ($result !== null) {
                $this->resultBag->add($result);
            }
        }

        return $this->resultBag;
    }

    /**
     * Predefine (add) the existing result, so it can be used by other checkers during check.
     */
    public function predefineResult(ResultInterface $result): void
    {
        $this->resultBag->add($result);
    }

    /**
     * Predefine existing ResultBag so that it can be used by other checkers during check.
     */
    public function predefineResultBag(ResultBagInterface $resultBag): void
    {
        $this->resultBag = $resultBag;
    }

    /**
     * Set data which will be available in each check, using key value pair
     */
    public function setData(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
    }
}
