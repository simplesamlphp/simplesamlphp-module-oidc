<?php

namespace SimpleSAML\Module\oidc\Utils\Checker;

use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\RequestRuleInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;

use function sprintf;

class RequestRulesManager
{
    /**
     * @var RequestRuleInterface[] $rules
     */
    private array $rules = [];

    /**
     * @var ResultBagInterface $resultBag
     */
    protected $resultBag;

    /** @var array $data Which will be available during each check */
    protected array $data = [];

    protected LoggerService $loggerService;

    /**
     * RequestRulesManager constructor.
     * @param RequestRuleInterface[] $rules
     */
    public function __construct(array $rules = [], ?LoggerService $loggerService = null)
    {
        foreach ($rules as $rule) {
            $this->add($rule);
        }

        $this->resultBag = new ResultBag();
        $this->loggerService = $loggerService ?? new LoggerService();
    }

    public function add(RequestRuleInterface $rule): void
    {
        $this->rules[$rule->getKey()] = $rule;
    }

    /**
     * @param ServerRequestInterface $request
     * @param array $ruleKeysToExecute
     * @param bool $useFragmentInHttpErrorResponses Indicate that in case of HTTP error responses, params should be
     * returned in URI fragment instead of query.
     * @param array $allowedServerRequestMethods Indicate allowed HTTP methods used for request
     * @return ResultBagInterface
     * @throws OidcServerException
     */
    public function check(
        ServerRequestInterface $request,
        array $ruleKeysToExecute,
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
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
                $allowedServerRequestMethods
            );

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
     * Predefine existing ResultBag so that it can be used by other checkers during check.
     * @param ResultBagInterface $resultBag
     */
    public function predefineResultBag(ResultBagInterface $resultBag): void
    {
        $this->resultBag = $resultBag;
    }

    /**
     * Set data which will be available in each check, using key value pair
     * @param string $key
     * @param mixed $value
     */
    public function setData(string $key, $value): void
    {
        $this->data[$key] = $value;
    }
}
