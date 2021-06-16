<?php


namespace SimpleSAML\Modules\OpenIDConnect\Services;

use SimpleSAML\Auth\Simple;
use SimpleSAML\Utils\Auth;

/**
 * Provide contextual authentication information for administration interface.
 * @package SimpleSAML\Modules\OpenIDConnect\Services
 */
class AuthContextService
{

    /**
     * @var ConfigurationService
     */
    private $configurationService;

    /**
     * AuthContextService constructor.
     * @param ConfigurationService $configurationService
     */
    public function __construct(ConfigurationService $configurationService)
    {
        $this->configurationService = $configurationService;
    }

    public function isSspAdmin(): bool
    {
        return Auth::isAdmin();
    }

    public function getAuthUserId(): string
    {

        $simple = $this->authenticate();
        $userIdAttr = $this->configurationService->getOpenIDConnectConfiguration()->getString('useridattr');
        //TODO: check userIdAttr is set
        //TODO: check if user entitled?
        return $simple->getAttributes()[$userIdAttr][0];

    }

    private function authenticate(): Simple
    {
        $defaultAuthSource = $this->configurationService->getOpenIDConnectConfiguration()->getString('auth');
        $simple = new Simple($defaultAuthSource);
        $simple->requireAuth();
        return $simple;
    }

}