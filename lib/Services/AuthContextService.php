<?php

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Utils\Attributes;
use SimpleSAML\Utils\Auth;

/**
 * Provide contextual authentication information for administration interface.
 * @package SimpleSAML\Module\oidc\Services
 */
class AuthContextService
{
    /**
     * Users with this permission can register,edit,etc their own clients
     */
    public const PERM_CLIENT = 'client';

    /**
     * @var ConfigurationService
     */
    private $configurationService;

    /**
     * @var AuthSimpleFactory
     */
    private $authSimpleFactory;

    /**
     * AuthContextService constructor.
     * @param ConfigurationService $configurationService
     * @param AuthSimpleFactory $authSimpleFactory
     */
    public function __construct(ConfigurationService $configurationService, AuthSimpleFactory $authSimpleFactory)
    {
        $this->configurationService = $configurationService;
        $this->authSimpleFactory = $authSimpleFactory;
    }

    public function isSspAdmin(): bool
    {
        return Auth::isAdmin();
    }

    public function getAuthUserId(): string
    {
        $simple = $this->authenticate();
        $userIdAttr = $this->configurationService->getOpenIDConnectConfiguration()->getString('useridattr');
        return Attributes::getExpectedAttribute($simple->getAttributes(), $userIdAttr);
    }

    /**
     * Checks if the user has the correct entitlements for the given permission. Throws an exception if user does not.
     * @param string $neededPermission The permissions needed
     * @throws \Exception thrown if permissions are not enabled or user is missing the needed entitlements
     */
    public function requirePermission(string $neededPermission)
    {
        $auth = $this->authenticate();

        $permissions = $this->configurationService->getOpenIDConnectConfiguration()->getConfigItem('permissions', []);
        if (is_null($permissions) || !$permissions->hasValue('attribute')) {
            throw new \RuntimeException('Permissions not enabled');
        }
        if (!$permissions->hasValue($neededPermission)) {
            throw new \RuntimeException('No permission defined for ' . $neededPermission);
        }
        $attributeName = $permissions->getString('attribute');
        $entitlements = $auth->getAttributes()[$attributeName] ?? [];
        $neededEntitlements = $permissions->getArrayizeString($neededPermission);
        foreach ($entitlements as $entitlement) {
            if (in_array($entitlement, $neededEntitlements)) {
                return;
            }
        }
        throw new \RuntimeException('Missing entitlement for ' . $neededPermission);
    }

    private function authenticate(): Simple
    {
        $simple = $this->authSimpleFactory->getDefaultAuthSource();
        $simple->requireAuth();
        return $simple;
    }
}
