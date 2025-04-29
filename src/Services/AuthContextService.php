<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use RuntimeException;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\ModuleConfig;

/**
 * Provide contextual authentication information for administration interface.
 * @package SimpleSAML\Module\oidc\Services
 */
class AuthContextService
{
    /**
     * Users with this permission can register,edit,etc. their own clients
     */
    final public const PERM_CLIENT = 'client';

    /**
     * AuthContextService constructor.
     */
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly AuthSimpleFactory $authSimpleFactory,
        private readonly SspBridge $sspBridge,
    ) {
    }

    /**
     * @throws \SimpleSAML\Error\Exception
     * @throws \Exception
     */
    public function getAuthUserId(): string
    {
        $simple = $this->authenticate();
        $userIdAttr = $this->moduleConfig->getUserIdentifierAttribute();
        return (string)$this->sspBridge->utils()->attributes()->getExpectedAttribute(
            $simple->getAttributes(),
            $userIdAttr,
        );
    }

    /**
     * Checks if the user has the correct entitlements for the given permission. Throws an exception if user does not.
     * @param string $neededPermission The permissions needed
     * @throws \Exception thrown if permissions are not enabled or user is missing the needed entitlements
     */
    public function requirePermission(string $neededPermission): void
    {
        $permissions = $this->moduleConfig
            ->config()
            ->getOptionalConfigItem(ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS, null);

        if (is_null($permissions) || !$permissions->hasValue('attribute')) {
            throw new RuntimeException('Permissions not enabled');
        }
        if (!$permissions->hasValue($neededPermission)) {
            throw new RuntimeException('No permission defined for ' . $neededPermission);
        }

        $auth = $this->authenticate();

        $attributeName = $permissions->getString('attribute');
        /** @var string[] $entitlements */
        $entitlements = $auth->getAttributes()[$attributeName] ?? [];
        $neededEntitlements = $permissions->getArrayizeString($neededPermission);
        foreach ($entitlements as $entitlement) {
            if (in_array($entitlement, $neededEntitlements, true)) {
                return;
            }
        }
        throw new RuntimeException('Missing entitlement for ' . $neededPermission);
    }

    /**
     * @throws \Exception
     */
    private function authenticate(): Simple
    {
        $simple = $this->authSimpleFactory->getDefaultAuthSource();
        $simple->requireAuth();
        return $simple;
    }
}
