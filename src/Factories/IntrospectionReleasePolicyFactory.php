<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\Introspection\IntrospectionReleasePolicyInterface;
use SimpleSAML\Module\oidc\Services\Introspection\PassthroughIntrospectionReleasePolicy;
use SimpleSAML\Module\oidc\Utils\ClassInstanceBuilder;
use Throwable;

/**
 * Builds the introspection release policy the deployment configured, or the passthrough default.
 *
 * Called when an answer needs a decision rather than when the endpoint is constructed, so that a policy which
 * can not be built is answered as the endpoint's own failure, in the endpoint's JSON, like any other.
 */
class IntrospectionReleasePolicyFactory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly ClassInstanceBuilder $classInstanceBuilder,
    ) {
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError When the configured class is not a release policy, or can
     * not be constructed with the configured arguments.
     */
    public function build(): IntrospectionReleasePolicyInterface
    {
        $policyClass = $this->moduleConfig->getApiOAuth2TokenIntrospectionReleasePolicyClass();

        if (is_null($policyClass)) {
            return new PassthroughIntrospectionReleasePolicy();
        }

        // Checked before anything is constructed, so that a mistyped or wrong class name is refused without
        // running a constructor which was never meant to be run here.
        if (!is_subclass_of($policyClass, IntrospectionReleasePolicyInterface::class)) {
            throw new ConfigurationError(
                sprintf(
                    '%s names %s, which is not a class implementing %s.',
                    ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RELEASE_POLICY,
                    $policyClass,
                    IntrospectionReleasePolicyInterface::class,
                ),
            );
        }

        try {
            $policy = $this->classInstanceBuilder->build(
                $policyClass,
                $this->moduleConfig->getApiOAuth2TokenIntrospectionReleasePolicyArguments(),
            );
        } catch (Throwable $e) {
            throw new ConfigurationError(
                sprintf(
                    'The introspection release policy %s can not be constructed with the arguments in %s: %s',
                    $policyClass,
                    ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RELEASE_POLICY_ARGUMENTS,
                    $e->getMessage(),
                ),
            );
        }

        if (!$policy instanceof IntrospectionReleasePolicyInterface) {
            // Not reached for a class which passed the check above; here for the type.
            throw new ConfigurationError(sprintf('%s did not construct a release policy.', $policyClass));
        }

        return $policy;
    }
}
