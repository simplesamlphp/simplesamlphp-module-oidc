<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity;
use SimpleSAML\Modules\OpenIDConnect\Factories\AuthSimpleFactory;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;

class AuthenticationService
{
    /**
     * @var UserRepository
     */
    private $userRepository;
    /**
     * @var AuthSimpleFactory
     */
    private $authSimpleFactory;
    /**
     * @var string
     */
    private $userIdAttr;

    public function __construct(
        UserRepository $userRepository,
        AuthSimpleFactory $authSimpleFactory,
        string $userIdAttr
    ) {
        $this->userRepository = $userRepository;
        $this->authSimpleFactory = $authSimpleFactory;
        $this->userIdAttr = $userIdAttr;
    }

    /**
     * @param string $authSource
     *
     * @throws \SimpleSAML_Error_Exception
     *
     * @return UserEntity
     */
    public function getAuthenticateUser(string $authSource): UserEntity
    {
        $authSimple = $this->authSimpleFactory->build($authSource);
        $authSimple->requireAuth();

        $claims = $authSimple->getAttributes();
        if (!array_key_exists($this->userIdAttr, $claims)) {
            throw new \SimpleSAML_Error_Exception('Attribute `useridattr` doesn\'t exists in claims. Available attributes are: '.implode(', ', array_keys($claims)));
        }

        $userId = $claims[$this->userIdAttr][0];
        $user = $this->userRepository->getUserEntityByIdentifier($userId);

        if (!$user) {
            $user = UserEntity::fromData($userId, $claims);
            $this->userRepository->add($user);
        } else {
            $user->setClaims($claims);
            $this->userRepository->update($user);
        }

        return $user;
    }
}
