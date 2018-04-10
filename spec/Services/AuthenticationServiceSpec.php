<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\SimpleSAML\Modules\OpenIDConnect\Services;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity;
use SimpleSAML\Modules\OpenIDConnect\Factories\AuthSimpleFactory;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\AuthenticationService;

class AuthenticationServiceSpec extends ObjectBehavior
{
    const AUTH_SOURCE = 'auth_source';
    const USER_ID_ATTR = 'uid';
    const USERNAME = 'username';

    public function let(
        UserRepository $userRepository,
        AuthSimpleFactory $authSimpleFactory,
        Simple $simple
    ) {
        $this->beConstructedWith($userRepository, $authSimpleFactory, self::USER_ID_ATTR);
        $authSimpleFactory->build(self::AUTH_SOURCE)->willReturn($simple);
        $simple->getAttributes()->willReturn([
            self::USER_ID_ATTR => [self::USERNAME],
        ]);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(AuthenticationService::class);
    }

    public function it_creates_new_user(
        Simple $simple,
        UserRepository $userRepository
    ) {
        $simple->requireAuth()->shouldBeCalled();
        $simple->getAttributes()->shouldBeCalled();

        $userRepository->getUserEntityByIdentifier(self::USERNAME)->shouldBeCalled()->willReturn(null);
        $userRepository->add(Argument::type(UserEntity::class))->shouldBeCalled();

        $this->getAuthenticateUser(self::AUTH_SOURCE)->shouldHaveIdentifier(self::USERNAME);
        $this->getAuthenticateUser(self::AUTH_SOURCE)->shouldHaveClaims([self::USER_ID_ATTR => [self::USERNAME]]);
    }

    public function it_returns_an_user(
        Simple $simple,
        UserRepository $userRepository,
        UserEntity $userEntity
    ) {
        $simple->requireAuth()->shouldBeCalled();
        $simple->getAttributes()->shouldBeCalled();

        $userRepository->getUserEntityByIdentifier(self::USERNAME)->shouldBeCalled()->willReturn($userEntity);
        $userEntity->setClaims([
            self::USER_ID_ATTR => [self::USERNAME],
        ])->shouldBeCalled();
        $userRepository->update($userEntity)->shouldBeCalled();

        $this->getAuthenticateUser(self::AUTH_SOURCE)->shouldBe($userEntity);
    }

    public function it_throws_exception_if_claims_not_exists(
        Simple $simple
    ) {
        $simple->requireAuth()->shouldBeCalled();
        $simple->getAttributes()->shouldBeCalled()->willReturn([
            'eduPersonTargetedId' => [self::USERNAME],
        ]);

        $this->shouldThrow(\SimpleSAML_Error_Exception::class)->during('getAuthenticateUser', [self::AUTH_SOURCE]);
    }

    public function getMatchers(): array
    {
        return [
            'haveIdentifier' => function (UserEntity $subject, $id) {
                return $subject->getIdentifier() === $id;
            },
            'haveClaims' => function (UserEntity $subject, array $claims) {
                return $subject->getClaims() === $claims;
            },
        ];
    }
}
