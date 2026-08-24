<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Auth\State;

/**
 *
 */
class StateService
{
    /**
     * @var \SimpleSAML\Auth\State
     */
    private readonly State $authState;


    /**
     *
     */
    public function __construct()
    {
        $this->authState = new State();
    }


    /**
     * @return \SimpleSAML\Auth\State
     */
    public function getAuthState(): State
    {
        return $this->authState;
    }


    /**
     * @param   string  $id
     * @param   string  $stage
     * @param   bool    $allowMissing
     *
     * @return array|null
     * @throws \SimpleSAML\Error\NoState
     */
    public function loadState(string $id, string $stage, bool $allowMissing = false): ?array
    {
        return $this->authState::loadState($id, $stage, $allowMissing);
    }
}
