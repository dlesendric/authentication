<?php

/*
 * This file is part of the Active Collab ID project.
 *
 * (c) A51 doo <info@activecollab.com>. All rights reserved.
 */

namespace ActiveCollab\Authentication\Session;

use ActiveCollab\Authentication\AuthenticationResultInterface;

/**
 * @package ActiveCollab\Authentication\Session
 */
interface SessionInterface extends AuthenticationResultInterface
{
    /**
     * @return string
     */
    public function getSessionId();
}
