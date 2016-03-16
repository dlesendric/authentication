<?php

/*
 * This file is part of the Active Collab ID project.
 *
 * (c) A51 doo <info@activecollab.com>. All rights reserved.
 */

namespace ActiveCollab\Authentication\Test;

use ActiveCollab\Authentication\Adapter\BrowserSession;
use ActiveCollab\Authentication\Session\SessionInterface;
use ActiveCollab\Authentication\Test\AuthenticatedUser\AuthenticatedUser;
use ActiveCollab\Authentication\Test\AuthenticatedUser\Repository as UserRepository;
use ActiveCollab\Authentication\Test\Base\BrowserSessionTestCase;
use ActiveCollab\Authentication\Test\Session\Repository as SessionRepository;
use ActiveCollab\Authentication\Test\Session\Session;

/**
 * @package ActiveCollab\Authentication\Test
 */
class BrowserSessionInitializeTest extends BrowserSessionTestCase
{
    /**
     * Test request cookies.
     */
    public function testRequestCookie()
    {
        $this->setCookie('my_cookie', '123');
        $this->assertEquals('123', $this->cookies->get($this->request, 'my_cookie'));
    }

    /**
     * Test initialization skips when there's no session cookie.
     */
    public function testInitializationSkipWhenTheresNoSessionCookie()
    {
        $this->assertNull((new BrowserSession($this->empty_users_repository, $this->empty_sessions_repository, $this->cookies))->initialize($this->request));
    }

    /**
     * @expectedException \ActiveCollab\Authentication\Exception\InvalidSession
     */
    public function testExceptionWhenSessionIsNotValid()
    {
        $this->setCookie('sessid', 'not a valid session ID');

        (new BrowserSession($this->empty_users_repository, $this->empty_sessions_repository, $this->cookies))->initialize($this->request);
    }

    /**
     * Test if we get authenticated user when we use a good token.
     */
    public function testAuthenticationWithGoodSessionId()
    {
        $test_session_id = 's123';

        $user_repository = new UserRepository([new AuthenticatedUser(1, 'ilija.studen@activecollab.com', 'Ilija Studen', '123')]);
        $session_repository = new SessionRepository([new Session($test_session_id, 'ilija.studen@activecollab.com')]);

        $this->setCookie('sessid', $test_session_id);

        $user = (new BrowserSession($user_repository, $session_repository, $this->cookies))->initialize($this->request);

        $this->assertInstanceOf(AuthenticatedUser::class, $user);
    }

    /**
     * Test if we get authenticated user when we use a good token.
     */
    public function testAuthenticationWithGoodSessionIdAlsoSetsSession()
    {
        $test_session_id = 's123';

        $user_repository = new UserRepository([new AuthenticatedUser(1, 'ilija.studen@activecollab.com', 'Ilija Studen', '123')]);
        $session_repository = new SessionRepository([new Session($test_session_id, 'ilija.studen@activecollab.com')]);

        $this->setCookie('sessid', $test_session_id);

        $session = null;

        $user = (new BrowserSession($user_repository, $session_repository, $this->cookies))->initialize($this->request, $session);

        $this->assertInstanceOf(AuthenticatedUser::class, $user);
        $this->assertInstanceOf(SessionInterface::class, $session);
    }

    /**
     * Test if session usage is recorded.
     */
    public function testAuthenticationRecordsSessionUsage()
    {
        $test_session_id = 's123';

        $user_repository = new UserRepository([new AuthenticatedUser(1, 'ilija.studen@activecollab.com', 'Ilija Studen', '123')]);
        $session_repository = new SessionRepository([new Session($test_session_id, 'ilija.studen@activecollab.com')]);

        $this->setCookie('sessid', $test_session_id);

        $this->assertSame(0, $session_repository->getUsageById($test_session_id));

        $user = (new BrowserSession($user_repository, $session_repository, $this->cookies))->initialize($this->request);
        $this->assertInstanceOf(AuthenticatedUser::class, $user);

        $this->assertSame(1, $session_repository->getUsageById($test_session_id));
    }
}
