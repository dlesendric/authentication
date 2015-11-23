<?php

namespace ActiveCollab\Authentication\Test;

use ActiveCollab\Authentication\AuthenticatedUser\AuthenticatedUserInterface;
use ActiveCollab\Authentication\AuthenticationResultInterface;
use ActiveCollab\Authentication\Adapter\BrowserSession;
use ActiveCollab\Authentication\Exception\InvalidSession;
use ActiveCollab\Authentication\Test\AuthenticatedUser\AuthenticatedUser;
use ActiveCollab\Authentication\Test\AuthenticatedUser\Repository as UserRepository;
use ActiveCollab\Authentication\Test\Base\BrowserSessionTestCase;
use ActiveCollab\Authentication\Test\Session\Repository as SessionRepository;
use ActiveCollab\Authentication\Test\Session\Session;
use ActiveCollab\Authentication\Test\Token\Token;
use GuzzleHttp\Psr7;

/**
 * @package ActiveCollab\Authentication\Test
 */
class BrowserSessionTerminateTest extends BrowserSessionTestCase
{
    /**
     * @expectedException \InvalidArgumentException
     */
    public function testTerminteNonSessionRaisesAnException()
    {
        (new BrowserSession($this->empty_users_repository, $this->empty_sessions_repository))->terminate(new Token('123', 'ilija.studen@activecollab.com'));
    }

    /**
     * Test session termination
     */
    public function testTerminateSession()
    {
        $test_session_id = 's123';

        $user_repository = new UserRepository([new AuthenticatedUser(1, 'ilija.studen@activecollab.com', 'Ilija Studen', '123')]);
        $session_repository = new SessionRepository([new Session($test_session_id, 'ilija.studen@activecollab.com')]);

        $browser_session_adapter = new BrowserSession($user_repository, $session_repository);

        // ---------------------------------------------------
        //  Successufl authentication
        // ---------------------------------------------------

        $session = null;
        $user = $browser_session_adapter->initialize($this->request->withCookieParams(['sessid' => $test_session_id]), $session);

        $this->assertInstanceOf(AuthenticatedUserInterface::class, $user);
        $this->assertInstanceOf(Session::class, $session);

        // ---------------------------------------------------
        //  Terminate
        // ---------------------------------------------------

        $browser_session_adapter->terminate($session);

        $this->setExpectedException(InvalidSession::class);
        $browser_session_adapter->initialize($this->request->withCookieParams(['sessid' => $test_session_id]));
    }
}
