<?php

use Zend\Authentication\AuthenticationService;
use Zend\EventManager\EventManager;

class Firewall
{
    private $authFails = [];

    public function getFailureCount($identifier)
    {
        if (isset($this->authFails[$identifier])) {
            return $this->authFails[$identifier];
        }

        return 0;
    }

    public function onAuthenticate(\Zend\Authentication\Event\Authenticate $event)
    {
        $identity = $event->getParam('identity');
        if ($identity !== null) {
            if ($this->getFailurecount($identity) > 2) {
                $result = new \Zend\Authentication\Result(-4, $identity, 'Too many failed attempts');
                $event->setResult($result);
                $event->stopPropagation();

                return $result;
            }
        }

        $ip = $event->getParam('ip');
        if ($ip !== null) {
            if ($this->getFailurecount($ip) > 2) {
                $result = new \Zend\Authentication\Result(-4, $ip, 'Too many failed attempts');
                $event->setResult($result);
                $event->stopPropagation();

                return $result;
            }
        }
    }

    public function onAuthenticationFailed(\Zend\Authentication\Event\Authenticate $event)
    {
        $identity = $event->getParam('identity');
        if ($identity !== null) {
            $this->authFails[$identity]++;
        }

        $ip = $event->getParam('ip');
        if ($ip !== null) {
            $this->authFails[$ip]++;
        }
    }
}

$firewall = new Firewall();

$callback = function ($identity, $credential) {
    if ($identity === $credential) {
        return new \Zend\Stdlib\ArrayObject(['identity' => $identity, 'credential' => $credential]);
    }

    throw new \Exception('Authentication failed');
};

$adapter = new \Zend\Authentication\Adapter\Callback($callback);
$listener = new \Zend\Authentication\Listener\LegacyAdapterListener($adapter);

$events = new EventManager();
$events->attach('Authenticate', [$firewall, 'onAuthenticate'] , -1);
$events->attach('Authenticate', [$listener, 'onAuthenticate'], 10);
$events->attach('AuthenticationFailed', [$firewall, 'onAuthenticationFailed'] , -1);

$authService = new AuthenticationService($events);

$authService->authenticate(['ip' => '127.0.0.1', 'identity' => 'test', 'credential' => 'failed']);
$authService->authenticate(['ip' => '127.0.0.1', 'identity' => 'test', 'credential' => 'failed']);
$authService->authenticate(['ip' => '127.0.0.1', 'identity' => 'test2', 'credential' => 'failed']);

// result = failure to many attempts
$authService->authenticate(['ip' => '127.0.0.1', 'identity' => 'test2', 'credential' => 'failed']);