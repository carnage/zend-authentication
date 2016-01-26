<?php

use Zend\Authentication\AuthenticationService;
use Zend\EventManager\EventManager;

class TwoFAListener
{
    public function onAuthenticate(\Zend\Authentication\Event\Authenticate $event)
    {
        $result = $event->getResult();
        if ($result->isValid()) {
            $prevResult = $event->getPreviousResult();
            $identity = $result->getIdentity();

            if ($prevResult !== null) {
                $identity = $prevResult->getIdentity();
            }

            if (isset($identity['do2fa']) && $identity['do2fa']) {
                $twoFactorResponse = $event->getParam('twoFactorResponse');

                if (isset($twoFactorResponse)) {
                    if (
                        $prevResult !== null &&
                        isset($prevResult->twoFactorToken) &&
                        $twoFactorResponse === $prevResult->twoFactorToken
                    ) {
                        $result = new \Zend\Authentication\Result(\Zend\Authentication\Result::SUCCESS, $identity);
                        $event->setResult($result);

                        return $result;
                    }
                }

                $result = new \Zend\Authentication\Result(-4, $identity, 'Requires 2 factor Auth');
                $result->twoFactorToken = 'efg456'; //generate randomly
                $event->setResult($result);
                $event->stopPropagation();

                return $result;

            }
        }

        return $result;
    }
}

$twoFaListener = new TwoFAListener();

$callback = function ($identity, $credential) {
    if ($identity === $credential) {
        return new \Zend\Stdlib\ArrayObject(['identity' => $identity, 'credential' => $credential, 'do2fa' => true]);
    }

    throw new \Exception('Authentication failed');
};

$adapter = new \Zend\Authentication\Adapter\Callback($callback);
$listener = new \Zend\Authentication\Listener\LegacyAdapterListener($adapter);

$events = new EventManager();
$events->attach('Authenticate', [$listener, 'onAuthenticate'], 10);
$events->attach('Authenticate', [$TwoFAlistener, 'onAuthenticate'], 20);

$authService = new AuthenticationService($events);

$authService->authenticate(['identity' => 'test', 'credential' => 'test']);

//result success with test identity
$authService->authenticate(['twoFactorResponse' => 'efg456']);