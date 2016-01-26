<?php

use Zend\Authentication\AuthenticationService;
use Zend\EventManager\EventManager;

$callback = function ($identity, $credential) {
    if ($identity === $credential) {
        return new \Zend\Stdlib\ArrayObject(['identity' => $identity, 'credential' => $credential]);
    }

    throw new \Exception('Authentication failed');
};

$adapter = new \Zend\Authentication\Adapter\Callback($callback);
$listener = new \Zend\Authentication\Listener\LegacyAdapterListener($adapter);

$callback2 = function ($identity, $credential) {
    if ($identity === 'test' && $credential === 'tester') {
        return new \Zend\Stdlib\ArrayObject(['identity' => $identity, 'credential' => $credential]);
    }

    throw new \Exception('Authentication failed');
};

$adapter2 = new \Zend\Authentication\Adapter\Callback($callback2);
$listener2 = new \Zend\Authentication\Listener\LegacyAdapterListener($adapter2);

$events = new EventManager();
$events->attach('Authenticate', [$listener, 'onAuthenticate'], 10);
$events->attach('Authenticate', [$listener2, 'onAuthenticate'], 20);

$authService = new AuthenticationService($events);

//auths against adapter 1
$authService->authenticate(['identity' => 'test', 'credential' => 'test']);

//auths against adapter 2
$authService->authenticate(['identity' => 'test', 'credential' => 'tester']);

