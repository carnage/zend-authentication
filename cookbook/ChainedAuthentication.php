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

$callback2 = function ($identity, $credential) {
    if ($identity === 'test' && $credential === 'tester') {
        return new \Zend\Stdlib\ArrayObject(['identity' => $identity, 'credential' => $credential]);
    }

    throw new \Exception('Authentication failed');
};

$adapter2 = new \Zend\Authentication\Adapter\Callback($callback2);

$authService = new AuthenticationService(null, $adapter, 10);
$authService->addAdapter($adapter2, 20);

//auths against adapter 1
$authService->authenticate(['identity' => 'test', 'credential' => 'test']);

//auths against adapter 2
$authService->authenticate(['identity' => 'test', 'credential' => 'tester']);

