<?php

use Zend\Authentication\AuthenticationService;
use Zend\EventManager\EventManager;

class AuditLog
{
    private $log;

    /**
     * AuditLog constructor.
     * @TODO add dependency for a psr logger
     * @param $log
     */
    public function __construct($log)
    {
        $this->log = $log;
    }

    public function onAuthenticationFailed(\Zend\Authentication\Event\Authenticate $event)
    {
        $this->log->warn(
            sprintf('Authenication Failure for (%s) from (%s)', $event->getParam('identity'), $event->getParam('ip'))
        );
    }
}

$auditLog = new AuditLog(new stdClass());

$callback = function ($identity, $credential) {
    if ($identity === $credential) {
        return new \Zend\Stdlib\ArrayObject(['identity' => $identity, 'credential' => $credential]);
    }

    throw new \Exception('Authentication failed');
};

$adapter = new \Zend\Authentication\Adapter\Callback($callback);

$authService = new AuthenticationService(null, $adapter);
$authService->addListener('AuthenticationFailed', [$auditLog, 'onAuthenticationFailed'] , -1);

$authService->authenticate(['ip' => '127.0.0.1', 'identity' => 'test', 'credential' => 'failed']);
