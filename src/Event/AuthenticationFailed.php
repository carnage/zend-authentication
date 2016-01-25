<?php

namespace Zend\Authentication\Event;

use Zend\EventManager\Event;

class AuthenticationFailed extends Event
{
    protected $name = 'AuthenticationFailed';

    protected $result;

    /**
     * @return mixed
     */
    public function getResult()
    {
        return $this->result;
    }

    /**
     * @param mixed $result
     */
    public function setResult($result)
    {
        $this->result = $result;
    }
}