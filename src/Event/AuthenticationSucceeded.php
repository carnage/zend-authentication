<?php

namespace Zend\Authentication\Event;

use Zend\EventManager\Event;

class AuthenticationSucceeded extends Event
{
    protected $name = 'AuthenticationSucceeded';

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