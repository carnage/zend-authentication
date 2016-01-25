<?php

namespace Zend\Authentication\Event;

use Zend\EventManager\Event;

class Authenticate extends Event
{
    protected $name = 'Authenticate';

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