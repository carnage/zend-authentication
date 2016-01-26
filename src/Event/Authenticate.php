<?php

namespace Zend\Authentication\Event;

use Zend\EventManager\Event;

class Authenticate extends Event
{
    protected $name = 'Authenticate';

    protected $result;

    protected $previousResult;

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

    /**
     * @return mixed
     */
    public function getPreviousResult()
    {
        return $this->previousResult;
    }

    /**
     * @param mixed $previousResult
     */
    public function setPreviousResult($previousResult)
    {
        $this->previousResult = $previousResult;
    }
}