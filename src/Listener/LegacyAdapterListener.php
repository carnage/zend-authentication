<?php

namespace Zend\Authentication\Listener;

use Zend\Authentication\Adapter\AdapterInterface;
use Zend\Authentication\Adapter\ValidatableAdapterInterface;
use Zend\Authentication\Event\Authenticate;
use Zend\Authentication\Result;

class LegacyAdapterListener
{
    /**
     * @var AdapterInterface
     */
    private $adapter;

    /**
     * LegacyAdapterListener constructor.
     * @param AdapterInterface $adapter
     */
    public function __construct(AdapterInterface $adapter)
    {
        $this->adapter = $adapter;
    }

    public function onAuthenticate(Authenticate $event)
    {
        $result = $event->getResult();
        if ($result instanceof Result && $result->isValid()) {
            //If a previous adapter has already returned a valid result don't change that
            return null;
        }

        if ($this->adapter instanceof ValidatableAdapterInterface) {
            $this->adapter->setIdentity($event->getParam('identity'));
            $this->adapter->setCredential($event->getParam('credential'));
        }

        $result = $this->adapter->authenticate();

        $event->setResult($result);

        return $result;
    }
}