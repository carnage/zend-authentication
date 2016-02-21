<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2015 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace Zend\Authentication;

use Zend\Authentication\Event\Authenticate;
use Zend\Authentication\Event\AuthenticationFailed;
use Zend\Authentication\Event\AuthenticationSucceeded;
use Zend\Authentication\Listener\AuthenticationAdapterListener;
use Zend\EventManager\EventManager;
use Zend\EventManager\EventManagerInterface;

class AuthenticationService implements AuthenticationServiceInterface
{
    /**
     * Persistent storage handler
     *
     * @var Storage\StorageInterface
     */
    protected $storage = null;

    /**
     * Authentication adapter
     *
     * @var EventManagerInterface
     */
    protected $events;

    /**
     * Constructor
     *
     * @param EventManagerInterface $eventManager
     * @param Storage\StorageInterface $storage
     */
    public function __construct(Storage\StorageInterface $storage = null, Adapter\AdapterInterface $adapter = null, $priority = 10)
    {
        if (null !== $storage) {
            $this->setStorage($storage);
        }

        $this->events = new EventManager();
        if ($adapter !== null) {
            $this->addAdapter($adapter, $priority);
        }
    }


    /**
     * Returns the persistent storage handler
     *
     * Session storage is used by default unless a different storage adapter has been set.
     *
     * @return Storage\StorageInterface
     */
    public function getStorage()
    {
        if (null === $this->storage) {
            $this->setStorage(new Storage\Session());
        }

        return $this->storage;
    }

    /**
     * Sets the persistent storage handler
     *
     * @param  Storage\StorageInterface $storage
     * @return AuthenticationService Provides a fluent interface
     */
    public function setStorage(Storage\StorageInterface $storage)
    {
        $this->storage = $storage;
        return $this;
    }

    /**
     * Authenticates against the supplied adapter
     *
     * @? This is currently a BC break the original takes an auth adapter as a parameter. This still conforms to the interface though.
     *
     * @param array $authenticationContext
     * @return Result
     */
    public function authenticate($authenticationContext = [])
    {
        $event = new Authenticate();
        $event->setTarget($this);
        $event->setParams($authenticationContext);
        $event->setPreviousResult($this->getResult());

        $this->events->triggerEvent($event);

        $result = $event->getResult();

        if ($result->isValid()) {
            $event = new AuthenticationSucceeded();
        } else {
            $event = new AuthenticationFailed();
        }

        $event->setTarget($this);
        $event->setResult($result);
        $event->setParams($authenticationContext);

        $this->events->trigger($event);

        /**
         * ZF-7546 - prevent multiple successive calls from storing inconsistent results
         * Ensure storage has clean state
         */
        if ($this->hasIdentity()) {
            $this->clearIdentity();
        }

        $this->getStorage()->write($result);

        return $result;
    }

    /**
     * Returns true if and only if an identity is available from storage
     *
     * @return bool
     */
    public function hasIdentity()
    {
        return !$this->getStorage()->isEmpty() && $this->getStorage()->read()->isValid();
    }

    /**
     * Returns the identity from storage or null if no identity is available
     *
     * @return mixed|null
     */
    public function getIdentity()
    {
        $result = $this->getResult();

        if ($result !== null && $result->isValid()) {
            return $result->getIdentity();
        }

        return null;
    }

    /**
     * Clears the identity from persistent storage
     *
     * @return void
     */
    public function clearIdentity()
    {
        $this->getStorage()->clear();
    }

    /**
     * @param Adapter\AdapterInterface $adapter
     * @param int $priority
     */
    public function addAdapter(Adapter\AdapterInterface $adapter, $priority = 10)
    {
        $listener = new AuthenticationAdapterListener($adapter);
        $this->events->attach('Authenticate', [$listener, 'onAuthenticate'], $priority);
    }

    /**
     * @? Should there be a separate method for each event type instead of passing the event as a string?
     *
     * @param $event
     * @param callable $listener
     * @param $priority
     */
    public function addListener($event, callable $listener, $priority)
    {
        $this->events->attach($event, $listener, $priority);
    }

    /**
     * @return Result|null
     */
    private function getResult()
    {
        $storage = $this->getStorage();

        if ($storage->isEmpty()) {
            return null;
        }

        $result = $storage->read();
        return $result;
    }
}
