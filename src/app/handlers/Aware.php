<?php
namespace handler\Aware;

use Phalcon\Di\Injectable;
use Phalcon\Events\EventsAwareInterface;
use Phalcon\Events\ManagerInterface;

class Aware extends Injectable implements EventsAwareInterface
{
    protected $eventsManager;

    public function getEventsManager(): ManagerInterface
    {
        return $this->eventsManager;
    }

    public function setEventsManager(ManagerInterface $eventsManager): void
    {
        $this->eventsManager = $eventsManager;
    }

    public function process()
    {
        $this->eventsManager->fire('application:beforeProductAdd', $this);
        $this->eventsManager->fire('application:beforeOrderAdd', $this);
        $this->eventsManager->fire('application:beforeHanldeRequest', $this);
    }
}
