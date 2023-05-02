<?php
session_start();
use Phalcon\Mvc\Controller;

class AddcomponentController extends Controller
{
    public function indexAction()
    {
        // redirected to index view
    }

    public function addAction()
    {
        $controller = $this->request->getPost('controller');
        $action = $this->request->getPost('action');
        if (!isset($this->session->controllerList)) {
            $this->session->controllerList = [];
        }
        if (!isset($this->session->controllerList[$controller])) {
            $_SESSION['controllerList'][$controller] = [];
        }
        if (!isset($this->session->controllerList[$controller][$action])) {
            array_push($_SESSION['controllerList'][$controller], $action);
        }
        $this->response->redirect('/addcomponent/index?bearer='.$_SESSION['currUser']);
    }
}
