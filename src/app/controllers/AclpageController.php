<?php
use Phalcon\Mvc\Controller;

class AclpageController extends Controller
{
    public function indexAction()
    {
        // redirected to index view
        $this->response->redirect('/aclpage/acl');
    }

    public function aclAction()
    {
        // give access (role, controller, action);
        $role = $this->request->getPost('role');
        $controller = $this->request->getPost('controller');
        $action = $this->request->getPost('action');
        $arr = array('role' => $role, 'controller' => $controller, 'action' => $action);
        if (!isset($this->session->accessList)) {
            $this->session->accessList = array();
        }
        array_push($_SESSION['accessList'], $arr);
    }
    public function handlerAction()
    {
        $res = "";
        foreach ($this->session->controllerList as $key => $value) {
            if ($key == $_POST['controller']) {
                foreach ($value as $v) {
                    $res .= "<option value=$v>$v</option>";
                }
            }
        }
        return $res;
    }
}
