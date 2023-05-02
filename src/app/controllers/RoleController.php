<?php
use Phalcon\Mvc\Controller;

session_start();
class RoleController extends Controller
{
    public function indexAction()
    {
        // redirected to index view
    }
    public function addAction()
    {
        $role = $this->request->getPost();

        if (!isset($this->session->roles)) {
            $this->session->roles = [];
        }
        array_push($_SESSION['roles'], $role['roleName']);
        $this->response->redirect('/role?bearer='.$_SESSION['currUser']);
    }
}
