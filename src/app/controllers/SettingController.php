<?php
use Phalcon\Mvc\Controller;

class SettingController extends Controller
{
    public function IndexAction()
    {
        // redirected to index view
    }

    public function addAction()
    {
        $settings = $this->db->fetchAll("SELECT * FROM settings", \Phalcon\Db\Enum::FETCH_ASSOC);
        $input = array(
            'title' => $this->escaper->escapeHtml($this->request->getPost('title')),
            'price' => $this->escaper->escapeHtml($this->request->getPost('defaultPrice')),
            'stock' => $this->escaper->escapeHtml($this->request->getPost('defaultStock')),
            'zip'   => $this->escaper->escapeHtml($this->request->getPost('defaultZip'))
        );
        if (isset($settings[0])) {
            $conn = $this->container->get('db');
            $conn->query(
                "update `settings` set `title`='$input[title]',
            `price`='$input[price]',
            `stock`='$input[stock]',
            `zip`='$input[zip]' where `id`='1'"
            );
        } else {
            // insert into settings db
            $this->db->insert(
                "settings",
                $input,
                [
                    'title',
                    'price',
                    'stock',
                    'zip'
                ]
            );
        }
        $this->response->redirect('/index/');
    }
}
