<?php
use Phalcon\Mvc\Controller;
use handler\Aware\Aware;
use handler\Listener\Listener;
use Phalcon\Events\Manager as EventsManager;

class OrderController extends Controller
{
    public function IndexAction()
    {
        // generate dropdown here
        $product = $this->db->fetchAll("SELECT * FROM products", \Phalcon\Db\Enum::FETCH_ASSOC);
        $output = "<label for=\"products\">Choose a product</label>
        <select name=\"products\" id=\"products\">";
        foreach ($product as $value) {
            $output .= "<option value=\"$value[name]\">$value[name]</option>";
        }
        $output .= '</select>';
        $this->view->dropdown = $output;
    }

    public function addAction()
    {
        $eventsManager = new EventsManager();
        $component = new Aware();

        $component->setEventsManager($eventsManager);
        $eventsManager->attach(
            'application:beforeOrderAdd',
            new Listener()
        );
        $component->process();
        $arr = array(
            'customerName'    => $this->escaper->escapeHtml($this->request->getPost('customerName')),
            'customerAddress' => $this->escaper->escapeHtml($this->request->getPost('customerAddress')),
            'zip'             => $this->escaper->escapeHtml($this->request->getPost('zip')),
            'products'        => $this->escaper->escapeHtml($this->request->getPost('products')),
            'quantity'        => $this->escaper->escapeHtml($this->request->getPost('quantity'))
        );
        $this->db->insert(
            "orders",
            $arr,
            [
                'customerName',
                'customerAddress',
                'zip',
                'products',
                'quantity'
            ]
        );
        $this->response->redirect('/order/show');
        $this->view->disable();
    }

    public function showAction()
    {
        $order = $this->db->fetchAll("SELECT * FROM orders", \Phalcon\Db\Enum::FETCH_ASSOC);
        $output = '<table class = "table table-bordered table-striped"><tr><th>Order Id</th>
        <th>Customer Name</th>
        <th>Customer Address</th>
        <th>Zip</th>
        <th>Product</th>
        <th>Quantity</th></tr>';
        foreach ($order as $value) {
            $output .= '<tr>';
            $output .= "<td>$value[id]</td>";
            $output .= "<td>$value[customerName]</td>";
            $output .= "<td>$value[customerAddress]</td>";
            $output .= "<td>$value[zip]</td>";
            $output .= "<td>$value[products]</td>";
            $output .= "<td>$value[quantity]</td></tr>";
        }
        $output .= '</table>';
        $this->view->result = $output;
    }
}
