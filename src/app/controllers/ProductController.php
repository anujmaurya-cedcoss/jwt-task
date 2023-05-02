<?php
use Phalcon\Mvc\Controller;
use handler\Aware\Aware;
use handler\Listener\Listener;
use Phalcon\Events\Manager as EventsManager;

class ProductController extends Controller
{
    public function IndexAction()
    {
        // redirected to view
    }
    public function ShowAction()
    {
        $product = $this->db->fetchAll("SELECT * FROM products", \Phalcon\Db\Enum::FETCH_ASSOC);
        $output = '<table class = "table table-bordered table-striped"><tr><th>Product Id</th>
        <th>Product Name</th>
        <th>Product Description</th>
        <th>Product Tags</th>
        <th>Product Price</th>
        <th>Product Stock</th></tr>';
        foreach ($product as $key => $value) {
            $output .= '<tr>';
            $output .= "<td>$value[id]</td>";
            $output .= "<td>$value[name]</td>";
            $output .= "<td>$value[description]</td>";
            $output .= "<td>$value[tags]</td>";
            $output .= "<td>$value[price]</td>";
            $output .= "<td>$value[stock]</td></tr>";
        }
        $output .= '</table>';
        $this->view->result = $output;
    }
    public function AddAction()
    {
        $eventsManager = new EventsManager();
        $component = new Aware();

        $component->setEventsManager($eventsManager);
        $eventsManager->attach(
            'application:beforeProductAdd',
            new Listener()
        );
        $component->process();

        $input = array(
            'name'        => $this->escaper->escapeHtml($this->request->getPost('name')),
            'description' => $this->escaper->escapeHtml($this->request->getPost('description')),
            'tags'        => $this->escaper->escapeHtml($this->request->getPost('tags')),
            'price'       => $this->escaper->escapeHtml($this->request->getPost('price')),
            'stock'       => $this->escaper->escapeHtml($this->request->getPost('stock')),
        );
        $this->db->insert(
            "products",
            $input,
            [
                'name',
                'description',
                'tags',
                'price',
                'stock'
            ]
        );
        $this->response->redirect('/product/show');
        $this->view->disable();
    }
}
