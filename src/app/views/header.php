<?php
session_start();
// add new product
$class = 'btn btn-info m-3';
echo $this->tag->linkTo(['product'.'?bearer='.$_SESSION['currUser'], 'Add new product!', 'class' => $class]);
// show all products
echo $this->tag->linkTo(['product/show'.'?bearer='.$_SESSION['currUser'], 'Show all products!', 'class' => $class]);
// place new order
echo $this->tag->linkTo(['order'.'?bearer='.$_SESSION['currUser'], 'Place new Order!', 'class' => $class]);
// show all orders
echo $this->tag->linkTo(['order/show'.'?bearer='.$_SESSION['currUser'], 'Show all Order!', 'class' => $class]);
// settings
echo $this->tag->linkTo(['setting'.'?bearer='.$_SESSION['currUser'], 'Setting', 'class' => $class]);
// add component
echo $this->tag->linkTo(['addcomponent'.'?bearer='.$_SESSION['currUser'], 'Add Component!', 'class' => $class]);
// add role
echo $this->tag->linkTo(['role'.'?bearer='.$_SESSION['currUser'], 'Add New Role', 'class' => $class]);
// acl page
echo $this->tag->linkTo(['aclpage/acl'.'?bearer='.$_SESSION['currUser'], 'Access Control', 'class' => $class]);
