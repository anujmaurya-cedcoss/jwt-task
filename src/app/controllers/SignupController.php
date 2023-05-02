<?php
use Phalcon\Mvc\Controller;
use Phalcon\Security\JWT\Signer\Hmac;
use Phalcon\Security\JWT\Builder;

class SignupController extends Controller
{
    public function indexAction()
    {
        $name = $this->escaper->escapeHtml($this->request->getPost('name'));
        $email = $this->escaper->escapeHtml($this->request->getPost('email'));
        $password = $this->escaper->escapeHtml($this->request->getPost('password'));
        $role = $this->escaper->escapeHtml($this->request->getPost('role'));
        if ($name != '' && $email != '' && $password != '' && $role != '') {
            $signer = new Hmac();
            // Builder object
            $builder = new Builder($signer);

            $now = new DateTimeImmutable();
            $issued = $now->getTimestamp();
            $notBefore = $now->modify('-1 minute')->getTimestamp();
            $expires = $now->modify('+1 day')->getTimestamp();
            $passphrase = 'QcMpZ&b&mo3TPsPk668J6QH8JA$&U&m2';

            // Setup
            $builder
                ->setContentType('application/json') // cty - header
                ->setExpirationTime($expires) // exp
                ->setId('currUser') // JTI id
                ->setIssuedAt($issued) // iat
                ->setNotBefore($notBefore) // nbf
                ->setSubject($role) // sub
                ->setPassphrase($passphrase) // password
            ;
            $tokenObject = $builder->getToken();
            $this->session->currUser = $tokenObject->getToken();
            $this->response->redirect('/product/show?bearer='.$this->session->currUser);
        } else {
            // user not verified
        }
    }
}
