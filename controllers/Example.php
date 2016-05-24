<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Example extends CI_Controller
{
	public function __construct(){
		parent::__construct();
		
		$this->load->model('demo_model'); // any auth model
	}
	
	public function basic_auth(){
		$this->load->library('http_auth');
		
		$username = $this->http_auth->getUsername();
		$password = $this->http_auth->getPassword($username);
		
		if(! $this->demo_model->userExists($username, $password) or ! $this->http_auth->validateClient($username, $password)){
			// not authorized
			$this->http_auth->requireAuth('Not authorized', 'text/plain');
		}else{
			// authorized
		}
	}
	
	public function digest_auth(){
		$this->load->library('http_auth', array('auth_type'=>'digest'));
		
		$username = $this->http_auth->getUsername();
		
		$password = $this->demo_model->userPassword($username);
		
		if(! $password or ! $this->http_auth->validateClient($username, $password)){
			// not authorized
			$this->http_auth->requireAuth('Not authorized', 'text/plain');
		}else{
			// authorized
		}
	}
	
	public function token_auth(){
		$this->load->library('http_auth');
		
		if($token = $this->http_auth->getToken()){
			if(! $this->demo_model->validateToken($token)){
				// invalid token
				$this->http_auth->requireToken(401, 'Not authorized', 'text/plain');
			}else{
				// token valid
			}
		}else{
			// token not available
			$this->http_auth->requireToken(NULL, 'Not authorized', 'text/plain');
		}
	}
}
