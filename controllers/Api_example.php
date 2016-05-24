<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Api_example extends CI_Controller
{
	private $token = '7c4a8d09ca3762af61e59520943dc26494f8941b';
	private $user = array('username'=>'admin', 'password'=>'123456');
	
	private $response = array('status'=>'', 'message'=>'', 'redirect'=>'', 'payload'=>'');
	
	public function __construct(){
		parent::__construct();
		$this->load->library('http_auth');
	}
	
	public function index(){
		$authorized = false;
		
		if($token = $this->http_auth->getToken()){
			if($this->_validateToken($token)){
				$authorized = true;
			}else{
				$this->response['message'] = 'Invalid token';
				$this->http_auth->requireToken(401);
			}
		}else{
			$this->response['message'] = 'Not authorized';
			$this->http_auth->requireToken();
		}
		
		if(! $authorized){
			$this->response['status'] = 0;
			$this->response['redirect'] = 'welcome/authenticate';
		}else{
			$this->response['status'] = 1;
			$this->response['message'] = 'Authorized Access';
			$this->response['payload'] = array('user_data'=>$this->user);
		}
		
		$this->_render();
	}
	
	public function authenticate(){
		$authenticated = false;
		
		if($username = $this->http_auth->getUsername()){
			$user = $this->_getUser($username);
			
			if($user and $this->http_auth->validateClient($user['username'], $user['password'])){
				$authenticated = true;
			}else{
				$this->response['message'] = 'Invalid Username or Password';
			}
		}else{
			$this->response['message'] = 'Not authorized';
		}
		
		if(! $authenticated){
			$this->response['status'] = 0;
			$this->response['redirect'] = 'welcome/authenticate';
			$this->http_auth->requireAuth();
		}else{
			$this->response['status'] = 1;
			$this->response['message'] = 'Authorized Access';
			$this->response['redirect'] = '/';
			$this->response['payload'] = array('access_token'=>$this->_generateToken());
		}
		
		$this->_render();
	}
	
	private function _render(){
		$this->output->set_content_type('application/json');
		$this->output->set_output(json_encode($this->response));
	}
	
	private function _getUser($username){
		return ($username == $this->user['username']) ? $this->user : NULL;
	}
	
	private function _generateToken(){
		return $this->token;
	}
	
	private function _validateToken($token){
		return ($token == $this->token);
	}
}
