<?php defined('BASEPATH') OR exit('No direct script access allowed');
/**
 * Http Auth library for CodeIgniter
 * @author Sujeet <sujeetkv90@gmail.com>
 * @link https://github.com/sujeetkv/ci-http-auth
 */

class Http_auth
{
	protected $auth_type = 'basic'; // 'basic' or 'digest'
	protected $auth_name = 'Authentication Required';
	
	protected $user = array();
	protected $token = NULL;
	
	protected $auth_header = '';
	protected $auth_scheme = NULL;
	
	protected $token_error = array(
		401 => array(
			'error' => 'invalid_token',
			'description' => 'Invalid token'
		),
		403 => array(
			'error' => 'insufficient_scope',
			'description' => 'Insufficient privilege'
		)
	);
	
	/**
	 * Initialize library
	 * @param array $config
	 */
	public function __construct($config = array()){
		$this->_initialize($config);
		
		if(! in_array($this->auth_type, array('basic', 'digest'))){
			log_message('error', "Invalid 'auth_type' for Http Auth class");
			throw new Http_auth_Exception('Invalid \'auth_type\' for Http Auth class.');
		}
		
		log_message('debug', "Http Auth Class Initialized");
	}
	
	/**
	 * Get username in case of basic and digest authentication
	 */
	public function getUsername(){
		return empty($this->user) ? NULL : current(array_keys($this->user));
	}
	
	/**
	 * Get password  in case of basic authentication
	 * @param string $username
	 */
	public function getPassword($username){
		return ($this->auth_type == 'digest' or ! isset($this->user[$username])) ? NULL : $this->user[$username];
	}
	
	/**
	 * Validate client request with credentials
	 * @param string $username
	 * @param string $password
	 */
	public function validateClient($username, $password){
		if($this->auth_type == 'digest'){
			if(! isset($this->user[$username])){
				return false;
			}else{
				$realm = $this->auth_name;
				$auth_data = $this->user[$username];
				
				if($auth_data['username'] != $username){
					return false;
				}else{
					$request_method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
					
					$A1 = md5($auth_data['username'] . ':' . $realm . ':' . $password);
					$A2 = md5($request_method . ':' . $auth_data['uri']);
					
					$auth_response = md5($A1.':'.$auth_data['nonce'].':'.$auth_data['nc'].':'.$auth_data['cnonce'].':'.$auth_data['qop'].':'.$A2);
					
					return ($auth_data['response'] == $auth_response);
				}
			}
		}else{
			return (isset($this->user[$username]) && $this->user[$username] == $password);
		}
	}
	
	/**
	 * Prompt authorization header for auth
	 * @param mixed $response
	 * @param string $response_type
	 */
	public function requireAuth($response = '', $response_type = ''){
		$realm = $this->auth_name;
		
		$auth_header = ($this->auth_type == 'digest') 
						? 'Digest realm="'.$realm.'",qop="auth",nonce="'.uniqid().'",opaque="'.md5($realm).'"' 
						: 'Basic realm="'.$realm.'"';
		
		/* header('HTTP/1.1 401 Unauthorized', true, 401); */
		set_status_header(401);
		header('WWW-Authenticate: ' . $auth_header);
		if(!empty($response)){
			empty($response_type) or header('Content-Type: ' . $response_type);
			exit($response);
		}
	}
	
	/**
	 * Get token  in case of token authentication
	 */
	public function getToken(){
		return empty($this->token) ? NULL : $this->token;
	}
	
	/**
	 * Prompt authorization header for token
	 * @param int $response_code
	 * @param mixed $response
	 * @param string $response_type
	 */
	public function requireToken($response_code = NULL, $response = '', $response_type = ''){
		$realm = $this->auth_name;
		
		if(isset($this->token_error[$response_code])){
			$token_error = $this->token_error[$response_code];
			$auth_header = 'Bearer realm="'.$realm.'",error="'.$token_error['error'].'",error_description="'.$token_error['description'].'"';
		}else{
			$auth_header = 'Bearer realm="'.$realm.'"';
			$response_code = 401;
		}
		
		set_status_header($response_code);
		header('WWW-Authenticate: ' . $auth_header);
		if(!empty($response)){
			empty($response_type) or header('Content-Type: ' . $response_type);
			exit($response);
		}
	}
	
	/**
	 * Get current auth scheme (auth|token)
	 */
	public function authScheme(){
		return $this->auth_scheme;
	}
	
	protected function _initialize($config){
		if(is_array($config)){
			if(isset($config['auth_type'])) $this->auth_type = strtolower($config['auth_type']);
			if(isset($config['auth_name'])) $this->auth_name = $config['auth_name'];
		}
		$this->_setAuthScheme();
		
		($this->auth_type == 'digest') ? $this->_processDigestHeader() : $this->_processBasicHeader();
		
		$this->_processBearerHeader();
	}
	
	protected function _setAuthScheme(){
		$this->_setAuthHeader();
		
		if(isset($_SERVER['PHP_AUTH_DIGEST']) or stripos($this->auth_header, 'digest') === 0 
		or (isset($_SERVER['PHP_AUTH_USER']) and isset($_SERVER['PHP_AUTH_PW'])) 
		or stripos($this->auth_header, 'basic') === 0){
			$this->auth_scheme = 'auth';
		}elseif(stripos($this->auth_header, 'bearer') === 0){
			$this->auth_scheme = 'token';
		}
	}
	
	protected function _setAuthHeader(){
		if(function_exists('apache_request_headers') and $headers = apache_request_headers() 
		and $headers = array_change_key_case($headers) and isset($headers['authorization'])){
			$this->auth_header = $headers['authorization'];
		}elseif(isset($_SERVER['HTTP_AUTHORIZATION'])){
			$this->auth_header = $_SERVER['HTTP_AUTHORIZATION'];
		}
	}
	
	protected function _processBasicHeader(){
		$username = '';
		$password = '';
		
		if(isset($_SERVER['PHP_AUTH_USER'])){
			$username = $_SERVER['PHP_AUTH_USER'];
			$password = isset($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : '';
		}elseif(stripos($this->auth_header, 'basic') === 0){
			list($username, $password) = explode(':', base64_decode(substr($this->auth_header, 6)));
		}
		
		if(!empty($username)){
			$this->user[$username] = $password;
		}
	}
	
	protected function _processDigestHeader(){
		$auth_digest = '';
		
		if(isset($_SERVER['PHP_AUTH_DIGEST'])){
			$auth_digest = $_SERVER['PHP_AUTH_DIGEST'];
		}elseif(stripos($this->auth_header, 'digest') === 0){
			$auth_digest = substr($this->auth_header, 7);
		}
		
		if(!empty($auth_digest) and $auth_data = $this->_parseDigest($auth_digest)){
			$this->user[$auth_data['username']] = $auth_data;
		}
	}
	
	protected function _processBearerHeader(){
		$token = '';
		
		if(stripos($this->auth_header, 'bearer') === 0){
			$token = substr($this->auth_header, 7);
		}
		
		if(!empty($token)){
			$this->token = $token;
		}
	}
	
	protected function _parseDigest($auth_digest){
		$needed_parts = array('nonce'=>1, 'nc'=>1, 'cnonce'=>1, 'qop'=>1, 'username'=>1, 'uri'=>1, 'response'=>1);
		$data = array();
		$keys = implode('|', array_keys($needed_parts));
		
		preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $auth_digest, $matches, PREG_SET_ORDER);
		
		foreach($matches as $m){
			$data[$m[1]] = ($m[3]) ? $m[3] : $m[4];
			unset($needed_parts[$m[1]]);
		}
		
		return ($needed_parts) ? false : $data;
	}
}

class Http_auth_Exception extends Exception
{
	
}

/* End of file Http_auth.php */