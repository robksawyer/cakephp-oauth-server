<?php
/**
 * CakePHP OAuth Server Plugin
 * 
 * This is an example controller providing the necessary endpoints
 * 
 * @author Thom Seddon <thom@seddonmedia.co.uk>
 * @see https://github.com/thomseddon/cakephp-oauth-server
 *  
 */

App::uses('OAuthAppController', 'OAuth.Controller');

/**
 * Clients Controller
 *
 * @property Client $Client
 */
class OAuthController extends OAuthAppController {
	
	public $components = array('OAuth.OAuth', 'Auth', 'Session', 'Security');

	public $uses = array('Users');

	public $helpers = array('Form');

/**
 * beforeFilter
 *  
 */
	public function beforeFilter() {
		parent::beforeFilter();
		$this->OAuth->allow('test');
		$this->OAuth->authenticate = array('fields' => array('username' => 'email'));
		if ($this->request->is('post') && (!isset($this->request->data['User']) || !isset($this->request->data['Authorize']))) {
			//If its a post, but not one of our own forms (watch if you fiddle with the form names)
			$this->Security->validatePost = false;
		}
	}

/**
 * Example Authorize Endpoint
 * 
 * Send users here first for authorization_code grant mechanism
 * 
 * Required params (GET or POST):
 *	- response_type = code
 *	- client_id
 *	- redirect_url
 *  
 */
	public function authorize () {

		if (!$this->Auth->loggedIn()) {
			$this->redirect(array('action' => 'login', '?' => $this->request->query));
		}
		
		if ($this->request->is('post')) {
			$userId = $this->Auth->user('id');

			if ($this->Session->check('OAuth.logout')) {
				$this->Auth->logout();
				$this->Session->delete('OAuth.logout');
			}

			//Did they accept the form? Adjust accordingly
			$accepted = $this->request->data['accept'] == 'Yep';
			try {
				$this->OAuth->finishClientAuthorization($accepted, $userId, $this->request->data['Authorize']);
			} catch (OAuth2RedirectException $e) {
				$e->sendHttpResponse();
			}
		}

		// Clickjacking prevention (supported by IE8+, FF3.6.9+, Opera10.5+, Safari4+, Chrome 4.1.249.1042+)
		$this->response->header('X-Frame-Options: DENY');

		if ($this->Session->check('OAuth.params')) {
				$OAuthParams = $this->Session->read('OAuth.params');
				$this->Session->delete('OAuth.params');
		} else {
			try {
				$OAuthParams =  $this->OAuth->getAuthorizeParams();
			} catch (Exception $e){
				$e->sendHttpResponse();
			}
		}
		$this->set(compact('OAuthParams'));
	}

/**
 * Example Login Action
 * 
 * Users must authorize themselves before granting the app authorization
 * Allows login state to be maintained after authorization
 *  
 */
	public function login () {
		$OAuthParams = $this->OAuth->getAuthorizeParams();
		if ($this->request->is('post')) {
			//Attempted login
			if ($this->Auth->login()) {
				//Write this to session so we can log them out after authenticating
				$this->Session->write('OAuth.logout', true);
				
				//Write the auth params to the session for later
				$this->Session->write('OAuth.params', $OAuthParams);
				
				//Off we go
				$this->redirect(array('action' => 'authorize'));
			} else {
				$this->Session->setFlash(__('Username or password is incorrect'), 'default', array(), 'auth');
			}
		}
		$this->set(compact('OAuthParams'));
	}


/**
 * Example Token Endpoint - this is where clients can retrieve an access token
 * 
 * Grant types and parameters:
 * 1) authorization_code - exchange code for token
 *	- code
 *	- client_id
 *	- client_secret
 *
 * 2) refresh_token - exchange refresh_token for token
 *	- refresh_token
 *	- client_id
 *	- client_secret
 * 
 * 3) password - exchange raw details for token
 *	- username
 *	- password
 *	- client_id
 *	- client_secret
 *  
 */
	public function token(){
		$this->autoRender = false;
		$this->Security->csrfCheck = false;
		try {
			$this->OAuth->grantAccessToken();
		} catch (OAuth2ServerException $e) {
			$e->sendHttpResponse();
		}
		
	}
	
/**
 * Quick and dirty example implementation for protecetd resource
 * 
 * User accesible via $this->OAuth->user();
 * Single fields avaliable via $this->OAuth->user("id"); 
 * 
 */
	public function userinfo() {
		$this->autoRender = false;
		$user = $this->OAuth->user();
		echo json_encode($user);
	}
	
	public function test() {
		$this->autoRender = false;
		pr($this->OAuth->Client->add('http://www.example.com'));
		
	}
	
}