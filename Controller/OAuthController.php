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
	
	public $components = array('OAuth.OAuth', 'Auth', 'Session', 'Security','ThreeScale.ThreeScale');

	public $uses = array('User');

	public $helpers = array('Form');
	
	private $blackHoled = false;

/**
 * beforeFilter
 *  
 */
	public function beforeFilter() {
		parent::beforeFilter();
		$this->layout = 'default';
		$this->OAuth->authenticate = array(
			'fields' => array(
				'username' => 'username',
				'password' => 'passwd'
			)
		);
		$this->Auth->allow($this->OAuth->allowedActions);
		$this->Security->blackHoleCallback = 'blackHole';

		//Only authorize on the following methods
		if (!$this->request->is('post')) {
			if(in_array($this->params['action'], array('authorize','login'))){
				//The following checks to see if the client exists in the database. If not, it's created.
				if(isset($this->params->query['client_id'])){
					//Check to make sure that the app is valid. 
					$response = $this->ThreeScale->Client->oauth_authorize($this->params->query['client_id']);
					if ($response->isSuccess() === true) {
						$appDetails = $response->getApplication();
						$appExtDetails = $this->ThreeScale->Client->application($this->params->query['client_id'],$appDetails['key']); 
						$appExtDetailsClean = array(
							'id' => $appExtDetails['id'],
							'redirect_url' => $appExtDetails['redirect_url'],
							'description' => $appExtDetails['description'],
							'extra_fields' => $appExtDetails['extra_fields'],
							'plan' => $appExtDetails['plan'],
							'name' => $appExtDetails['name'],
							'state' => $appExtDetails['state']
						);
						unset($appExtDetails);
						$this->Session->write('OAuthApp.details', $appExtDetailsClean);
						unset($appExtDetailsClean);

						//Check to see if the client already exists in the database.
						$client = $this->OAuth->Client->find('count',array('conditions' => array('Client.client_id' => $this->params->query['client_id'])));
						if($client > 0){
							//The client exists. Let's update it with the latest 3scale information
							$success = $this->OAuth->Client->update(array(
								'Client' => array(
									'client_id' => $this->params->query['client_id'],
									'client_secret' => $appDetails['key'],
									'redirect_uri' => $appDetails['redirect_url']
								)));
						}else{
							//Add the client
							$success = $this->OAuth->Client->add(array(
								'Client' => array(
									'client_id' => $this->params->query['client_id'],
									'client_secret' => $appDetails['key'],
									'redirect_uri' => $appDetails['redirect_url']
								)));
						}

						//Add the redirect_uri
						$this->params->query['redirect_uri'] = $appDetails['redirect_url'];

						/*
						$usageReports = $response->getUsageReports();
						if(!empty($usageReports)){
							$usageReport  = $usageReports[0];
							if($usageReport->isExceeded()){
								$error = array(
									'code' => '300',
									'message' => 'Rate limit exceeded.'
								);
								$this->set(array(
									'error' => $error,
									'_serialize' => 'error'
								));
							}
						}*/
					} else {
						// Something's wrong with this app.
						$meta = array(
							'code' => 401,
							'message' => 'Unauthorized'
						);
						$notifications = array();
						$response = array(
							'error_type' => $response->getErrorCode(),
							'error_description' => $response->getErrorMessage()
						);
						$this->set(compact('meta','notifications','response'));
						return array(
							'_serialize' => array('meta','notifications','response')
						);
					}
				}
			}
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
			return $this->redirect(array('action' => 'login', '?' => $this->request->query));
		}

		if ($this->request->is('post')) {
			$this->validateRequest();

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
		if ($this->Session->check('OAuthApp.details')) {
				$OAuthAppDetails = $this->Session->read('OAuthApp.details');
				$this->Session->delete('OAuthApp.details');
		}else{
			$OAuthAppDetails = array();
		}
		$this->set(compact('OAuthParams','OAuthAppDetails'));
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
			$this->validateRequest();

			$loginData = array('User' => array(
					'username' => $this->request->data['User']['username'],
					'passwd' => $this->request->data['User']['passwd']
				));
			//Attempted login
			if ($this->Auth->login($loginData['User'])) {
				unset($loginData);
				$userData = $this->User->find('first',array(
					'conditions' => array(
						'User.username' => $this->request->data['User']['username']
					),
					'fields' => array('username','name','id','banned','active','role','private'),
					'recursive' => -1
				));
				$this->Session->write('Auth.User',$userData['User']); //Update the session

				//Write this to session so we can log them out after authenticating
				$this->Session->write('OAuth.logout', true);

				//Write the auth params to the session for later
				$this->Session->write('OAuth.params', $OAuthParams);

				//Off we go
				return $this->redirect(array('action' => 'authorize'));
			} else {
				$this->Session->setFlash(__('Username or password is incorrect'), 'default', array(), 'auth');
			}
		}
		$appName = $this->applicationDetails['name'];
		$this->set(compact('OAuthParams','appName'));
	}

/**
 * getUser method
 * Returns the current user's details.
 * @return array
 */
	private function getUser($request) {
		$username = env('PHP_AUTH_USER');
		$pass = env('PHP_AUTH_PW');

		if (empty($username) || empty($pass)) {
			return false;
		}
		return $this->_findUser($username, $pass);
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
		try {
			$this->OAuth->grantAccessToken();
		} catch (OAuth2ServerException $e) {
			$e->sendHttpResponse();
		}
		
	}
	
/**
 * Quick and dirty example implementation for protected resource
 * 
 * User accesible via $this->OAuth->user();
 * Single fields avaliable via $this->OAuth->user("id"); 
 * 
 */
	public function userinfo() {
		$this->layout = null;
		$user = $this->OAuth->user();
		$this->set(compact('user'));
	}
	
/**
 * Blackhold callback
 * 
 * OAuth requests will fail postValidation, so rather than disabling it completely
 * if the request does fail this check we store it in $this->blackHoled and then
 * when handling our forms we can use $this->validateRequest() to check if there
 * were any errors and handle them with an exception.
 * Requests that fail for reasons other than postValidation are handled here immediately
 * using the best guess for if it was a form or OAuth
 * 
 * @param string $type
 */
	public function blackHole($type) {
		$this->blackHoled = $type;

		if ($type != 'auth') {
			if (isset($this->request->data['_Token'])) {
				//Probably our form
				$this->validateRequest();
			} else {
				//Probably OAuth
				$e = new OAuth2ServerException(OAuth2::HTTP_BAD_REQUEST, OAuth2::ERROR_INVALID_REQUEST, 'Request Invalid.');
				$e->sendHttpResponse();
			}
		}
	}

/**
 * Check for any Security blackhole errors
 * 
 * @throws BadRequestException 
 */
	private function validateRequest() {
		if ($this->blackHoled) {
			//Has been blackholed before - naughty
			throw new BadRequestException(__d('OAuth', 'The request has been black-holed'));
		}
	}

}
