<?php

App::uses('OAuthAppModel', 'OAuth.Model');
App::uses('OAuthComponent', 'OAuth.Controller/Component');
App::uses('String', 'Utility');
App::uses('Security', 'Utility');

/**
 * Client Model
 *
 * @property AccessToken $AccessToken
 * @property AuthCode $AuthCode
 * @property RefreshToken $RefreshToken
 */
class Client extends OAuthAppModel {
/**
 * Primary key field
 *
 * @var string
 */
	public $primaryKey = 'client_id';
/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'client_id';

/**
 * Secret to distribute when using addClient
 * 
 * @var type 
 */	
	protected $addClientSecret = false;

/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
		'client_id' => array(
			'isUnique' => array(
				'rule' => array('isUnique'),
			),
			'notempty' => array(
				'rule' => array('notempty'),
			),
		),
		'redirect_uri' => array(
			'notempty' => array(
				'rule' => array('notempty'),
			),
		),
	);

/**
 * hasMany associations
 *
 * @var array
 */
	public $hasMany = array(
		'AccessToken' => array(
			'className' => 'OAuth.AccessToken',
			'foreignKey' => 'client_id',
			'dependent' => false,
			'conditions' => '',
			'fields' => '',
			'order' => '',
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		),
		'AuthCode' => array(
			'className' => 'OAuth.AuthCode',
			'foreignKey' => 'client_id',
			'dependent' => false,
			'conditions' => '',
			'fields' => '',
			'order' => '',
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		),
		'RefreshToken' => array(
			'className' => 'OAuth.RefreshToken',
			'foreignKey' => 'client_id',
			'dependent' => false,
			'conditions' => '',
			'fields' => '',
			'order' => '',
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		)
	);


/**
 * UpdateClient
 * 
 * Convinience function for updating a client
 * 
 * @param mixed $data Either an array (e.g. $controller->request->data) or string redirect_uri
 * @return booleen Success of failure
 */
	public function update($data = null) {
		$this->data['Client'] = array();


		//Set the client id
		if (is_array($data) && is_array($data['Client']) && array_key_exists('client_id', $data['Client'])) {
			$this->data['Client']['client_id'] = $data['Client']['client_id'];
		}else{
			return false;
		}

		$this->read(null, $this->data['Client']['client_id']);

		//Set the client secret
		if (is_array($data) && is_array($data['Client']) && array_key_exists('client_secret', $data['Client'])) {
			$this->data['Client']['client_secret'] = $data['Client']['client_secret'];
		}else{
			return false;
		}

		if (is_array($data) && is_array($data['Client']) && array_key_exists('redirect_uri', $data['Client'])) {
			$this->data['Client']['redirect_uri'] = $data['Client']['redirect_uri'];
		} elseif (is_string($data)){
			$this->data['Client']['redirect_uri'] = $data;
		} else {
			return false;
		}

		return $this->save($this->data);
	}
	
/**
 * AddClient
 * 
 * Convinience function for adding client, will create a uuid client_id and random secret
 * 
 * @param mixed $data Either an array (e.g. $controller->request->data) or string redirect_uri
 * @return booleen Success of failure
 */
	public function add($data = null) {
		$this->data['Client'] = array();

		if (is_array($data) && is_array($data['Client']) && array_key_exists('redirect_uri', $data['Client'])) {
			$this->data['Client']['redirect_uri'] = $data['Client']['redirect_uri'];
		} elseif (is_string($data)){
			$this->data['Client']['redirect_uri'] = $data;
		} else {
			return false;
		}

		/**
		 * Only create a client id if one isn't passed.
		 */
		if(empty($this->data['Client']['client_id'])){
			//You may wish to change this
			$this->data['Client']['client_id'] = base64_encode(uniqid() . substr(uniqid(), 11, 2));	// e.g. NGYcZDRjODcxYzFkY2Rk (seems popular format)
			//$this->data['Client']['client_id'] = uniqid();					// e.g. 4f3d4c8602346
			//$this->data['Client']['client_id'] = str_replace('.', '', uniqid('', true));		// e.g. 4f3d4c860235a529118898
			//$this->data['Client']['client_id'] = str_replace('-', '', String::uuid());		// e.g. 4f3d4c80cb204b6a8e580a006f97281a
		}

		/**
		 * Create a client secret, only if one doesn't already exist.
		 */
		if(empty($this->data['Client']['client_secret'])){
			$this->addClientSecret = $this->newClientSecret();
			$this->data['Client']['client_secret'] = $this->addClientSecret;
		}

		/*$this->addClientSecret = $this->newClientSecret();
		$this->data['Client']['client_secret'] = $this->addClientSecret;*/

		return $this->save($this->data);
	}

/**
 * Create a new, pretty (as in moderately, not beautiful - that can't be guaranteed ;-) random client secret
 *
 * @return string
 */
	public function newClientSecret() {
		$length = 40;
		$chars = '@#!%*+/-=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		$str = '';
		$count = strlen($chars);
		while ($length--) {
			$str .= $chars[mt_rand(0, $count - 1)];
		}
		return OAuthComponent::hash($str);
	}
	

	public function beforeSave($options = array()) {
		//$this->data['Client']['client_secret'] = OAuthComponent::hash($this->data['Client']['client_secret']);
		return true;
	}
	
	public function afterSave($created) {
		if ($this->addClientSecret) {
			$this->data['Client']['client_secret'] = $this->addClientSecret;
		}
		return true;
	}

}