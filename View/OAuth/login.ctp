<?php

	echo $this->Session->flash('auth');

	echo $this->Form->create('User');

	foreach ($OAuthParams as $key => $value) {
		echo $this->Form->hidden(h($key), array('value' => h($value)));
	}

?>

Please login

<?php
	echo $this->Form->input('User.username');
	echo $this->Form->input('User.passwd',array('label' => 'Password'));

	echo $this->Form->end('submit');

?>
