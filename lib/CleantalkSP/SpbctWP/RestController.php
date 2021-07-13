<?php

namespace CleantalkSP\SpbctWP;

class RestController extends \WP_REST_Controller {

	public function __construct()
	{
		$this->namespace = 'cleantalk-security/v1';
	}

	public function register_routes()
	{
        register_rest_route( $this->namespace, "/alt_sessions", array(
            array(
                'methods'             => 'POST',
                'callback'            => array( \CleantalkSP\SpbctWP\Variables\AltSessions::class, 'setFromRemote' ),
                'args'                => array(
                    'cookies' => array(
                        'type'     => 'array',
                        'required' => true,
                    ),
                ),
                'permission_callback' => '__return_true',
            ),
            array(
                'methods'             => 'GET',
                'callback'            => array( \CleantalkSP\SpbctWP\Variables\AltSessions::class, 'getFromRemote' ),
                'args'                => array(
                    'name' => array(
                        'type'     => 'string',
                        'required' => true,
                    ),
                ),
                'permission_callback' => '__return_true',
            )
        ) );
	}

}