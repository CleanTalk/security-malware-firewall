<?php


namespace CleantalkSP\Security;

use CleantalkSP\Variables\Server;

class RenameLoginPage{
    
    /**
     * Login slug to make URL from it
     * @var string
     */
	protected $login_slug    = 'login';
    
    /**
     * redirect slug to make URL from it
     * @var string
     */
	protected $redirect_slug = '404';
    
    /**
     * New URL of login page
     * @var
     */
	protected $login_url;
    
    /**
     * URL to redirect from default login page
     * @var string
     */
	protected $redirect_url;
    
    /**
     * Parsed REQUEST_URI
     * @var array
     */
    protected $request;
	
	public function __construct( $login_slug, $redirect_slug ){
		
		$this->login_slug    = $login_slug;
		$this->redirect_slug = $redirect_slug;
        
        $this->request         = parse_url( Server::get( 'REQUEST_URI' ) ) ?: array();
        $this->request['path'] = isset( $this->request['path'] ) ? $this->request['path'] : '';
		
	}
	
}