<?php


namespace CleantalkSP\Security\Firewall;


use CleantalkSP\Templates\DTO;

/**
 * Class Result
 *
 * Using it as contract between Firewall components
 *
 * @since   2.83
 * @version 1.0.0
 * @uses    \CleantalkSP\Templates\DTO
 * @package CleantalkSP\Security\Firewall
 */
class Result extends DTO
{
    /**
     * @var string Firewall module name
     */
	public $module        = 'FW';
    
    /**
     * @var string IP address
     */
	public $ip            = '';
    
    /**
     * @var string Firewall results status
     */
	public $status        = 'PASS';
    
    /**
     * @var int Is the Firewall result is from personal list
     */
	public $is_personal   = 0;
    
    /**
     * @var string Country code of the IP if present
     */
	public $country_code  = '';
    
    /**
     * @var int Integer that represent an IP address
     */
	public $network       = 0;
    
    /**
     * @var int Integer that represent a network mask
     */
	public $mask          = 0;
    
    /**
     * @var array The triggered WAF signature
     */
	public $pattern       = array();
    
    /**
     * @var int
     */
	public $signature_id = 0;
	
    /**
     * @var string The part of the request which triggered WAF
     */
	public $triggered_for = '';
    
    /**
     * @var string Shows what should WAF do with the result
     */
	public $waf_action = '';
	
	public function __construct($params = array())
	{
		parent::__construct($params);
		
		// Additional validation logic here
		// Additional sanitizing logic here
  
	}
}