<?php

namespace CleantalkSP\SpbctWP;

use CleantalkSP\Variables\Server;
use CleantalkSP\SpbctWP\Helpers\Helper;
use CleantalkSP\Security\Firewall\Result;

/**
 * CleanTalk SpamFireWall base class.
 * Compatible with any CMS.
 *
 * @depends       \CleantalkSP\SpbctWP\Helper class
 * @depends       \CleantalkSP\SpbctWP\API class
 * @depends       \CleantalkSP\SpbctWP\DB class
 *
 * @version       4.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/php-antispam
 */
class Firewall extends \CleantalkSP\Security\Firewall {
	
	/**
	 * Creates Database driver instance.
	 *
	 * @param mixed $db database handler
	 */
	public function __construct( $db = null ){
		$this->db = DB::getInstance();
		parent::__construct( $db );
	}
	
	/**
	 * Use this method to handle logs updating by the module.
	 *
     * @param Result $fw_result
	 *
	 * @return void
	 */
    public function update_log( Result $fw_result )
    {
        // Increasing counter
        Counters\FirewallCounter::increment( stripos( $fw_result->status, 'pass') !== false ? 'pass' : 'deny' );
	    
		$log_item = array(
			
            'ip'              => $fw_result->ip,
			'time'            => time(),
            'status'          => $fw_result->status,
            'pattern'         => ! empty( $fw_result->pattern )
                ? json_encode( $fw_result->pattern )
                : '',
            'signature_id'    => $fw_result->signature_id,
            'triggered_for'    => ! empty( $fw_result->triggered_for )
                ? Helper::prepareParamForSQLQuery(substr($fw_result->triggered_for, 0, 100 ), '' )
                : '',
			'page_url'        => substr(
				addslashes(( Server::get('HTTPS') !== 'off' ? 'https://' : 'http://') . Server::get('HTTP_HOST').Server::get('REQUEST_URI')),
				0,
				4096
			),
			'http_user_agent' => Server::get('HTTP_USER_AGENT')
				? addslashes(htmlspecialchars(substr(Server::get('HTTP_USER_AGENT'), 0, 300)))
				: 'unknown',
			'request_method'  => Server::get( 'REQUEST_METHOD' ),
			'x_forwarded_for' => addslashes( htmlspecialchars( substr( Server::get( 'HTTP_X_FORWARDED_FOR' ), 0, 15 ) ) ),
            'network'         => $fw_result->network,
            'mask'            => $fw_result->mask,
            'is_personal'     => $fw_result->is_personal,
            'country_code'    => $fw_result->country_code,
		);
		
        $log_item['id'] = md5( $fw_result->ip . $log_item['http_user_agent'] . $fw_result->status . $fw_result->waf_action );
        
		$query = "INSERT INTO ". SPBC_TBL_FIREWALL_LOG ." SET
				entry_id        = '{$log_item['id']}',
				ip_entry        = '{$log_item['ip']}',
				entry_timestamp = {$log_item['time']},
				status          = '{$log_item['status']}',
				pattern         = IF('{$log_item['pattern']}' = '', NULL, '{$log_item['pattern']}'),
				signature_id    = IF({$log_item['signature_id']} = 0, NULL, {$log_item['signature_id']}),
				triggered_for   = IF('{$log_item['triggered_for']}' = '', NULL, '{$log_item['triggered_for']}'),
				requests        = 1,
				page_url        = '{$log_item['page_url']}',
				http_user_agent = '{$log_item['http_user_agent']}',
				request_method  = '{$log_item['request_method']}',
				x_forwarded_for = IF('{$log_item['x_forwarded_for']}' = '', NULL, '{$log_item['x_forwarded_for']}'),
				network         = IF('{$log_item['network']}' = '' OR '{$log_item['network']}' IS NULL, NULL, {$log_item['network']}),
				mask            = IF('{$log_item['mask']}' = '' OR '{$log_item['mask']}' IS NULL, NULL, {$log_item['mask']}),
				country_code    = IF('{$log_item['country_code']}' = '',    NULL, '{$log_item['country_code']}'),
				is_personal     = {$log_item['is_personal']}
			ON DUPLICATE KEY UPDATE
				ip_entry        = ip_entry,
				entry_timestamp = {$log_item['time']},
				status          = '{$log_item['status']}',
				pattern         = IF('{$log_item['pattern']}' = '', NULL, '{$log_item['pattern']}'),
				signature_id    = IF({$log_item['signature_id']} = 0, NULL, {$log_item['signature_id']}),
				triggered_for   = IF('{$log_item['triggered_for']}' = '', NULL, '{$log_item['triggered_for']}'),
				requests        = requests + 1,
				page_url        = '{$log_item['page_url']}',
				http_user_agent = http_user_agent,
				request_method  = '{$log_item['request_method']}',
				x_forwarded_for = IF('{$log_item['x_forwarded_for']}' = '', NULL, '{$log_item['x_forwarded_for']}'),
				network         = IF('{$log_item['network']}' = '' OR '{$log_item['network']}' IS NULL, NULL, {$log_item['network']}),
				mask            = IF('{$log_item['mask']}' = '' OR '{$log_item['mask']}' IS NULL, NULL, {$log_item['mask']}),
				country_code    = IF('{$log_item['country_code']}' = '',    NULL, '{$log_item['country_code']}'),
				is_personal     = {$log_item['is_personal']}";
		
		$this->db->execute( $query );
	}
    
    /**
     * Check if we should pass the firewall check for all modules base on request and surrounding.
     *
     * @return bool
     */
	public static function isException(){
        return Server::in_uri('elementor/v1/globals') &&
               (spbc_is_plugin_active('elementor/elementor.php') || spbc_is_plugin_active('elementor-pro/elementor-pro.php'));
    }
}
