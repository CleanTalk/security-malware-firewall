<?php

namespace CleantalkSP\SpbctWP\Firewall;

use CleantalkSP\SpbctWP\Helper;
use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Server;
use CleantalkSP\SpbctWP\Scanner;

class WAF extends \CleantalkSP\SpbctWP\Firewall\FirewallModule {
	
	public $module_name = 'WAF';
	
	protected $waf__xss_check     = false;
	protected $waf__sql_check     = false;
	protected $waf__file_check    = false;
	protected $waf__exploit_check = false;
	
	private $waf_pattern       = array(); // Why WAF is triggered (reason)
	
	private $waf_sql_patterns = array();
	private $waf_exploit_patterns = array();
	private $waf_xss_patterns = array();
	
	protected $api_key = false;
	
	public $waf_file_mime_check = array(
		'text/x-php',
		'text/plain',
		'image/x-icon',
	);
	
	/**
	 * FireWall_module constructor.
	 * Use this method to prepare any data for the module working.
	 *
	 * @param array $params
	 */
	public function __construct( $params = array() ){
		
		parent::__construct( $params );
		
	}
	
	/**
	 * Use this method to execute main logic of the module.
	 * @return mixed
	 */
	public function check() {
		
		$results = array();
		
		// Get signatures from DB
		$signatures = $this->db->fetch_all('SELECT * FROM '. SPBC_TBL_SCAN_SIGNATURES . ' WHERE type = "WAF_RULE";', ARRAY_A);
		
		if ( $signatures ) {
			
			foreach ( $signatures as $signature ) {
				
				switch ( $signature['attack_type'] ) {
					
					case 'SQL_INJECTION':
						$this->waf_sql_patterns[] = $signature['body'];
						break;
					case 'XSS':
						$this->waf_xss_patterns[] = $signature['body'];
						break;
					case 'EXPLOIT':
						$this->waf_exploit_patterns[] = $signature['body'];
						break;
				}
			}
		}
		
		// XSS
		if( $this->waf__xss_check ){
			if($this->waf__xss_check($_POST) || $this->waf__xss_check($_GET) || $this->waf__xss_check($_COOKIE)){
				$results[] = array('ip' => end($this->ip_array), 'is_personal' => false, 'status' => 'DENY_BY_WAF_XSS', 'pattern' => $this->waf_pattern);
			}
		}
		
		// SQL-injection
		if( $this->waf__sql_check ){
			if($this->waf__sql_check($_POST) || $this->waf__sql_check($_GET)){
				$results[] = array('ip' => end($this->ip_array), 'is_personal' => false, 'status' => 'DENY_BY_WAF_SQL', 'pattern' => $this->waf_pattern);
			}
		}
		
		// File
		if ($this->waf__file_check ){
			if($this->waf__file_check()){
				$results[] = array('ip' => end($this->ip_array), 'is_personal' => false, 'status' => 'DENY_BY_WAF_FILE', 'pattern' => $this->waf_pattern);
			}
		}
		
		// Exploits
		if( $this->waf__exploit_check ){
			if($this->waf__exploit_check()){
				$results[] = array('ip' => end($this->ip_array), 'is_personal' => false, 'status' => 'DENY_BY_WAF_EXPLOIT', 'pattern' => $this->waf_pattern);
			}
		}
		
		foreach( $results as &$result ){
			$result = array_merge(
				array(
					'ip'          => end( $this->ip_array ),
					'is_personal' => false,
					'module'      => 'WAF',
					'status'      => 'PASS',
				),
				$result
			);
		}
		
		return $results;
		
	}
	
	/**
	 * Checks array for XSS-attack patterns
	 *
	 * @param $arr
	 *
	 * @return bool
	 */
	private function waf__xss_check( $arr ) {
		
		foreach( $arr as $name => $param ){
			
			// Recursion
			if( is_array( $param ) ){
				$result = $this->waf__xss_check( $param );
				if( $result === true )
					return true;
				continue;
			}
			
			//Check
			foreach( $this->waf_xss_patterns as $pattern ){
				/** @todo add regexp check  */
				if( stripos( $param, $pattern ) !== false ){
					$this->waf_pattern = array( 'critical' => $pattern );
					return true;
				}
			}
		}
		
		return false;
		
	}
	
	/**
	 * Checks array for SQL injections
	 *
	 * @param $arr
	 *
	 * @return bool
	 */
	private function waf__sql_check( $arr ) {
		
		foreach( $arr as $name => $param ){
			
			if( is_array( $param ) ){
				$result = $this->waf__sql_check( $param );
				if( $result === true )
					return true;
				continue;
			}
			
			foreach( $this->waf_sql_patterns as $pattern ){
				if( @ preg_match('/'.$pattern.'/i', $param) === 1 ){
					$this->waf_pattern = array( 'critical' =>  $pattern );
					return true;
				}
			}
		}
		
		return false;
		
	}
	
	/**
	 * Checks $_SERVER['QUERY_STRING'] for exploits
	 *
	 * @return bool
	 */
	private function waf__exploit_check() {
		
		foreach( $this->waf_exploit_patterns as $pattern ){
			if( @ preg_match('@'.$pattern.'@i', Server::get('QUERY_STRING')) === 1 ){
				$this->waf_pattern = array( 'critical' =>  $pattern );
				return true;
			}
		}
		
		return false;
		
	}
	
	/**
	 * Checks uploaded files for malicious code
	 *
	 * @return boolean Does the file contain malicious code
	 */
	private function waf__file_check() {
		
		if( ! empty( $_FILES ) ){
			foreach( $_FILES as $filez ){
				if ( ( empty($filez['errror'] ) || $filez['errror'] == UPLOAD_ERR_OK ) ) {
					$filez['tmp_name'] = is_array( $filez['tmp_name'] ) ? $filez['tmp_name'] : array( $filez['tmp_name'] );
					foreach( $filez['tmp_name'] as $file ){
						if(
							is_string( $file ) &&
							is_uploaded_file( $file ) &&
							is_readable( $file ) &&
							in_array( Helper::get_mime_type( $file ), $this->waf_file_mime_check )
						) {
							$fileh = new Scanner\Heuristic\Controller(array('content' => file_get_contents($file ) ) );
							if( empty( $fileh->error ) ){
								$fileh->processContent();
								if( ! empty( $fileh->verdict ) ){
									foreach( $fileh->verdict as $severity => $result ){
										$this->waf_pattern[$severity] = reset($result);
									}
									return true;
								}
							}
						}
					}
				}
			}
		}
		
		return false;
		
	}
	
	/**
	 * AJAX callback for details about latest blocked file
	 */
	public static function waf_file__get_last_blocked_info() {
		
		check_ajax_referer('spbc_secret_nonce', 'security');
		
		global $wpdb;
		
		$timestamp = intval(Post::get('timestamp'));
		
		// Select only latest ones.
		$result = $wpdb->get_results(
			'SELECT *'
			.' FROM '. SPBC_TBL_FIREWALL_LOG
			.' WHERE status = "DENY_BY_WAF_FILE" AND entry_timestamp > '.($timestamp - 2)
			.' ORDER BY entry_timestamp DESC LIMIT 1;'
			, OBJECT
		);
		
		if($result){
			$result = $result[0];
			$out = array(
				'blocked' => true,
				'warning' => __('Security by CleanTalk: File was blocked by Web Application FireWall.', 'security-malware-firewall'),
				'pattern_title' => __('Detected pattern: ', 'security-malware-firewall'),
				'pattern' => json_decode($result->pattern, true),
			);
		}else
			$out = array('blocked' => false);
		
		die(json_encode($out));
	}
}