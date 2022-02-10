<?php

namespace CleantalkSP\SpbctWP\Firewall;

use CleantalkSP\SpbctWP\Helper;
use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Server;
use CleantalkSP\SpbctWP\Scanner;

class WAF extends \CleantalkSP\SpbctWP\Firewall\FirewallModule {
	
	public $module_name = 'WAF';
	
	protected $waf__suspicious_check             = true;
	protected $waf__xss_check                    = false;
	protected $waf__sql_check                    = false;
	protected $waf__file_check                   = false;
	protected $waf__file_check__uploaded_plugins = false;
	protected $waf__exploit_check                = false;
	
	private $waf_pattern       = array(); // Why WAF is triggered (reason)
	
	private $waf_sql_patterns = array();
	private $waf_exploit_patterns = array();
	private $waf_xss_patterns = array();
	private $waf_suspicious_patterns = array();
	
	protected $api_key = false;
	
	public $waf_file_mime_check = array(
		'text/x-php',
		'text/plain',
		'image/x-icon',
        'application/zip',
        'application/x-zip-compressed',
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
					case 'SUSPICIOUS':
						$this->waf_suspicious_patterns[] = $signature['body'];
						break;
				}
			}
		}
		
        $results[] = $this->waf__suspicious_check ? $this->waf__suspicious_check( array( $_POST, $_GET, $_COOKIE ) ) : false;
        $results[] = $this->waf__xss_check        ? $this->waf__xss_check(array( $_POST, $_GET, $_COOKIE ))          : false;
        $results[] = $this->waf__sql_check        ? $this->waf__sql_check( array( $_POST, $_GET ) )                  : false;
        $results[] = $this->waf__file_check       ? $this->waf__file_check()                                         : false;
        $results[] = $this->waf__exploit_check    ? $this->waf__exploit_check( Server::get('QUERY_STRING') )         : false;
        
        // Adding common parameters to results
		foreach( $results as $key => &$result ){
		
		    // Cleaning from "false" values
		    if( $result === false ){
		        unset($results[ $key ]);
		        continue;
            }
            
            $result['ip']          = end( $this->ip_array );
            $result['is_personal'] = false;
            $result['module']      = 'WAF';
		} unset( $result );
		
		return $results;
		
	}
	
    /**
     * Checks an array for suspicious signatures entry
     *
     * @param array $arr
     *
     * @return false|array
     */
    private function waf__suspicious_check( $arr )
    {
        foreach( $arr as $name => $param ){
        
            // Recursion
            if( is_array( $param ) ){
                $result = $this->waf__suspicious_check( $param );
                if( $result !== false ){
                    return $result;
                }
                continue;
            }
        
            //Check
            foreach( $this->waf_suspicious_patterns as $pattern ){
                if( @ preg_match('@'.$pattern.'@i', $param) === 1 ){
                    return array('status' => 'PASS', 'triggered_for' => $param, 'pattern' => array( 'suspicious' => $pattern ) );
                }
            }
        }
    
        return false;
    }
	   
	/**
	 * Checks array for XSS-attack patterns
	 *
	 * @param $arr
	 *
	 * @return false|array
	 */
	private function waf__xss_check( $arr ) {
		
		foreach( $arr as $name => $param ){
			
			// Recursion
			if( is_array( $param ) ){
				$result = $this->waf__xss_check( $param );
				if( $result !== false ){
                    return $result;
                }
				continue;
			}
			
			//Check
			foreach( $this->waf_xss_patterns as $pattern ){
				/** @todo add regexp check  */
				if( stripos( $param, $pattern ) !== false ){
					return array('status' => 'DENY_BY_WAF_XSS', 'pattern' => array( 'critical' => $pattern ) );
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
	 * @return false|array
	 */
	private function waf__sql_check( $arr ) {
		
		foreach( $arr as $name => $param ){
			
			if( is_array( $param ) ){
				$result = $this->waf__sql_check( $param );
				if( $result !== false ){
                    return $result;
                }
				continue;
			}
			
			foreach( $this->waf_sql_patterns as $pattern ){
				if( @ preg_match('/'.$pattern.'/i', $param) === 1 ){
					$this->waf_pattern = array( 'critical' =>  $pattern );
					return array('status' => 'DENY_BY_WAF_SQL', 'pattern' => array( 'critical' =>  $pattern ) );
				}
			}
		}
		
		return false;
		
	}
	
	/**
	 * Checks given string for exploits
	 *
	 * @param string $string
	 *
	 * @return false|array
	 */
	private function waf__exploit_check( $string ) {
		
		foreach( $this->waf_exploit_patterns as $pattern ){
			if( @ preg_match('@'.$pattern.'@i', $string) === 1 ){
				return array('status' => 'DENY_BY_WAF_EXPLOIT', 'pattern' => array( 'critical' =>  $pattern ));
			}
		}
		
		return false;
		
	}
	
	/**
	 * Checks uploaded files for malicious code
	 *
	 * @return false|array Does the file contain malicious code
	 */
	private function waf__file_check() {
		
		if( ! empty( $_FILES ) ){
			foreach( $_FILES as $files ){
				if ( ( empty($files['error'] ) || $files['error'] === UPLOAD_ERR_OK ) ) {
					$files['tmp_name'] = is_array( $files['tmp_name'] ) ? $files['tmp_name'] : array( $files['tmp_name'] );
					foreach( $files['tmp_name'] as $file ){
						if(
							is_string( $file ) &&
							is_uploaded_file( $file ) &&
							is_readable( $file ) &&
							in_array( Helper::get_mime_type( $file ), $this->waf_file_mime_check )
						) {
						    
						    // Uploaded plugins and themes check
                            if( $this->waf__file_check__uploaded_plugins ){
                                add_filter('upgrader_source_selection', '\CleantalkSP\SpbctWP\Firewall\WAF::waf__file_check__modules_check', 2, 4);
                            }
                            
                            if( in_array(Helper::get_mime_type( $file ), array('text/x-php', 'text/plain', 'image/x-icon') ) ){
                                $heuristic_result = new Scanner\Heuristic\Controller(array('content' => file_get_contents($file)));
                            }
                            
                            if( isset( $heuristic_result ) && empty( $heuristic_result->error ) ){
                                $heuristic_result->processContent();
                                if( ! empty( $heuristic_result->verdict ) ){
                                    $patterns = array();
                                    foreach( $heuristic_result->verdict as $severity => $result ){
                                        $patterns[$severity] = reset($result);
                                    }
									return array( 'status' => 'DENY_BY_WAF_FILE', 'pattern' => $patterns );
								}
							}
						}
					}
				}
			}
		}
		
		return false;
		
	}
    
    public static function waf__file_check__modules_check($source, $remote_source, \WP_Upgrader $upgrader, $args_hook_extra)
    {
        // Show initial check message
        show_message(sprintf('Security by CleanTalk is checking the uploaded %s&#8230;', $args_hook_extra['type']));
        
        // Prepare and run scan
        $dir_scan = new \CleantalkSP\SpbctWP\Scanner\DirectoryScan(
            $source,
            Scanner\Controller::getRootPath(),
            array(
                'output_file_details' => array('path', 'full_hash'),
            )
        );
        $dir_scan->setElements();
        $results = $dir_scan->scan(true);
        
        // Output the result
        show_message('&nbsp;&nbsp;' . __('Checked files:', 'security-malware-firewall'));
        $overall_result = true;
        foreach( $results as $path => $result ){
        
            if( ! empty( $result['error'] ) ){
                show_message('&nbsp;&nbsp;<b>Error occurred while checking file</b> ' . $path . ': ' . $result['error'] );
                continue;
            }
            
            $overall_result &= $result['status'] === 'OK';
            
            // Cutting useless path prefix
            $display_path = preg_replace('#^.wp-content.upgrade[\\\\].+?[\\\\]#', '', $path);
            show_message("&nbsp;&nbsp;&nbsp;&nbsp;$display_path: <b>{$result['status']}</b>");
        }
        
        // Output result message
        if( $overall_result ){
            show_message('&nbsp;&nbsp;<b>No malware has been found. Installation continues.</b>');
        }else{
            // Remove the directory with bad plugin
            \CleantalkSP\Common\Helper::fs__removeDirectoryRecursively($source);
            
            return new \WP_Error(
                'spbct.plugin_check.malware_found',
                '<b>Malware has been found. Installation interrupted.</b>'
            );
        }
        
        return $source;
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