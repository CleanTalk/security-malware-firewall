<?php

namespace CleantalkSP\Common;

use CleantalkSP\Common\HTTP\Request;

/**
 * CleanTalk API class.
 * Mostly contains wrappers for API methods. Check and send methods.
 * Compatible with any CMS.
 *
 * @version       3.2.1
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/php-antispam
 */
class API
{
	/* Default params  */
	const URL = 'https://api.cleantalk.org';
	const DEFAULT_AGENT = 'cleantalk-api-321';
 
	private static function getProductID( $product_name ) {
		$product_id = null;
		$product_id = $product_name === 'antispam' ? 1 : $product_id;
		$product_id = $product_name === 'security' ? 4 : $product_id;
		return $product_id;
	}
	
    public static function sendRequest($data, $presets = array() )
    {
        $http = new Request();
        
        return $http->setUrl(static::URL)
                    ->setData($data)
                    ->setPresets(array_merge($presets, ['retry_with_socket']))
                    ->addCallback(
                        __CLASS__ . '::processResponse',
                        [$data['method_name']]
                    )
                    ->request();
    }
    
    /**
     * Function checks API response
     *
     * @param string $request_result
     * @param string $url
     * @param string $method_name
     *
     * @return mixed (array || array('error' => true))
     */
	public static function processResponse($request_result, $url, $method_name)
	{
		// Errors handling
		// Bad connection
		if( is_array($request_result) && isset($request_result['error'])){
			return array(
				'error' => 'CONNECTION_ERROR' . (isset($request_result['error']) ? ': "' . $request_result['error'] . '"' : ''),
			);
		}
		
		// JSON decode errors
		$request_result = json_decode($request_result, true);
		if(empty($request_result)){
			return array(
				'error' => 'JSON_DECODE_ERROR',
			);
		}
		
		// Server errors
		if( $request_result && ( isset( $request_result['error_no'], $request_result['error_message'] ) ) ){
			
			if( $request_result['error_no'] !== 12 ){
				return array(
					'error' => "SERVER_ERROR NO: {$request_result['error_no']} MSG: {$request_result['error_message']}",
					'error_no' => $request_result['error_no'],
					'error_message' => $request_result['error_message'],
				);
			}
		}
		
		// Patches for different methods
		switch($method_name){
			
			// notice_paid_till
			case 'notice_paid_till':
                
                $request_result = isset($request_result['data']) ? $request_result['data'] : $request_result;
                
                if( (isset($request_result['error_no']) && $request_result['error_no'] == 12) ||
                    (
                        ! (isset($request_result['service_id']) && is_int($request_result['service_id'])) &&
                        empty($request_result['moderate_ip'])
                    )
                ){
                    $request_result['valid'] = 0;
                }else{
                    $request_result['valid'] = 1;
                }
                
                return $request_result;
			
			// get_antispam_report_breif
			case 'get_antispam_report_breif':
				
				$out = isset($request_result['data']) && is_array($request_result['data'])
					? $request_result['data']
					: array('error' => 'NO_DATA');
				
				for($tmp = array(), $i = 0; $i < 7; $i++){
					$tmp[date('Y-m-d', time() - 86400 * 7 + 86400 * $i)] = 0;
				}
				$out['spam_stat'] = (array)array_merge($tmp, isset($out['spam_stat']) ? $out['spam_stat'] : array());
				$out['top5_spam_ip'] = isset($out['top5_spam_ip']) ? $out['top5_spam_ip'] : array();
				
				return $out;

			case 'services_templates_add' :
			case 'services_templates_update' :
				return isset( $request_result['data'] ) && is_array($request_result['data'] ) && count($request_result['data'] ) === 1
					? $request_result['data'][0]
					: array('error' => 'NO_DATA');
				
            case 'security_mscan_status':
                $data = array();
                foreach( $request_result['data'] as $key => &$datum ){
                    
                    // Do not process bad response without correct status
                    if( ! isset( $datum['file_status'] ) || ! in_array($datum['file_status'], array('SAFE','NEW','DANGEROUS'), true) ){
                        return array('error' => 'DATA_IS_BAD__STATUS');
                    }
                    
                    $datum['comment'] = is_null($datum['comment']) ? '' : $datum['comment'];
                    // Do not process bad comments
                    if( ! isset( $datum['comment'] ) || ! Validate::isText($datum['comment']) ){
                        return array('error' => 'DATA_IS_BAD__COMMENT');
                    }
                    
                    // Return only the latest submitted files
                    if( isset( $data[ $datum['file_path'] ] ) && $datum['submited'] > $data[ $datum['file_path'] ]['submited']){
                        $data[ $datum['file_path'] ] = $datum;
                    }
                    if( ! isset( $data[ $datum['file_path'] ] ) ){
                        $data[ $datum['file_path'] ] = $datum;
                    }
                }
                
                return array_values($data);
            
            case 'service_get':
                return [
                    'server_response' => isset($request_result['data'][0]['server_response'])
                        ? strip_tags($request_result['data'][0]['server_response'], '<p><a><br>')
                        : '',
                    'server_response_combine' => ! empty($request_result['data'][0]['server_response'])
                        ? $request_result['data'][0]['server_response']
                        : true,
                ];
                
			default:
				return isset($request_result['data']) && is_array($request_result['data'])
					? $request_result['data']
					: array('error' => 'NO_DATA');
		}
	}
	
    /**
     * Wrapper for 2s_blacklists_db API method.
     * Gets data for SpamFireWall.
     *
     * @param string      $api_key
     * @param null|string $out Data output type (JSON or file URL)
     *
     * @return mixed|string|array('error' => STRING)
     */
    public static function method__get_2s_blacklists_db($api_key, $out = null)
    {
        $request = array(
            'method_name' => '2s_blacklists_db',
            'auth_key'    => $api_key,
            'out'         => $out,
        );
        
        return static::sendRequest($request);
    }
	
	/**
	 * Wrapper for get_api_key API method.
	 * Gets access key automatically.
	 *
	 * @param string      $product_name Type of product
	 * @param string      $email        Website admin email
	 * @param string      $website      Website host
	 * @param string      $platform     Website platform
	 * @param string|null $timezone
	 * @param string|null $language
	 * @param string|null $user_ip
	 * @param bool        $wpms
	 * @param bool        $white_label
	 * @param string      $hoster_api_key
	 *
	 * @return array|bool|mixed
	 */
    public static function method__get_api_key(
        $product_name,
        $email,
        $website,
        $platform,
        $timezone = null,
        $language = null,
        $user_ip = null,
        $wpms = false,
        $white_label = false,
        $hoster_api_key = ''
    ){
        $request = array(
            'method_name'          => 'get_api_key',
            'product_name'         => $product_name,
            'email'                => $email,
            'website'              => $website,
            'platform'             => $platform,
            'timezone'             => $timezone,
            'http_accept_language' => $language,
            'user_ip'              => $user_ip,
            'wpms_setup'           => $wpms,
            'hoster_whitelabel'    => $white_label,
            'hoster_api_key'       => $hoster_api_key,
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for get_antispam_report API method.
     * Gets spam report.
     *
     * @param string  $host   website host
     * @param integer $period report days
     *
     * @return array|bool|mixed
     */
    public static function method__get_antispam_report($host, $period = 1)
    {
        $request = array(
            'method_name' => 'get_antispam_report',
            'hostname'    => $host,
            'period'      => $period,
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for get_antispam_report_breif API method.
     * Gets spam statistics.
     *
     * @param string $api_key
     *
     * @return array|bool|mixed
     */
    public static function method__get_antispam_report_breif($api_key)
    {
        $request = array(
            'method_name' => 'get_antispam_report_breif',
            'auth_key'    => $api_key,
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for notice_paid_till API method.
     * Gets information about renew notice.
     *
     * @param string $api_key     API key
     * @param string $path_to_cms Website URL
     * @param string $product_name
     *
     * @return array|bool|mixed
     */
    public static function method__notice_paid_till($api_key, $path_to_cms, $product_name = 'antispam')
    {
        $request = array(
            'method_name' => 'notice_paid_till',
            'path_to_cms' => $path_to_cms,
            'auth_key'    => $api_key,
        );
        
        if( self::getProductID($product_name) ){
            $request['product_id'] = self::getProductID($product_name);
        }
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for ip_info API method.
     * Gets IP country.
     *
     * @param string $data
     *
     * @return array|bool|mixed
     */
    public static function method__ip_info($data)
    {
        $request = array(
            'method_name' => 'ip_info',
            'data'        => $data,
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for spam_check_cms API method.
     * Checks IP|email via CleanTalk's database.
     *
     * @param string      $api_key
     * @param array       $data
     * @param null|string $date
     *
     * @return array|bool|mixed
     */
    public static function method__spam_check_cms($api_key, $data, $date = null)
    {
        $request = array(
            'method_name' => 'spam_check_cms',
            'auth_key'    => $api_key,
            'data'        => is_array($data) ? implode(',', $data) : $data,
        );
        
        if( $date ){
            $request['date'] = $date;
        }
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for spam_check API method.
     * Checks IP|email via CleanTalk's database.
     *
     * @param string      $api_key
     * @param array       $data
     * @param null|string $date
     *
     * @return array|bool|mixed
     */
    public static function method__spam_check($api_key, $data, $date = null)
    {
        $request = array(
            'method_name' => 'spam_check',
            'auth_key'    => $api_key,
            'data'        => is_array($data) ? implode(',', $data) : $data,
        );
        
        if( $date ){
            $request['date'] = $date;
        }
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for sfw_logs API method.
     * Sends SpamFireWall logs to the cloud.
     *
     * @param string $api_key
     * @param array  $data
     *
     * @return array|bool|mixed
     */
    public static function method__sfw_logs($api_key, $data)
    {
        $request = array(
            'auth_key'    => $api_key,
            'method_name' => 'sfw_logs',
            'data'        => json_encode($data),
            'rows'        => count($data),
            'timestamp'   => time(),
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for security_logs API method.
     * Sends security logs to the cloud.
     *
     * @param string $api_key
     * @param array  $data
     *
     * @return array|bool|mixed
     */
    public static function method__security_logs($api_key, $data)
    {
        $request = array(
            'auth_key'    => $api_key,
            'method_name' => 'security_logs',
            'timestamp'   => current_time('timestamp'),
            'data'        => json_encode($data),
            'rows'        => count($data),
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for security_logs API method.
     * Sends Securitty Firewall logs to the cloud.
     *
     * @param string $api_key
     * @param array  $data
     *
     * @return array|bool|mixed
     */
    public static function method__security_logs__sendFWData($api_key, $data)
    {
        $request = array(
            'auth_key'    => $api_key,
            'method_name' => 'security_logs',
            'timestamp'   => current_time('timestamp'),
            'data_fw'     => json_encode($data),
            'rows_fw'     => count($data),
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for security_logs API method.
     * Sends empty data to the cloud to syncronize version.
     *
     * @param string $api_key
     *
     * @return array|bool|mixed
     */
    public static function method__security_logs__feedback($api_key)
    {
        $request = array(
            'auth_key'    => $api_key,
            'method_name' => 'security_logs',
            'data'        => '0',
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for security_firewall_data API method.
     * Gets Securitty Firewall data to write to the local database.
     *
     * @param string $api_key
     *
     * @return array|bool|mixed
     */
    public static function method__security_firewall_data($api_key)
    {
        $request = array(
            'auth_key'    => $api_key,
            'method_name' => 'security_firewall_data',
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for security_firewall_data_file API method.
     * Gets URI with security firewall data in .csv.gz file to write to the local database.
     *
     * @param string $api_key
     *
     * @return array|bool|mixed
     */
    public static function method__security_firewall_data_file($api_key, $out = null)
    {
        $request = array(
            'auth_key'    => $api_key,
            'method_name' => 'security_firewall_data_file',
        );
        
        if( $out ){
            $request['out'] = $out;
        }
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for security_linksscan_logs API method.
     * Send data to the cloud about scanned links.
     *
     * @param string $api_key
     * @param string $scan_time  Datetime of scan
     * @param bool   $scan_result
     * @param int    $links_total
     * @param string $links_list JSON string
     *
     * @return array|bool|mixed
     */
    public static function method__security_linksscan_logs($api_key, $scan_time, $scan_result, $links_total, $links_list)
    {
        $request = array(
            'auth_key'          => $api_key,
            'method_name'       => 'security_linksscan_logs',
            'started'           => $scan_time,
            'result'            => $scan_result,
            'total_links_found' => $links_total,
            'links_list'        => $links_list,
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for security_mscan_logs API method.
     * Sends result of file scan to the cloud.
     *
     * @param string $api_key
     * @param bool   $list_unknown
     * @param int    $service_id
     * @param string $scan_time Datetime of scan
     * @param bool   $scan_result
     * @param int    $scanned_total
     * @param array  $modified  List of modified files with details
     * @param array  $unknown   List of modified files with details
     *
     * @return array|bool|mixed
     */
    public static function method__security_mscan_logs(
        $api_key,
        $list_unknown,
        $service_id,
        $scan_time,
        $scan_result,
        $scanned_total,
        $modified,
        $unknown
    ){
        $request = array(
            'method_name'      => 'security_mscan_logs',
            'auth_key'         => $api_key,
            'list_unknown'     => (int)$list_unknown,
            'service_id'       => $service_id,
            'started'          => $scan_time,
            'result'           => $scan_result,
            'total_core_files' => $scanned_total,
        );
        
        if( ! empty($modified) ){
            $request['failed_files']      = json_encode($modified);
            $request['failed_files_rows'] = count($modified);
        }
        if( ! empty($unknown) ){
            $request['unknown_files']      = json_encode($unknown);
            $request['unknown_files_rows'] = count($unknown);
        }
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for security_mscan_files API method.
     * Sends file to the cloud for analysis.
     *
     * @param string $api_key
     * @param string $file_path  Path to the file
     * @param string $file       File itself
     * @param string $file_md5   MD5 hash of file
     * @param array  $weak_spots List of weak spots found in file
     * @param        $version
     * @param        $source
     * @param        $source_type
     * @param        $source_status
     * @param        $full_hash
     *
     * @return array|bool|mixed
     */
    public static function method__security_mscan_files(
        $api_key,
        $file_path,
        $file,
        $file_md5,
        $weak_spots,
        $version,
        $source,
        $source_type,
        $source_status,
        $full_hash
    ){
        $request = array(
            'method_name'    => 'security_mscan_files',
            'auth_key'       => $api_key,
            'path_to_sfile'  => $file_path,
            'attached_sfile' => $file,
            'md5sum_sfile'   => $file_md5,
            'dangerous_code' => $weak_spots,
            'version'        => $version,
            'source'         => $source,
            'source_type'    => $source_type,
            'source_status'  => $source_status,
            'real_hash'      => $full_hash,
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for get_antispam_report API method.
     * Function gets spam domains report.
     *
     * @param string             $api_key
     * @param array|string|mixed $data
     * @param string             $date
     *
     * @return array|bool|mixed
     */
    public static function method__backlinks_check_cms($api_key, $data, $date = null)
    {
        $request = array(
            'method_name' => 'backlinks_check_cms',
            'auth_key'    => $api_key,
            'data'        => is_array($data) ? implode(',', $data) : $data,
        );
        
        if( $date ){
            $request['date'] = $date;
        }
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for get_antispam_report API method.
     * Function gets spam domains report
     *
     * @param string $api_key
     * @param array  $logs
     *
     * @return array|bool|mixed
     */
    public static function method__security_backend_logs($api_key, $logs)
    {
        $request = array(
            'method_name' => 'security_backend_logs',
            'auth_key'    => $api_key,
            'logs'        => json_encode($logs),
            'total_logs'  => count($logs),
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for get_antispam_report API method.
     * Sends data about auto repairs
     *
     * @param string $api_key
     * @param bool   $repair_result
     * @param string $repair_comment
     * @param        $repaired_processed_files
     * @param        $repaired_total_files_processed
     * @param        $backup_id
     *
     * @return array|bool|mixed
     */
    public static function method__security_mscan_repairs(
        $api_key,
        $repair_result,
        $repair_comment,
        $repaired_processed_files,
        $repaired_total_files_processed,
        $backup_id
    ){
        $request = array(
            'method_name'                  => 'security_mscan_repairs',
            'auth_key'                     => $api_key,
            'repair_result'                => $repair_result,
            'repair_comment'               => $repair_comment,
            'repair_processed_files'       => json_encode($repaired_processed_files),
            'repair_total_files_processed' => $repaired_total_files_processed,
            'backup_id'                    => $backup_id,
            'mscan_log_id'                 => 1,
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Wrapper for get_antispam_report API method.
     * Force server to update checksums for specific plugin\theme
     *
     * @param string $api_key
     * @param string $plugins_and_themes_to_refresh
     *
     * @return array|bool|mixed
     */
    public static function method__request_checksums($api_key, $plugins_and_themes_to_refresh)
    {
        $request = array(
            'method_name' => 'request_checksums',
            'auth_key'    => $api_key,
            'data'        => $plugins_and_themes_to_refresh,
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Settings templates get API method wrapper
     *
     * @param string $api_key
     * @param string $product_name
     *
     * @return array|bool|mixed
     */
    public static function method__services_templates_get($api_key, $product_name = 'antispam')
    {
        $request = array(
            'method_name'        => 'services_templates_get',
            'auth_key'           => $api_key,
            'search[product_id]' => self::getProductID($product_name),
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Settings templates add API method wrapper
     *
     * @param string $api_key
     * @param null   $template_name
     * @param string $options
     * @param string $product_name
     *
     * @return array|bool|mixed
     */
    public static function method__services_templates_add($api_key, $template_name = null, $options = '', $product_name = 'antispam')
    {
        $request = array(
            'method_name'        => 'services_templates_add',
            'auth_key'           => $api_key,
            'name'               => $template_name,
            'options_site'       => $options,
            'search[product_id]' => self::getProductID($product_name),
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Settings templates add API method wrapper
     *
     * @param string $api_key
     * @param int    $template_id
     * @param string $options
     * @param string $product_name
     *
     * @return array|bool|mixed
     */
    public static function method__services_templates_update($api_key, $template_id, $options = '', $product_name = 'antispam')
    {
        $request = array(
            'method_name'        => 'services_templates_update',
            'auth_key'           => $api_key,
            'template_id'        => $template_id,
            'name'               => null,
            'options_site'       => $options,
            'search[product_id]' => self::getProductID($product_name),
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Adding admin IP to the Security FW WL
     *
     * @param $user_token
     * @param $ip
     * @param $service_id
     *
     * @return array|bool|mixed
     */
    public static function method__private_list_add__secfw_wl($user_token, $ip, $service_id)
    {
        $request = array(
            'method_name'  => 'private_list_add',
            'user_token'   => $user_token,
            'service_id'   => $service_id,
            'records'      => $ip,
            'service_type' => 'securityfirewall',
            'product_id'   => 4,
            'record_type'  => 1,
            'note'         => 'Website admin IP. Added automatically.',
            'status'       => 'allow',
            'expired'      => date('Y-m-d H:i:s', time() + 86400 * 30),
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Adding admin IP to the Security FW WL
     *
     * @param string          $api_key
     * @param string|string[] $file_paths // Array of file
     * @param string|string[] $file_ids
     *
     * @return array|bool|mixed
     */
    public static function method__security_mscan_status($api_key, $file_paths, $file_ids = array())
    {
        // Cast input to array because of method specification
        $file_paths = (array)$file_paths;
        $file_ids   = (array)$file_ids;
        
        $request = array(
            'method_name' => 'security_mscan_status',
            'auth_key'    => $api_key,
            'files'       => json_encode($file_paths),
            'file_ids'    => json_encode($file_ids),
        );
        
        return static::sendRequest($request);
    }
    
    /**
     * Receiving some data about service
     *
     * @param string $api_key
     * @param string $user_token
     *
     * @return array|bool|mixed
     */
    public static function method__service_get($api_key, $user_token)
    {
        $request = array(
            'method_name' => 'service_get',
            'auth_key'    => $api_key,
            'user_token'  => $user_token,
        );
        
        return static::sendRequest($request);
    }
	
    /**
     * Sending of local settings API method wrapper
     *
     * @param string $api_key
     * @param string $hostname
     * @param string $settings
     *
     * @return array|bool|mixed
     *
     * @psalm-suppress PossiblyUnusedMethod
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function methodSendLocalSettings(
        $api_key,
        $hostname,
        $settings
    ) {
        $request = array(
            'method_name' => 'service_update_local_settings',
            'auth_key' => $api_key,
            'hostname' => $hostname,
            'settings' => $settings
        );
        
        return static::sendRequest($request, ['async']);
    }
}