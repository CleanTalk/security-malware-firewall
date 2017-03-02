<?php
class SecurityFireWall
{
	public $ip = 0;
	public $ip_str = '';
	public $ip_array = Array();
	public $ip_str_array = Array();
	public $blocked_ip = '';
	public $passed_ip = '';
	public $result = false;
	
	public function spbc_get_real_ip(){
		
		$result=Array();
		if ( function_exists( 'apache_request_headers' ) )
			$headers = apache_request_headers();
		else
			$headers = $_SERVER;

		if ( array_key_exists( 'X-Forwarded-For', $headers ) ){
			$the_ip = explode(",", trim($headers['X-Forwarded-For']));
			$the_ip = trim($the_ip[0]);
			$result[] = $the_ip;
			$this->ip_str_array[]=$the_ip;
			$this->ip_array[]=sprintf("%u", ip2long($the_ip));
		}
		
		if ( array_key_exists( 'HTTP_X_FORWARDED_FOR', $headers )){
			$the_ip = explode(",", trim($headers['HTTP_X_FORWARDED_FOR']));
			$the_ip = trim($the_ip[0]);
			$result[] = $the_ip;
			$this->ip_str_array[]=$the_ip;
			$this->ip_array[]=sprintf("%u", ip2long($the_ip));
		}
		
		$the_ip = filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
		$result[] = $the_ip;
		$this->ip_str_array[]=$the_ip;
		$this->ip_array[]=sprintf("%u", ip2long($the_ip));

		if(isset($_GET['security_test_ip'])){
			$the_ip = $_GET['security_test_ip'];
			$result[] = $the_ip;
			$this->ip_str_array[]=$the_ip;
			$this->ip_array[]=sprintf("%u", ip2long($the_ip));
		}
		
		return $result;
	}
	
	public function check_ip(){		
	
		global $wpdb;
		
		for($i=0;$i<sizeof($this->ip_array);$i++){
			$r = $wpdb->get_results("
				SELECT COUNT(spbc_network) AS cnt 
				FROM `".$wpdb->base_prefix."spbc_firewall_data` 
				WHERE spbc_network = ".$this->ip_array[$i].";", ARRAY_A);
						
			if($r[0]['cnt']){
				$this->result=true;
				$this->blocked_ip=$this->ip_str_array[$i];
			}else{
				$this->passed_ip = $this->ip_str_array[$i];
			}
		}
	}
	
	public function spbc_die(){
		
		global $ct_options, $ct_data;
		$spbc_die_page=file_get_contents(dirname(__FILE__)."/spbc_die_page.html");
		$spbc_die_page=str_replace("{REMOTE_ADDRESS}",$this->blocked_ip,$spbc_die_page);
		$spbc_die_page=str_replace("{REQUEST_URI}",$_SERVER['REQUEST_URI'],$spbc_die_page);
		$spbc_die_page=str_replace("{SFW_COOKIE}",md5($this->blocked_ip.$ct_options['apikey']),$spbc_die_page);
		@header('Cache-Control: no-cache');
		@header('Expires: 0');
		@header('HTTP/1.0 403 Forbidden');
		wp_die( $spbc_die_page, "Blacklisted", Array('response'=>403) );
	}
	
	static public function firewall_update($spbc_key){
			
		global $wpdb;
		
		if(!function_exists('spbc_sendRawRequest'))
			require_once(plugin_dir_path(__FILE__) . 'spbc-tools.php');
		
		$data = Array('auth_key' => $spbc_key, 'method_name' => 'security_firewall_data');	
		$result = spbc_sendRawRequest('https://api.cleantalk.org/2.1', $data, false, 20);
		
		$result=json_decode($result, true);
		
		if(isset($result['data']) && count($result['data'])){

			$result=$result['data'];
			
			$wpdb->query("TRUNCATE TABLE `".$wpdb->base_prefix."spbc_firewall_data`;");
			
			$row_to_write = 100000;
			$sql_write_iteration = ceil(count($result)/$row_to_write);
					
			$count_result = 0;
			for($j=0; $j < $sql_write_iteration; $j++){
				
				$to_mysql = array_slice($result, $j*$row_to_write, $row_to_write, false);
								
				$query="INSERT INTO `".$wpdb->base_prefix."spbc_firewall_data` VALUES ";
				
				for($i=0; $i<sizeof($to_mysql); $i++){
					
					$query.="(".$to_mysql[$i][0].",".$to_mysql[$i][1].")";		
					$query.= ($i == count($to_mysql)-1 ? ";" : ", "); //If the last value
					
				}
								
				$wpdb->query($query);
				
				$count_result += count($to_mysql);
			}
			return $count_result;
		}
	}
	
	//Add entries to SFW log
	static public function firewall_update_logs($ip, $result){
		
		if($ip === NULL || $result === NULL){
			error_log('SPBC Firewall log update failed');
			return;
		}
				
		global $wpdb;
		
		$blocked_new = ($result == 'blocked' ? '1' : '0');
		$blocked = ($result == 'blocked' ? ' + 1' : '');
		$time = time(); //(int)current_time('timestamp');

		$query = "INSERT INTO `".$wpdb->base_prefix."spbc_firewall_logs`
		SET 
			`ip_entry` = '$ip',
			`all_entry` = 1,
			`blocked_entry` = ".$blocked_new.",
			`entry_timestamp` = '".$time."'
		ON DUPLICATE KEY 
		UPDATE 
			`all_entry` = `all_entry` + 1,
			`blocked_entry` = `blocked_entry`".$blocked.",
			`entry_timestamp` = '".$time."'";

		$result = $wpdb->query($query);
	}
	
	//*Send and wipe SFW log
	public static function send_logs($spbc_key){
		
		global $wpdb;
		
		//Getting logs
		$result = $wpdb->get_results("SELECT * FROM `".$wpdb->base_prefix."spbc_firewall_logs`", ARRAY_A);
				
		if(count($result)){
			//Compile logs
			$data = array();
			
			//$for_return['all'] = 0;
			$for_return = 0;
			
			foreach($result as $key => $value){
				//Compile log
				$data[] = array(
					'datetime' => date('Y-m-d H:i:s', $value['entry_timestamp']),
					'visitor_ip' => ip2long(trim($value['ip_entry'])),
					'hits' => $value['blocked_entry']
				);
				//Compile to return;
				//$for_return['all'] = $for_return['all'] + $value['all_entry'];
				$for_return++;
			} unset($key, $value, $result);
			
			//Final compile
			$request_data = array (
				'data_fw' => json_encode($data),
				'rows_fw' => count($data),
				'timestamp' => time()
			);
						
			//Sendings request
			if(!function_exists('spbc_sendRawRequest'))
				require_once(plugin_dir_path(__FILE__) . 'spbc-tools.php');
			
			$result = spbc_sendRawRequest('https://api.cleantalk.org/?method_name=security_logs&auth_key='.$spbc_key, $request_data, false);
			$result = json_decode($result);
			//Checking answer and truncate table
			if(isset($result->data) && isset($result->data->rows))
				if($result->data->rows == count($data)){
					$wpdb->query("TRUNCATE TABLE `".$wpdb->base_prefix."spbc_firewall_logs`");
					return $for_return;
				}
				
		}else		
			return false;
	}
}
