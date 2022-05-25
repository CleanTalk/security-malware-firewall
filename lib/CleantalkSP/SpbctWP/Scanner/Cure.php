<?php

namespace CleantalkSP\SpbctWP\Scanner;

class Cure {
	
	public $signature = null;
	public $objects = array();
	public $actions = array();
	public $modifiers = array();
	public $comments = array();
	
	public $result = true;
	
    function __construct($file){
        
		global $wpdb;
		
		$weak_spots = json_decode($file['weak_spots'], true);
		
		if(!empty($weak_spots['SIGNATURES'])){
			
			foreach ($weak_spots['SIGNATURES'] as $string => $signatures_in_string) {
				
				foreach ($signatures_in_string as $signature_id) {
					
					$tmp = $wpdb->get_results('SELECT * FROM '. SPBC_TBL_SCAN_SIGNATURES .' WHERE id = "'. $signature_id .'"', OBJECT);
					$this->signature = $tmp[0];
					
					$result = $this->signature_cure($file, $this->signature);
					if(!empty($result['error'])){
						$this->result = $result;
						return ;
					}
				}
			}
		}else
			$this->result = array('error' => 'COULD NOT GET SIGNATURE FROM DB');
    }

	public function signature_cure($file, $signature) {
		
		if(!empty($signature->cci)){
			
			$instructions = json_decode($signature->cci, true);
			
			foreach ($instructions['cci'] as $instruction) {
				
				// Object
				foreach ($instruction['objects'] as $key => &$object) {
					
					// Building path to file
					
					// Default if unset
					if(!isset($object['file']))
						$object['file'] = 'self';
					
					// self
					if($object['file'] === 'self'){
						$object['file'] = spbc_get_root_path().$file['path'];
					// absolute "/var/www/wordpress.com"
					}elseif($object['file'][0] == '/' || $object['file'][0] == '\\'){
						$object['file'] = spbc_get_root_path().$object['file'];
					// relative ".some_file.php"
					}else{
						$object['file'] = spbc_get_root_path()
							.preg_replace('/(.*\\\\).*?\.php$/', '$1',	$file['path'])
							.$object['file'];
					}
					
					// Building code if nessary
					if(isset($object['code'])){
						if($object['code'] === 'self')
							$object['code'] = $signature->body;
					}
					
					// Perform actions
					if(!isset($object['code'])){
						$result = $this->action_perform__with_file($object,	$instruction['action'], $file, $signature->id ); // Actions with file.
					}else{
						$result = $this->action_perform__with_code($object,	$instruction['action'], $file, $signature->id); // Actions with code.
					}			
					
					$this->objects[] = $object;
					
					if(!empty($result['error'])) {
                        return $result;
                    } else {
                        global $spbc;

                        if(!$spbc->settings['there_was_signature_treatment']) {
                            $spbc->settings['there_was_signature_treatment'] = 1;
                            $spbc->save('settings');
                        }
                    }				
				}
			}
		}
	}
	
	/**
	 * @param $object
	 * @param $actions
	 * @param $file
	 * @param string $signature_id
	 *
	 * @return array|bool|bool[]|false|int|string[]
	 */
	public function action_perform__with_file($object, $actions, $file, $signature_id) {
    	$result = true;
		
		if( ! file_exists( $object['file'] ) )
			return array( 'error' => 'Curing. File ' . $object['file'] . ' does not exists.');
   
		foreach ( $actions as $action => $action_details ) {
			switch ($action) {
				case 'delete':
					$result = unlink($object['file']);
					file_put_contents( $object['file'], "<?php\n// Security by Cleantalk: Malware was deleted: #". $signature_id );
					break;
				case 'quarantine':
					$result = spbc_scanner_file_quarantine(true, $file['fast_hash']);
					break;
				case 'move_to':
					/** @todo moveTo */
					break;
				case 'replace_with':
					if($action_details === 'original')
						$result = spbc_scanner_file_replace(true, $file['fast_hash']);
					if($action_details === 'blank')
						$result = file_put_contents($object['file'], '<?php\n/* File was cleaned by Security by Cleantalk */');
					break;
			}
		}
		return $result;
	}
	
	/**
	 * @param $object
	 * @param $actions
	 * @param $file
	 * @param $signature_id
	 *
	 * @return bool|false|int
	 */
	public function action_perform__with_code($object, $actions, $file, $signature_id) {
		
		$result = true;
  
		foreach ( $actions as $action => $action_details ) {
			
			if( file_exists( $object['file'] ) ) {
                $file_content = file_get_contents( $object['file'] );
            } else {
                return array('error' => 'Curing. File ' . $object['file'] . ' does not exists.');
            }
			
				$is_regexp = \CleantalkSP\SpbctWP\Helpers\Helper::isRegexp($object['code']);
			
			switch ($action) {
				case 'delete':
					
					$file_content = $is_regexp
						? preg_replace( $object['code'], '// Security by Cleantalk: Malware was deleted: #'. $signature_id, $file_content, 1 )
						: str_replace( $object['code'], '// Security by Cleantalk: Malware was deleted: #'. $signature_id, $file_content );
					
					$result = file_put_contents($object['file'], $file_content);
					
					break;
					
				case 'replace_with':
					
					$file_content = $is_regexp
						? preg_replace( $object['code'], $action_details, $file_content, 1 )
						: str_replace( $object['code'], $action_details, $file_content );
					
					$result = file_put_contents($object['file'], $file_content);
					
					break;
			}
		}
		
		return $result;
	}
}
