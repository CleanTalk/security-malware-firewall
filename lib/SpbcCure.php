<?php

class SpbcCure {
	
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
					
					$result = $this->signtaure_cure($file, $this->signature);
					if(!empty($result['error'])){
						$this->result = $result;
						return ;
					}
				}
			}
		}else
			$this->result = array('error' => 'COULD NOT GET SIGNATURE FROM DB');
    }

	public function signtaure_cure($file, $signature) {
		
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
						$result = $this->action_perform__with_file($object,	$instruction['action'], $file); // Actions with file.
					}else{
						$result = $this->action_perform__with_code($object,	$instruction['action'], $file); // Actions with code.
					}			
					
					$this->objects[] = $object;
					
					if(!empty($result['error']))
						return $result;
					
				}
			}
		}
	}
	
	public function action_perform__with_file($object, $actions, $file) {
    	$result = true;
		foreach ( $actions as $action => $action_details ) {
			switch ($action) {
				case 'delete':
					$result = unlink($object['file']);
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
	
	public function action_perform__with_code($object, $actions, $file) {
		
		$result = true;
  
		foreach ( $actions as $action => $action_details ) {
			
			$file_content = file_get_contents( $object['file'] );
			$is_regexp = preg_match( '@^/.*/$@', $object['code'] ) || preg_match( '@^#.*#$@', $object['code'] );
			
			switch ($action) {
				case 'delete':
					
					$file_content = $is_regexp
						? preg_replace( $object['code'], '', $file_content, 1 )
						: str_replace( $object['code'], '', $file_content );
					
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
