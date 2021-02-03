<?php

namespace CleantalkSP\Common;

class CleantalkTools{
	
	public static function get_all_files_from_directory($dir){
		
		$objs = glob($dir."/*");
		$objs_add = glob($dir."/.*");      // getting files named like .htaccess
		unset($objs_add[0], $objs_add[1]); // removing . and .. dirs from the set
		return array_merge($objs, $objs_add); 
	}
	
	public static function directory__remove__recursively($dir, $log = array()){
		
		if(!is_dir($dir)){
			$objs = self::get_all_files_from_directory($dir);
			foreach($objs as $obj){
				$log[$obj] = '';
				if(is_dir($obj)){
					$result = self::directory__remove__recursively($obj);
					$log = array_merge($log, $result['log']);
					$log[$obj] .= 'DIR';
				}else{
					$result = unlink($obj);
					$log[$obj] .= 'FILE';
				}
				if($result['success'] === false){
					$log[$obj] .= ': NOT DELETED';
					return array('success' => false, 'log' => array_merge($log, $result['log']),);
				}
				$log[$obj] .= ': DELETED';
			}
			return array('success' => rmdir($dir), 'log'     => $log,);
		}else
			return array('success' => false, 'log' => array($dir => 'is not a directory'));
	}
	
	public static function directory__view__recursively($dir, $log = array()){
		if(is_dir($dir)){
			$objs = self::get_all_files_from_directory($dir);
			foreach($objs as $obj){
				if(is_dir($obj)){
					$result = self::directory__view__recursively($obj);
					$log = array_merge($log, $result['log']);
					$log[$obj] = 'DIRECTORY';
				}else{
					$log[$obj] = 'FILE';
				}
			}
			return array('success' => true, 'log' => $log,);
			
		}else
			return array('success' => false, 'log' => array($dir => 'is not a directory'));
	}
	
}