<?php

use CleantalkSP\SpbctWP\Helpers\Helper;

function spbc_backup__rotate($type = 'signatures', $out = array('success' => true)){
	global $wpdb;
	$result = $wpdb->get_row('SELECT COUNT(*) as cnt FROM '. SPBC_TBL_BACKUPS .' WHERE type = '. Helper::prepareParamForSQLQuery(strtoupper($type)), OBJECT);
	if($result->cnt > 10){
		$result = $wpdb->get_results(
			'SELECT backup_id'
			. ' FROM '. SPBC_TBL_BACKUPS
			. ' WHERE datetime < ('
				. 'SELECT datetime'
				. ' FROM '. SPBC_TBL_BACKUPS
				. ' WHERE type = ' . Helper::prepareParamForSQLQuery(strtoupper($type))
				. ' ORDER BY datetime DESC'
				. ' LIMIT 9,1)'
		);
		if($result && count($result)){
			foreach ($result as $backup) {
				$result = spbc_backup__delete(true, $backup->backup_id);
				if(!empty($result['error'])){
                    $out = array('error' => 'BACKUP_DELETE: ' . substr($result['error'], 0, 1024));
                }
			}
		}
	}
	
	return $out;
}

function spbc_backup__delete($direct_call = false, $backup_id = null){
	
	if(!$direct_call){
        check_ajax_referer('spbc_secret_nonce', 'security');
    }
	$backup_id = !$direct_call && !empty($_POST['backup_id']) ? (int)$_POST['backup_id'] : $backup_id;
	
	if(is_dir(SPBC_PLUGIN_DIR.'backups/backup_'.$backup_id)){
	
		global $wpdb;

		// Deleting backup files
		foreach(glob(SPBC_PLUGIN_DIR.'backups/backup_'.$backup_id.'/*') as $filename){
			if(!unlink($filename)){
				$output = array('error' =>'FILE_DELETE_ERROR: '. substr($filename, 0, 1024));
				break;
			}
		}

		if(empty($output['error'])){
			if(rmdir(SPBC_PLUGIN_DIR.'backups/backup_'.$backup_id)){
				if($wpdb->delete( SPBC_TBL_BACKUPED_FILES, array( 'backup_id' => $backup_id ), array('%d'))){
					if($wpdb->delete( SPBC_TBL_BACKUPS, array( 'backup_id' => $backup_id ), array('%d'))){
						$output = array(
							'html' => '<td '.(isset($_POST['cols']) ? "colspan='{$_POST['cols']}'" : '').'>Backup deleted</td>',
							'success' => true,
							'color' => 'black',
							'background' => 'rgba(240, 110, 110, 0.7)',
						);
					}else{
                        $output = array('error' => 'DELETING_BACKUP_DB_ERROR: ' . substr($wpdb->last_error, 0, 1024));
                    }
				}else{
                    $output = array('error' => 'DELETING_BACKUP_FILES_DB_ERROR: ' . substr($wpdb->last_error, 0, 1024));
                }
			}else{
                $output = array('error' => 'DIRECTORY_DELETE_ERROR: ' . substr(SPBC_PLUGIN_DIR . 'backups/backup_' . $backup_id, 0, 1024));
            }
		}
	}else{
        $output = array('comment' => 'DIRECTORY_NOT_EXISTS: ' . substr(SPBC_PLUGIN_DIR . 'backups/backup_' . $backup_id, 0, 1024));
    }
	
	if(!$direct_call){
        header('Content-Type: application/json');
        die(json_encode($output));
    }
    
    return $output;
}

function spbc_backup__files_with_signatures($direct_call = false){
	
	if(!$direct_call){
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }
	
	global $wpdb, $spbc;
	
	$files_to_backup = $wpdb->get_results('SELECT path, weak_spots FROM '. SPBC_TBL_SCAN_FILES .' WHERE weak_spots LIKE "%{\"SIGNATURES\":%";', ARRAY_A);
	
	if(is_array($files_to_backup) && count($files_to_backup)){
		
		$sql_query = 'INSERT INTO '.SPBC_TBL_BACKUPED_FILES.' (backup_id, real_path, back_path) VALUES';
		$sql_data = array();
		
		foreach ($files_to_backup as $file) {
			
			$weak_spots = json_decode($file['weak_spots'], true);
			
			if(!empty($weak_spots['SIGNATURES'])){
				$signtures_in_file = array();
				foreach ($weak_spots['SIGNATURES'] as $signatures_in_string) {
					$signtures_in_file = array_merge($signtures_in_file, array_diff($signatures_in_string, $signtures_in_file));
				}
				$signtures_in_file = implode(',', $signtures_in_file);
			}
			
			$signatures_with_cci = !empty($signtures_in_file)
				? $wpdb->get_results('SELECT * FROM '. SPBC_TBL_SCAN_SIGNATURES .' WHERE id IN ('. $signtures_in_file .') AND cci IS NOT NULL')
				: null;
			
			// Backup only files which will be cured
			if( $signatures_with_cci ) {
				
				if( ! isset( $backup_id ) ){
					
					// Adding new backup
					$wpdb->insert(SPBC_TBL_BACKUPS, array('type' => 'SIGNATURES', 'datetime' => date('Y-m-d H:i:s')));
					$backup_id = $wpdb->insert_id;
					
					if(!is_dir(SPBC_PLUGIN_DIR.'backups/')){
                        mkdir(SPBC_PLUGIN_DIR . 'backups/');
                    }
						
					if(!is_dir(SPBC_PLUGIN_DIR.'backups/backup_'.$backup_id)){
                        mkdir(SPBC_PLUGIN_DIR . 'backups/backup_' . $backup_id);
                    }
				}
				
				$result = spbc_backup__file( $file['path'], $backup_id );
				
				if ( empty( $result['error'] ) ) {
					$sql_data[] = '(' . $backup_id . ',' . Helper::prepareParamForSQLQuery($file['path'] ) . ',' . Helper::prepareParamForSQLQuery($result ) . ')';
				} else {
					$output = $result;
					break;
				}
			}
		}
		
		// Writing backuped files to DB
		if( ! empty( $sql_data ) ) {
			
			if ( $wpdb->query( $sql_query . implode( ',', $sql_data ) . ';' ) !== false ) {
				
				// Updating current backup status
				if ( $wpdb->update( SPBC_TBL_BACKUPS, array( 'status' => 'BACKUPED' ), array( 'backup_id' => $backup_id ) ) !== false ) {
					
					$result = spbc_backup__rotate( 'signatures' );
					if ( empty( $result['error'] ) ) {
						
						$spbc->data['scanner']['last_backup'] = $backup_id;
						$spbc->save( 'data' );
						
						$output = array( 'success' => true );
					} else {
						$output = array( 'error' => 'BACKUP_ROTATE: ' . substr( $result['error'], 0, 1024 ) );
					}
				} else {
					$output = array( 'error' => 'DB_WRITE_ERROR: ' . substr( $wpdb->last_error, 0, 1024 ) );
				}
			} else {
				$wpdb->update( SPBC_TBL_BACKUPS, array( 'status' => 'STOPPED' ), array( 'backup_id' => $backup_id ) );
				$output = array( 'error' => 'DB_WRITE_ERROR: ' . substr( $wpdb->last_error, 0, 1024 ) );
			}
		}else{
            $output = array('success' => true);
        }
	}else{
        $output = array('success' => true);
    }
    
    $output['end'] = 1;
	
	if(!$direct_call){
        header('Content-Type: application/json');
        die(json_encode($output));
    }
    
    return $output;
}

function spbc_backup__file($filename, $backup_id){
	
	global $spbc;
	
	$file_path = spbc_get_root_path().$filename;
	
	if(file_exists($file_path)){
		
		if(is_readable($file_path)){
			
			$backup_path = '/wp-content/plugins/security-malware-firewall/backups/backup_'
               . $backup_id
               . '/' . str_replace( '/', '__', str_replace( '\\', '__', $filename ) )
               . '.' . hash( 'sha256', $filename . $spbc->data['salt'] );
						
			if(copy($file_path, spbc_get_root_path().$backup_path)){
				$output = $backup_path;
				
			}else{
                $output = array('error' => 'COPY_FAILED');
            }
		}else{
            $output = array('error' => 'FILE_NOT_READABLE');
        }
	}else{
        $output = array('error' => 'FILE_NOT_EXISTS');
    }
	
	return $output;
}

function spbc_rollback($direct_call = false, $backup_id = null){

	if(!$direct_call){
        check_ajax_referer('spbc_secret_nonce', 'security');
    }
		
	$backup_id = !$direct_call && !empty($_POST['backup_id']) ? (int)$_POST['backup_id'] : $backup_id;
	
	global $wpdb;
	
	$files_to_rollback = $wpdb->get_results('SELECT real_path, back_path FROM '. SPBC_TBL_BACKUPED_FILES .' WHERE backup_id = '. $backup_id .';', ARRAY_A);
		
	if(is_array($files_to_rollback) && count($files_to_rollback)){
		
		$wpdb->update(SPBC_TBL_BACKUPS, array('status' => 'ROLLBACK'), array('backup_id' => $backup_id));
		
		foreach ($files_to_rollback as $file) {
			
			$result = spbc_rollback__file($file['back_path'], $file['real_path']);
            
            if( ! empty($result['error']) ){
                $output = $result;
                break;
            }
		}
		
		if(empty($output['error'])){
			
			if($wpdb->delete( SPBC_TBL_BACKUPED_FILES, array( 'backup_id' => $backup_id ), array('%d'))){
				
				if($wpdb->delete( SPBC_TBL_BACKUPS, array( 'backup_id' => $backup_id ), array('%d'))){
					
					rmdir(spbc_get_root_path().'/wp-content/plugins/security-malware-firewall/backups/backup_'.$backup_id);
					
					$output = array(
						'html' => '<td '.(isset($_POST['cols']) ? "colspan='{$_POST['cols']}'" : '').'>Rollback succeeded</td>',
						'success' => true,
						'color' => 'black',
						'background' => 'rgba(110, 240, 110, 0.7)',
					);
						
				}else{
                    $output = array('error' => 'DELETING_BACKUP_DB_WRITE_ERROR: ' . substr($wpdb->last_error, 0, 1024));
                }
			}else{
                $output = array('error' => 'DELETING_BACKUP_FILES_DB_WRITE_ERROR: ' . substr($wpdb->last_error, 0, 1024));
            }
		}else{
            $output = array('error' => 'FILE_BACKUP_ERROR: ' . $output['error'] . 'FILE: ' . $file['back_path']);
        }
	}else{
        $output = array('error' => 'BACKUP_NOT_FOUND');
    }
	
	if(!$direct_call){
        header('Content-Type: application/json');
        die(json_encode($output));
    }
    
    return $output;
}

function spbc_rollback__file($back_path, $real_path){
	
	$back_path = spbc_get_root_path().$back_path;
	$real_path = spbc_get_root_path().$real_path;
	
	if(file_exists($back_path)){
		
		if(is_writable($back_path)){
			
			if(is_dir(dirname($real_path))){
				
				if(copy($back_path, $real_path)){
					
					unlink($back_path);
					
					$output = array('success' => true);
					
				}else{
                    $output = array('error' => 'COPY_FAILED');
                }
			}else{
                $output = array('error' => 'REAL_FILE_DIR_NOT_EXISTS');
            }
		}else{
            $output = array('error' => 'BACKUPED_FILE_NOT_WRITABLE');
        }
	}else{
        $output = array('error' => 'BACKUPED_FILE_NOT_EXISTS');
    }
	
	return $output;
	
}

function spbc_backups_count_found() {

	global $wpdb;

	$count = $wpdb->get_results(
		'SELECT COUNT(*) FROM '. SPBC_TBL_BACKUPS,
		OBJECT_K);
	return $count ? key($count) : 0;

}