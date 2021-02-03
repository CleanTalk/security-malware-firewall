<?php

if( !function_exists('locale_get_display_region') ){
	/*
	 * Patch for locale_get_display_region()
	 * For old PHP versions
	 */
	function locale_get_display_region($locale, $in_locale = 'EN'){
		return 'Unkonwn' . ($locale ? ': ' . $locale : '');
	}
}

if(!function_exists('utf8_decode')){
	/**
	 * Patch for utf8_decode()
	 * If PHP complied without XML support
	 * From getID3() by James Heinrich <info@getid3.org> under GNU GPL
	 */
	function utf8_decode($string){
		$newcharstring = '';
		$offset = 0;
		$stringlength = strlen($string);
		while ($offset < $stringlength) {
			if ((ord($string[$offset]) | 0x07) == 0xF7) {
				$charval = ((ord($string[($offset + 0)]) & 0x07) << 18) &
						   ((ord($string[($offset + 1)]) & 0x3F) << 12) &
						   ((ord($string[($offset + 2)]) & 0x3F) <<  6) &
							(ord($string[($offset + 3)]) & 0x3F);
				$offset += 4;
			} elseif ((ord($string[$offset]) | 0x0F) == 0xEF) {
				$charval = ((ord($string[($offset + 0)]) & 0x0F) << 12) &
						   ((ord($string[($offset + 1)]) & 0x3F) <<  6) &
							(ord($string[($offset + 2)]) & 0x3F);
				$offset += 3;
			} elseif ((ord($string[$offset]) | 0x1F) == 0xDF) {
				$charval = ((ord($string[($offset + 0)]) & 0x1F) <<  6) &
							(ord($string[($offset + 1)]) & 0x3F);
				$offset += 2;
			} elseif ((ord($string[$offset]) | 0x7F) == 0x7F) {
				$charval = ord($string[$offset]);
				$offset += 1;
			} else {
				$charval = false;
				$offset += 1;
			}
			if ($charval !== false) {
				$newcharstring .= (($charval < 256) ? chr($charval) : '?');
			}
		}
		return $newcharstring;
	}	
}

if(!function_exists('mime_content_type')) {
	/**
	* Patch for mime_content_type()
	* 
	* @author svogal
	* @link http://php.net/manual/ru/function.mime-content-type.php source
	*/
   function mime_content_type($filename) {

	   $mime_types = array(

		   'txt' => 'text/plain',
		   'htm' => 'text/html',
		   'html' => 'text/html',
		   'php' => 'text/html',
		   'css' => 'text/css',
		   'js' => 'application/javascript',
		   'json' => 'application/json',
		   'xml' => 'application/xml',
		   'swf' => 'application/x-shockwave-flash',
		   'flv' => 'video/x-flv',

		   // images
		   'png' => 'image/png',
		   'jpe' => 'image/jpeg',
		   'jpeg' => 'image/jpeg',
		   'jpg' => 'image/jpeg',
		   'gif' => 'image/gif',
		   'bmp' => 'image/bmp',
		   'ico' => 'image/vnd.microsoft.icon',
		   'tiff' => 'image/tiff',
		   'tif' => 'image/tiff',
		   'svg' => 'image/svg+xml',
		   'svgz' => 'image/svg+xml',

		   // archives
		   'zip' => 'application/zip',
		   'rar' => 'application/x-rar-compressed',
		   'exe' => 'application/x-msdownload',
		   'msi' => 'application/x-msdownload',
		   'cab' => 'application/vnd.ms-cab-compressed',

		   // audio/video
		   'mp3' => 'audio/mpeg',
		   'qt' => 'video/quicktime',
		   'mov' => 'video/quicktime',

		   // adobe
		   'pdf' => 'application/pdf',
		   'psd' => 'image/vnd.adobe.photoshop',
		   'ai' => 'application/postscript',
		   'eps' => 'application/postscript',
		   'ps' => 'application/postscript',

		   // ms office
		   'doc' => 'application/msword',
		   'rtf' => 'application/rtf',
		   'xls' => 'application/vnd.ms-excel',
		   'ppt' => 'application/vnd.ms-powerpoint',

		   // open office
		   'odt' => 'application/vnd.oasis.opendocument.text',
		   'ods' => 'application/vnd.oasis.opendocument.spreadsheet',
	   );

	   $tmp = explode('.',$filename);
	   $ext = strtolower(array_pop( $tmp ));
	   if (array_key_exists($ext, $mime_types)) {
		   return $mime_types[$ext];
	   }
	   elseif (function_exists('finfo_open')) {
		   $finfo = finfo_open(FILEINFO_MIME);
		   $mimetype = finfo_file($finfo, $filename);
		   finfo_close($finfo);
		   return $mimetype;
	   }
	   else {
		   return 'application/octet-stream';
	   }
   }
}

if(!function_exists('filter_var')){
	
	define('FILTER_VALIDATE_IP', 'ip');
	define('FILTER_FLAG_IPV4', 'ipv4');
	define('FILTER_FLAG_IPV6', 'ipv6');
	define('FILTER_VALIDATE_EMAIL', 'email');
	define('FILTER_FLAG_EMAIL_UNICODE', 'unicode');
	
	function filter_var($variable, $filter, $option = false){
		if($filter == 'ip'){
			if($option == 'ipv4'){
				if(preg_match("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/", $variable, $matches)){
					$variable = $matches[1];
					return $variable;
				}
			}
			if($option == 'ipv6'){
				if(preg_match("/\s*(([:.]{0,7}[0-9a-fA-F]{0,4}){1,8})\s*/", $variable, $matches)){
					$variable = $matches[1];
					return $variable;
				}
			}
		}
		if($filter == 'email'){
			if($option == 'unicode' || $option == false){
				if(preg_match("/\s*(\S*@\S*\.\S*)\s*/", $variable, $matches)){
					$variable = $matches[1];
					return $variable;
				}
			}
		}
	}
}