<?php


namespace CleantalkSP\SpbctWP\Helpers;


class Helper extends \CleantalkSP\Common\Helpers\Helper
{
    /**
	 * Escapes MySQL params
	 *
	 * @param string|int|array $param
	 * @param string     $quotes
	 *
	 * @return int|string
	 */
	public static function prepareParamForSQLQuery($param, $quotes = '\'')
	{
		if(is_array($param)){
			foreach($param as &$par){
				$par = self::prepareParamForSQLQuery($par);
			} unset( $par );
		}
		switch(true){
			case is_numeric($param):
				$param = intval($param);
				break;
			case is_string($param) && strtolower($param) === 'null':
				$param = 'NULL';
				break;
			case is_string($param):
				global $wpdb;
//				$param = preg_match('/;|\'+/', $param) ? preg_replace('/;|\'+/', '', $param) : $param;
				$param = $quotes . $wpdb->_real_escape($param) . $quotes;
				break;
		}
		return $param;
	}
	
	/**
	 * Escapes MySQL params
	 *
	 * @param string|int $param
	 *
	 * @return int|string
	 */
	public static function unescapeString($param)
	{
		$patterns = array(
			'/\//',
			'/\;/',
			'/\|/',
			'/\\\\\r/',
			'/\\\\\\\\/',
			"/\\\\\'/",
			'/\\\\\"/',
		);
		$replacements = array(
			'/',
			';',
			'|',
			'\r',
			'\\',
			'\'',
			'"',
		);
		$param = preg_replace($patterns, $replacements, $param );
		return $param;
	}
}