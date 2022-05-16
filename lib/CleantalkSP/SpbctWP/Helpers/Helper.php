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

    /**
     * Returns true if $signature is regexp, else return false. Supports modifications set [imSsxADUuXJ].
     * @param string $signature - signature expression from DB
     * @param string $delimiters - delimiters for regexp. Default set is '#/'. Do not use @ symbol as delimiter.
     * @return bool
     */
    public static function isRegexp($signature, $delimiters = '#/')
    {
        $pattern_modifiers = '[imSsxADUuXJ]{0,11}';
        $limit = strlen($delimiters) - 1;
        for ( $i = 0; $i <= $limit; $i++ ) {
            $pattern = '@^' . $delimiters[$i] . '.*' . $delimiters[$i] . $pattern_modifiers . '$@';
            if ( preg_match($pattern, $signature) ) {
                return true;
            }
        }
        return false;
    }
}