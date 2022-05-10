<?php


namespace CleantalkSP\Common\Helpers;


use CleantalkSP\Common\Validate;

/**
 * Class CSV
 * Gather static functions designed to ease work with CSV
 *
 * @version       1.0.0
 * @package       CleantalkSP\Common\Helpers
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/security-malware-firewall
 */
class CSV
{
	public static function sanitizeFromEmptyLines( $buffer ){
		$buffer = (array) $buffer;
		foreach( $buffer as $indx => &$line ){
			$line = trim( $line );
			if($line === '')
				unset( $buffer[$indx] );
		}
		return $buffer;
	}
	
	/**
	 * Parse Comma-separated values
	 *
	 * @param $buffer
	 *
	 * @return false|string[]
	 */
	public static function parseCSV( $buffer ){
		$buffer = explode( "\n", $buffer );
		$buffer = self::sanitizeFromEmptyLines($buffer );
		foreach($buffer as &$line){
		    
		    if( $line !== '' ){
                $line = str_getcsv( $line, ',', '\'' );
            }
		    
		}
		return $buffer;
	}
	
	/**
	 * Parse Newline-separated values
	 *
	 * @param $buffer
	 *
	 * @return false|string[]
	 */
	public static function parseNSV( $buffer ){
		$buffer = str_replace( array( "\r\n", "\n\r", "\r", "\n" ), "\n", $buffer );
		$buffer = explode( "\n", $buffer );
		return $buffer;
	}
	
	/**
	 * Pops line from buffer without formatting
	 *
	 * @param $csv
	 *
	 * @return false|string
	 */
	public static function popLineFromCSV( &$csv ){
		$pos  = strpos( $csv, "\n" );
		$line = substr( $csv, 0, $pos );
		$csv  = substr_replace( $csv, '', 0, $pos + 1 );
		return $line;
	}
	
	/**
	 * Pops line from the csv buffer and fromat it by map to array
	 *
	 * @param $csv
	 *
	 * @return array|false
	 */
	public static function getMapFromCSV( &$csv )
    {
		$line = static::popLineFromCSV($csv );
		
		// Validate each element of the map
        $map = array();
		foreach( explode( ',', $line ) as $elem ){
		    if( Validate::isWord($elem) ){
		        $map[] = $elem;
            }else{
		        return array('error' => 'CSV_BAD_MAP_ELEM');
            }
        }
		
		return $map ?: array('error' => 'CSV_EMPTY_MAP');
	}
    
    /**
     * Pops line from the csv buffer and fromat it by map to array
     *
     * @param string $csv
     * @param array  $map
     *
     * @return array|false
     */
    public static function popLineFromCSVToArray(&$csv, $map = array())
    {
        $line = trim(static::popLineFromCSV($csv));
        $line = strpos($line, '\'') === 0
            ? str_getcsv($line, ',', '\'')
            : explode(',', $line);
        if( $map ){
            $line = array_combine($map, $line);
        }
        
        return $line;
    }
}