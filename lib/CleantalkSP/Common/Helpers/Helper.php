<?php


namespace CleantalkSP\Common\Helpers;


class Helper
{
    /**
	 * Resolve DNS to a single IP-address
	 *
	 * @param string $host
	 * @param bool   $out
	 *
	 * @return bool
	 */
	public static function resolveDNS($host, $out = false)
	{
		// Get DNS records about URL
		if(function_exists('dns_get_record')){
			$records = @dns_get_record($host, DNS_A);
			if($records !== false){
				$out = $records[0]['ip'];
			}
		}
		
		// Another try if first failed
		if(!$out && function_exists('gethostbynamel')){
			$records = gethostbynamel($host);
			if($records !== false){
				$out = $records[0];
			}
		}
		
		return $out;
		
	}
    
    /**
     * Return the start of the given time interval in seconds
     *
     * @param int $interval Duration of the interval
     *
     * @return int
     */
    public static function getTimeIntervalStart( $interval = 300 ){
		return time() - ( ( time() - strtotime( date( 'd F Y' ) ) ) % $interval );
	}

}