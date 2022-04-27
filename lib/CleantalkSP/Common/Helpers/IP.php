<?php

namespace CleantalkSP\Common\Helpers;

use CleantalkSP\Variables\Server;
use CleantalkSP\Templates\Singleton;

/**
 * Class IP
 * The class contains methods to work with IP
 * Supports both 6th and 4th version of IP addresses
 *
 * Uses "singleton" template to store already discovered IPs
 *
 * @version       1.0.0
 * @package       CleantalkSP\Common\Helpers
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/security-malware-firewall
 */
class IP {
    
    use Singleton;
    
    /**
     * @var array Stored IPs
     *            [
     *              [ type ] => IP,
     *              [ type ] => IP,
     *            ]
     */
    private $ips_stored = array();
    
    /**
     * @var array Set of private networks IPv4 and IPv6
     */
    public static $private_networks = array(
        'v4' => array(
            '10.0.0.0/8',
            '100.64.0.0/10',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.1/32',
        ),
        'v6' => array(
            '0:0:0:0:0:0:0:1/128', // localhost
            '0:0:0:0:0:0:a:1/128', // ::ffff:127.0.0.1
        ),
    );
    
    /**
     * @var array Set of CleanTalk servers
     */
    public static $cleantalks_servers = array(
        // MODERATE
        'moderate1.cleantalk.org' => '162.243.144.175',
        'moderate2.cleantalk.org' => '159.203.121.181',
        'moderate3.cleantalk.org' => '88.198.153.60',
        'moderate4.cleantalk.org' => '159.69.51.30',
        'moderate5.cleantalk.org' => '95.216.200.119',
        'moderate6.cleantalk.org' => '138.68.234.8',
        // APIX
        'apix1.cleantalk.org' => '35.158.52.161',
        'apix2.cleantalk.org' => '18.206.49.217',
        'apix3.cleantalk.org' => '3.18.23.246',
        'apix4.cleantalk.org' => '44.227.90.42',
        'apix5.cleantalk.org' => '15.188.198.212',
        'apix6.cleantalk.org' => '54.219.94.72',
        //ns
        'netserv2.cleantalk.org' => '178.63.60.214',
        'netserv3.cleantalk.org' => '188.40.14.173',
    );
    
    /**
     * Getting arrays of IP (REMOTE_ADDR, X-Forwarded-For, X-Real-Ip, Cf_Connecting_Ip)
     *
     * @param string $ip_type_to_get Type of IP you want to receive
     * @param array  $headers
     *
     * @return string|null
     */
    public static function get( $ip_type_to_get = 'real', $headers = array() )
    {
        // If  return the IP of the current type if it already has been detected
        $ips_stored = self::getInstance()->ips_stored;
        if( ! empty( $ips_stored[ $ip_type_to_get ] ) ){
            return $ips_stored[ $ip_type_to_get ];
        }
        
        $out = null;
        
        switch( $ip_type_to_get ){
            
            // Cloud Flare
            case 'cloud_flare':
                $headers = $headers ?: HTTP::getHTTPHeaders();
                if(
                    isset( $headers['Cf-Connecting-Ip'] ) &&
                    ( isset( $headers['Cf-Ray'] ) || isset( $headers['X-Wpe-Request-Id'] ) ) &&
                    ! isset( $headers['X-Gt-Clientip'] )
                ){
                    if( isset( $headers['Cf-Pseudo-Ipv4'], $headers['Cf-Pseudo-Ipv6'] ) ){
                        $source = $headers['Cf-Pseudo-Ipv6'];
                    }else{
                        $source = $headers['Cf-Connecting-Ip'];
                    }
                    $tmp = strpos( $source, ',' ) !== false
                        ? explode( ',', $source )
                        : (array) $source;
                    $ip_version = self::validate( trim( $tmp[0] ) );
                    if( $ip_version ){
                        $out = $ip_version === 'v6' ? self::normalizeIPv6(trim($tmp[0] ) ) : trim($tmp[0] );
                    }
                }
                break;
            
            // GTranslate
            case 'gtranslate':
                $headers = $headers ?: HTTP::getHTTPHeaders();
                if( isset( $headers['X-Gt-Clientip'], $headers['X-Gt-Viewer-Ip'] ) ){
                    $ip_version = self::validate( $headers['X-Gt-Viewer-Ip'] );
                    if( $ip_version ){
                        $out = $ip_version === 'v6' ? self::normalizeIPv6($headers['X-Gt-Viewer-Ip'] ) : $headers['X-Gt-Viewer-Ip'];
                    }
                }
                break;
            
            // ezoic
            case 'ezoic':
                $headers = $headers ?: HTTP::getHTTPHeaders();
                if( isset( $headers['X-Middleton'], $headers['X-Middleton-Ip'] ) ){
                    $ip_version = self::validate( $headers['X-Middleton-Ip'] );
                    if( $ip_version ){
                        $out = $ip_version === 'v6' ? self::normalizeIPv6($headers['X-Middleton-Ip'] ) : $headers['X-Middleton-Ip'];
                    }
                }
                break;
            
            // Sucury
            case 'sucury':
                $headers = $headers ?: HTTP::getHTTPHeaders();
                if( isset( $headers['X-Sucuri-Clientip'] ) ){
                    $ip_version = self::validate( $headers['X-Sucuri-Clientip'] );
                    if( $ip_version ){
                        $out = $ip_version === 'v6' ? self::normalizeIPv6($headers['X-Sucuri-Clientip'] ) : $headers['X-Sucuri-Clientip'];
                    }
                }
                break;
            
            // X-Forwarded-By
            case 'x_forwarded_by':
                $headers = $headers ?: HTTP::getHTTPHeaders();
                if( isset( $headers['X-Forwarded-By'], $headers['X-Client-Ip'] ) ){
                    $ip_version = self::validate( $headers['X-Client-Ip'] );
                    if( $ip_version ){
                        $out = $ip_version === 'v6' ? self::normalizeIPv6($headers['X-Client-Ip'] ) : $headers['X-Client-Ip'];
                    }
                }
                break;
            
            // Stackpath
            case 'stackpath':
                $headers = $headers ?: HTTP::getHTTPHeaders();
                if( isset( $headers['X-Sp-Edge-Host'], $headers['X-Sp-Forwarded-Ip'] ) ){
                    $ip_version = self::validate( $headers['X-Sp-Forwarded-Ip'] );
                    if( $ip_version ){
                        $out = $ip_version === 'v6' ? self::normalizeIPv6($headers['X-Sp-Forwarded-Ip'] ) : $headers['X-Sp-Forwarded-Ip'];
                    }
                }
                break;
            
            // Ico-X-Forwarded-For
            case 'ico_x_forwarded_for':
                $headers = $headers ?: HTTP::getHTTPHeaders();
                if( isset( $headers['Ico-X-Forwarded-For'], $headers['X-Forwarded-Host'] ) ){
                    $ip_version = self::validate( $headers['Ico-X-Forwarded-For'] );
                    if( $ip_version ){
                        $out = $ip_version === 'v6' ? self::normalizeIPv6($headers['Ico-X-Forwarded-For'] ) : $headers['Ico-X-Forwarded-For'];
                    }
                }
                break;
            
            // OVH
            case 'ovh':
                $headers = $headers ?: HTTP::getHTTPHeaders();
                if( isset( $headers['X-Cdn-Any-Ip'], $headers['Remote-Ip'] ) ){
                    $ip_version = self::validate( $headers['Remote-Ip'] );
                    if( $ip_version ){
                        $out = $ip_version === 'v6' ? self::normalizeIPv6($headers['Remote-Ip'] ) : $headers['Remote-Ip'];
                    }
                }
                break;
            
            // Incapsula proxy
            case 'incapsula':
                $headers = $headers ?: HTTP::getHTTPHeaders();
                if( isset( $headers['Incap-Client-Ip'], $headers['X-Forwarded-For'] ) ){
                    $ip_version = self::validate( $headers['Incap-Client-Ip'] );
                    if( $ip_version ){
                        $out = $ip_version === 'v6' ? self::normalizeIPv6($headers['Incap-Client-Ip'] ) : $headers['Incap-Client-Ip'];
                    }
                }
                break;
            
            // Remote addr
            case 'remote_addr':
                $ip_version = self::validate( Server::get( 'REMOTE_ADDR' ) );
                if( $ip_version ){
                    $out = $ip_version === 'v6' ? self::normalizeIPv6(Server::get('REMOTE_ADDR' ) ) : Server::get('REMOTE_ADDR' );
                }
                break;
            
            // X-Forwarded-For
            case 'x_forwarded_for':
                $headers = $headers ?: HTTP::getHTTPHeaders();
                if( isset( $headers['X-Forwarded-For'] ) ){
                    $tmp     = explode( ',', trim( $headers['X-Forwarded-For'] ) );
                    $tmp     = trim( $tmp[0] );
                    $ip_version = self::validate( $tmp );
                    if( $ip_version ){
                        $out = $ip_version === 'v6' ? self::normalizeIPv6($tmp ) : $tmp;
                    }
                }
                break;
            
            // X-Real-Ip
            case 'x_real_ip':
                $headers = $headers ?: HTTP::getHTTPHeaders();
                if(isset($headers['X-Real-Ip'])){
                    $tmp = explode(",", trim($headers['X-Real-Ip']));
                    $tmp = trim($tmp[0]);
                    $ip_version = self::validate($tmp);
                    if($ip_version){
                        $out = $ip_version === 'v6' ? self::normalizeIPv6($tmp) : $tmp;
                    }
                }
                break;
            
            // Real
            // Getting real IP from REMOTE_ADDR or Cf_Connecting_Ip if set or from (X-Forwarded-For, X-Real-Ip) if REMOTE_ADDR is local.
            case 'real':
                
                // Detect IP type
                $out = self::get( 'cloud_flare', $headers );
                $out = $out ?: self::get( 'sucury', $headers );
                $out = $out ?: self::get( 'gtranslate', $headers );
                $out = $out ?: self::get( 'ezoic', $headers );
                $out = $out ?: self::get( 'stackpath', $headers );
                $out = $out ?: self::get( 'x_forwarded_by', $headers );
                $out = $out ?: self::get( 'ico_x_forwarded_for', $headers );
                $out = $out ?: self::get( 'ovh', $headers );
                $out = $out ?: self::get( 'incapsula', $headers );
                
                $ip_version = self::validate( $out );
                
                // Is private network
                if(
                    ! $out ||
                    ($out &&
                     (
                         self::isIPInPrivateNetworks($out, $ip_version ) ||
                         self::isIPInNetwork(
                             $out,
                             Server::get( 'SERVER_ADDR' ) . '/24',
                             $ip_version
                         )
                     ))
                ){
                    //@todo Remove local IP from x-forwarded-for and x-real-ip
                    $out = $out ?: self::get( 'x_forwarded_for', $headers );
                    $out = $out ?: self::get( 'x_real_ip', $headers );
                }
                
                $out = $out ?: self::get( 'remote_addr', $headers );
                
                break;
            
            default:
                $out = self::get( 'real', $headers );
        }
        
        // Final validating IP
        $out = self::validate( $out )
            ? $out
            : null;
        
        // Store the IP of the current type to skip the work next time
        self::getInstance()->ips_stored[ $ip_type_to_get ] = $out;
        
        return $out;
    }
    
    /**
     * Validating IPv4, IPv6
     *
     * @param mixed $ip
     *
     * @return string|bool returns the string with IP address version or false if bad data were passed
     * 
     */
    public static function validate($ip)
    {
        // Inappropriate value passed
        if( ! $ip ){
            return false;
        }
        
        // IPv4
        if( filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && $ip !== '0.0.0.0' ){
            return 'v4';
        }
        
        // IPv6
        if( filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && self::reduceIPv6($ip) !== '::' ){
            return 'v6';
        }
        
        return false;
    }
    
    /**
     * Normalize IPv6 to full length with all hextets.
     * Hextet - part of address which could contain 16 bits. Separated by ":" 1:2:3:4:5:6:7:8
     *
     * Please, note that all hextets will be present, but they won't be expanded.
     * See the examples below to make a difference:
     * 1:2:3:::6:7:8 - reduced
     * 1:2:3:0:0:6:7:8 - normalized
     * 0001:0002:0003:0000:0000:0006:0007:0008 - normalized and expanded
     *
     * @param string $ip
     *
     * @return string IPv6
     */
    public static function normalizeIPv6($ip)
    {
        if ( ! self::validate($ip) ){
            return false;
        }
        
        $ip = trim($ip, ' \n\r\t\v"');
        
        // Normalize IPv4 to IPv6
        $ip = preg_match('/^((?>\d{1,3}\.?){4})$/', $ip) ? '0:0:0:0:0:0:' . $ip : $ip;
        $ip = str_replace('::ffff:', '0:0:0:0:0:0:', $ip);
        
        // Searching for ::ffff:xx.xx.xx.xx patterns and turn it to IPv6
        if( preg_match( '/^(.*?)((?>\d{1,3}\.?){4})$/', $ip, $matches ) ){
            $ipv4 = dechex( sprintf( "%u", ip2long( $matches[2] ) ) );
            $ip = $matches[1]
                  . (strlen($ipv4) > 4 ? substr( $ipv4, 0, -4) : '0:')
                  . ':' . substr($ipv4, -4, 4);
            
            // Normalizing hextets number (
        }elseif(strpos($ip, '::') !== false){
            $ip = str_replace('::', str_repeat(':0', 8 - substr_count($ip, ':')) . ':', $ip);
        }
        
        // Replacing head and rear ":" with "0:" and ":0"
        $ip = strpos($ip, ':') === 0         ? '0' . $ip : $ip;
        $ip = strpos(strrev($ip), ':') === 0 ? $ip . '0' : $ip;
        
        // Simplifying hextets. Replacing heading zeros in the each hextets
        if(preg_match('/:0(?=[a-z0-9]+)/', $ip)){
            $ip = preg_replace('/:0(?=[a-z0-9]+)/', ':', strtolower($ip));
            $ip = self::normalizeIPv6($ip);
        }

        return strtolower( $ip );
    }
    
    /**
	 * Extend IPv6 to full length
	 * 1:2:3:4:5:6:7:8 becomes 0001:0002:0003:0004:0005:0006:0007:0008
	 *
	 * @param $ipv6
	 *
	 * @return string
	 */
	public static function extendIPv6( $ipv6 ){
		
		$ipv6 = explode( ':', $ipv6 );
		
		foreach( $ipv6 as &$hextet ){
			$hextet = str_pad( $hextet, 4, '0', STR_PAD_LEFT);
		}
		
		return implode( ':', $ipv6 );
	}

    
    /**
     * Reduce IPv6
     *
     * @param string $ip
     *
     * @return string IPv6
     */
    public static function reduceIPv6($ip)
    {
        if(strpos($ip, ':') !== false){
            $ip = preg_replace('/:0{1,4}/', ':', $ip);
            $ip = preg_replace('/:{2,}/', '::', $ip);
            $ip = strpos($ip, '0') === 0 ? substr($ip, 1) : $ip;
        }
        return $ip;
    }
    
    /**
     * Checks if the IP belongs to private network ranges
     *
     * @param string $ip
     * @param string $ip_type
     *
     * @return bool
     */
    public static function isIPInPrivateNetworks($ip, $ip_type = 'v4')
    {
        return self::isIPInNetwork($ip, self::$private_networks[$ip_type], $ip_type);
    }
    
    /**
     * Check if the IP belong to mask.
     * Recursive.
     *
     * Octet by octet for IPv4
     * Hextet by hextet for IPv6
     *
     * @param string $ip
     * @param string $cidr       network to compare with
     * @param string $ip_type    IPv6 or IPv4
     * @param int    $xtet_count Recursive counter. Determs current part of address to check.
     *
     * @return bool
     */
    public static function isIPInNetwork($ip, $cidr, $ip_type = 'v4', $xtet_count = 0)
    {
        if( is_array($cidr) ){
            foreach( $cidr as $curr_mask ){
                if( self::isIPInNetwork($ip, $curr_mask, $ip_type) ){
                    return true;
                }
            }
            
            return false;
        }
        
        if( ! self::validate($ip) || ! self::validateCIDR($cidr) ){
            return false;
        }
        
        $xtet_base = ($ip_type === 'v4') ? 8 : 16;
        
        // Calculate mask
        $exploded = explode('/', $cidr);
        $net_ip   = $exploded[0];
        $mask     = $exploded[1];
        
        // Exit condition
        $xtet_end = ceil($mask / $xtet_base);
        if( $xtet_count === $xtet_end ){
            return true;
        }
        
        // Length of bits for comparision
        $mask = $mask - $xtet_base * $xtet_count >= $xtet_base ? $xtet_base : $mask - $xtet_base * $xtet_count;
        
        // Explode by octets/hextets from IP and Net
        $net_ip_xtets = explode($ip_type === 'v4' ? '.' : ':', $net_ip);
        $ip_xtets     = explode($ip_type === 'v4' ? '.' : ':', $ip);
        
        // Standardizing. Getting current octets/hextets. Adding leading zeros.
        $net_xtet = str_pad(decbin($ip_type === 'v4' ? $net_ip_xtets[$xtet_count] : @hexdec($net_ip_xtets[$xtet_count])), $xtet_base, 0, STR_PAD_LEFT);
        $ip_xtet  = str_pad(decbin($ip_type === 'v4' ? $ip_xtets[$xtet_count] : @hexdec($ip_xtets[$xtet_count])), $xtet_base, 0, STR_PAD_LEFT);
        
        // Comparing bit by bit
        for( $i = 0, $result = true; $mask !== 0; $mask--, $i++ ){
            if( $ip_xtet[$i] !== $net_xtet[$i] ){
                $result = false;
                break;
            }
        }
        
        // Recursion. Moving to next octet/hextet.
        if( $result ){
            $result = self::isIPInNetwork($ip, $cidr, $ip_type, $xtet_count + 1);
        }
        
        return $result;
    }
    
    /**
     * Validate CIDR
     *
     * @param string $cidr expects string like 1.1.1.1/32
     *
     * @return bool
     */
    public static function validateCIDR( $cidr ){
        $cidr = explode( '/', $cidr );
        return isset( $cidr[0], $cidr[1] ) && self::validate( $cidr[0] ) && preg_match( '@\d{1,2}@', $cidr[1] );
    }
    
	/**
	 * Converts a valid IPv6 to four IPv4
	 *
	 * @param string $ipv6
	 *
	 * @return array 4 IPv4
	 */
	public static function convertIPv6ToFourIPv4( $ipv6 )
	{
		$current_ip_txt = explode( ':', $ipv6 );
		
		return array(
            sprintf( '%u', hexdec( $current_ip_txt[0] . $current_ip_txt[1] ) ),
            sprintf( '%u', hexdec( $current_ip_txt[2] . $current_ip_txt[3] ) ),
            sprintf( '%u', hexdec( $current_ip_txt[4] . $current_ip_txt[5] ) ),
			sprintf( '%u', hexdec( $current_ip_txt[6] . $current_ip_txt[7] ) ),
		);
	}
	
	/**
	 * Calculate new IP by mask and IP (integer view)
	 *
	 * @param integer $ip
	 * @param $mask
	 *
	 * @return string
	 */
	public static function calculateMaskForIP( $ip, $mask )
	{
		$mask  = str_pad( str_repeat( '1', $mask ), 32, '0' );
		
		return sprintf( "%u", bindec( $mask & base_convert( $ip, 10, 2 ) ) );
	}
	
	/**
	 * Calculate new IPs by masks and IP (integer view)
	 *
	 * @param integer $ip
	 * @param int $mask_start
	 * @param int $mask_end
	 *
	 * @return array
	 */
	public static function calculateMaskForIPs( $ip, $mask_start, $mask_end )
    {
		for( $out = array(), $mask = $mask_start; $mask <= $mask_end; $mask ++ ){
			$out[] = self::calculateMaskForIP($ip, $mask );
		}
		
		return $out;
	}
	
	/**
	 * Get URL form IP. Check if it's belong to cleantalk.
	 *
	 * @param string $ip
	 *
	 * @return false|int|string
	 */
	public static function isIPCleantalks($ip)
	{
		if(self::validate($ip)){
			$url = array_search($ip, self::$cleantalks_servers, true);
			return $url
				? true
				: false;
		}
  
        return false;
	}
	
	/**
	 * Get URL form IP. Check if it's belong to cleantalk.
	 *
	 * @param $ip
	 *
	 * @return false|int|string
	 */
	public static function resolveCleantalks($ip)
	{
		if(self::validate($ip)){
			$url = array_search( $ip, self::$cleantalks_servers, true );
			return $url ?: self::resolve($ip );
		}
		
        return $ip;
	}
	
	/**
	 * Get URL form IP
	 *
	 * @param $ip
	 *
	 * @return string
	 */
	public static function resolve($ip)
	{
		if(self::validate($ip)){
			$url = gethostbyaddr($ip);
			if($url){
                return $url;
            }
		}
		return $ip;
	}
}