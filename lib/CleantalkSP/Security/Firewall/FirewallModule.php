<?php

namespace CleantalkSP\Security\Firewall;

/*
 * The abstract class for any FireWall modules.
 * Compatible with any CMS.
 *
 * @version       1.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @since 2.49
 */

use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\State;

class FirewallModule extends FirewallModuleAbstract
{
    public $module_name;

    /**
     * @var DB
     */
    protected $db;
    /**
     * @var bool
     * @psalm-suppress PossiblyUnusedProperty
     */
    protected $data_table;
    /**
     * @var bool
     * @psalm-suppress PossiblyUnusedProperty
     */
    protected $log_table;

    protected $state = array();

    /**
     * @var bool
     * @psalm-suppress PossiblyUnusedProperty
     */
    protected $service_id;

    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    protected $result_code = '';

    protected $ip_array = array();

    /**
     * @var bool
     * @psalm-suppress PossiblyUnusedProperty
     */
    protected $test_ip;

    protected $die_page__file;

    /**
     * FireWall_module constructor.
     * Use this method to prepare any data for the module working.
     *
     */
    public function __construct($params = array())
    {
        foreach ( $params as $param_name => $param ) {
            $this->$param_name = isset($this->$param_name) ? $param : false;
        }
    }

    public function ipAppendAdditional(&$ips)
    {
    }

    /**
     * Use this method to execute main logic of the module.
     * @return array
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function check()
    {
        return array();
    }

    /**
     * @param $result
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function actionsForDenied($result)
    {
    }

    /**
     * @param $result
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function actionsForPassed($result)
    {
    }

    /**
     * @param mixed $db
     */
    public function setDb($db)
    {
        $this->db = $db;
    }

    /**
     * @param array $ip_array
     */
    public function setIpArray($ip_array)
    {
        $this->ip_array = $ip_array;
    }

    /**
     * Add no-cache headers
     *
     * @param Result $result
     */
    public function _die(Result $result) // phpcs:ignore PSR2.Methods.MethodDeclaration.Underscore
    {
        // Headers
        if ( headers_sent() === false ) {
            header('Expires: ' . date(DATE_RFC822, mktime(0, 0, 0, 1, 1, 1971)));
            header('Cache-Control: no-store, no-cache, must-revalidate');
            header('Cache-Control: post-check=0, pre-check=0', false);
            header('Pragma: no-cache');
            header("HTTP/1.0 403 Forbidden");
        }
    }
}
