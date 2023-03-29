<?php

namespace CleantalkSP\SpbctWP\Firewall;

use CleantalkSP\SpbctWP\Helpers\Helper;
use CleantalkSP\Security\Firewall\Result;

class TC extends FirewallModule
{
    public $module_name = 'TC';

    // Table names
    public $data_table = '';
    public $log_table = '';

    // Additional params
    /**
     * @psalm-suppress PossiblyUnusedProperty
     */
    protected $api_key = false;

    /**
     * @psalm-suppress PossiblyUnusedProperty
     */
    protected $set_cookies = false;

    // Default params
    protected $store_interval = 300;
    protected $chance_to_clean = 100;
    protected $tc_limit = 1000;
    protected $block_period = 3600;

    protected $is_logged_in = false;

    protected $user_is_admin;

    /**
     * FireWall_module constructor.
     * Use this method to prepare any data for the module working.
     *
     * @param array $params
     */
    public function __construct($params = array())
    {
        $params['block_period'] = $params['block_period'] ?: $this->block_period;

        parent::__construct($params);

        $this->user_is_admin = $params['user_is_admin'] ?: false;
    }

    /**
     * Use this method to execute main logic of the module.
     * @return array
     */
    public function check()
    {
        global $spbc;

        $results = array();

        if ( $this->user_is_admin ) {
            // Do not check admins
            return $results;
        }

        if ( $spbc->settings['traffic_control__exclude_authorised_users'] && $this->is_logged_in ) {
            // Do not check logged-in users if the option is enabled
            return $results;
        }

        $this->clearTable();

        $time = time();

        foreach ( $this->ip_array as $_ip_origin => $current_ip ) {
            $rand   = rand(1, 100000);
            //convert to long to prevent db mystery
            $md5_ip = md5($current_ip);
            $result = $this->db->fetchAll(
                "SELECT SUM(entries) as total_count"
                . ' FROM `' . $this->log_table . '`'
                . " WHERE
                    md5_ip = '$md5_ip' AND
                    interval_start < '$time' AND
                    $rand;",
                OBJECT
            );
            if ( ! empty($result) && $result[0]->total_count >= $this->tc_limit ) {
                $results[] = new Result(
                    array(
                        'module' => 'TC',
                        'ip'     => $current_ip,
                        'status' => 'DENY_BY_DOS',
                    )
                );
            }
        }

        return $results;
    }

    /**
     * @param $result
     *
     * @return void
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function middleAction($result = null)
    {
        if ( ! $this->is_logged_in ) {
            $this->clearTable();
        }

        $this->updateLog();
    }

    public function updateLog()
    {
        $interval_time = Helper::getTimeIntervalStart($this->store_interval);

        foreach ( $this->ip_array as $_ip_origin => $current_ip ) {
            $id = md5($current_ip . $interval_time);
            //convert to long to prevent db mystery
            $md5_ip = md5($current_ip);
            $this->db->execute(
                "INSERT INTO " . $this->log_table . " SET
					id = '$id',
					log_type = 0,
					ip = '$current_ip',
					md5_ip = '$md5_ip',
					entries = 1,
					interval_start = $interval_time
				ON DUPLICATE KEY UPDATE
					ip = ip,
					md5_ip = md5_ip,
					entries = entries + 1,
					interval_start = $interval_time;"
            );
        }
    }

    private function clearTable()
    {
        if ( rand(0, 1000) < $this->chance_to_clean ) {
            $interval_start = Helper::getTimeIntervalStart($this->block_period + $this->store_interval);
            $this->db->execute(
                'DELETE
				FROM ' . $this->log_table . '
				WHERE interval_start < ' . $interval_start . '
				AND log_type  = 0
				LIMIT 100000;'
            );
        }
    }
}
