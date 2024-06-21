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
    /**
     * How long to keep the record in TC log before it will be randomly cleaned.
     * @var int
     */
    protected $store_interval = 300;
    /**
     * Chance to clean tc log on a hit.
     * @var int
     */
    protected $chance_to_clean = 100;
    /**
     * How many hits should be logged to get a TC block
     * @var int
     */
    protected $tc_limit = 1000;
    /**
     * For how long the visitor will be blocked
     * @var int
     */
    protected $block_period = 3600;

    /**
     * Is user is logged in
     * @var bool
     */
    protected $is_logged_in = false;

    /**
     * Is request is skipped by role rules
     * @var bool
     */
    protected $tc_skipped_by_role = false;

    /**
     * @var array
     */
    private $entries_to_write;

    /**
     * @var array
     */
    private $seek_end_on;

    /**
     * @var array
     */
    private $block_end_on;

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

        $this->checkIsAdmin();
    }

    /**
     * Use this method to execute main logic of the module.
     * @return array
     */
    public function check()
    {
        global $spbc;

        $results = array();

        if ( FirewallState::$is_admin ) {
            // Role skipping rule. Do not check admins
            $this->tc_skipped_by_role = true;

            return $results;
        }

        if ( $spbc->settings['traffic_control__exclude_authorised_users'] && $this->is_logged_in ) {
            // Role skipping rule. Do not check logged-in users if the option is enabled
            $this->tc_skipped_by_role = true;

            return $results;
        }

        // Clear TC log if previous role rules have not been applied.
        $this->clearTable();

        foreach ( $this->ip_array as $current_ip ) {
            $check_result = $this->checkIp($current_ip);
            if ( $check_result ) {
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
     * Checking IP via TC table
     *
     * @param $ip
     *
     * @return bool true - IP will be blocked | false - IP will be passed
     */
    private function checkIp($ip)
    {
        $rand   = rand(1, 100000);
        $md5_ip = md5($ip);
        $sql    = "SELECT entries, block_end_on, seek_end_on FROM " . $this->log_table
            . " WHERE md5_ip = '$md5_ip' AND log_type = 0 AND $rand;";
        $result = $this->db->fetch($sql);

        // Start hits dispatching
        if ( ! $result ) {
            $this->startFollowing($ip);

            return false;
        }

        // Check TC block status
        if ( $result->block_end_on ) {
            if ( time() > $result->block_end_on ) {
                $this->removeBlock($ip);

                return false;
            }

            $this->prolongBlock($ip, $result->entries);

            return true;
        }

        // Check TC seek status
        if ( $result->seek_end_on ) {
            if ( time() > $result->seek_end_on ) {
                $this->startFollowing($ip);

                return false;
            }

            // Blocking - TC limit exceeded
            if ( $result->entries >= $this->tc_limit ) {
                $this->prolongBlock($ip, $result->entries);

                return true;
            }

            $this->processFollowing($ip, $result->entries, $result->seek_end_on);

            return false;
        }

        return false;
    }

    /**
     * TC module middle action. Update log if visitor not skipped by role rules.
     *
     * @param $result
     *
     * @return void
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function middleAction($result = null)
    {
        //Update log if request is not skipped by role rules
        if ( ! $this->tc_skipped_by_role ) {
            $this->updateLog();
        }
    }

    /**
     * Write a new record to TC log.
     * @return void
     */
    public function updateLog()
    {
        if ( ! FirewallState::$is_need_to_increment_entire ) {
            return;
        }

        foreach ( $this->ip_array as $current_ip ) {
            $entries      = isset($this->entries_to_write[$current_ip]) ? $this->entries_to_write[$current_ip] : 0;
            $seek_end_on  = isset($this->seek_end_on[$current_ip]) ? $this->seek_end_on[$current_ip] : 'NULL';
            $block_end_on = isset($this->block_end_on[$current_ip]) ? $this->block_end_on[$current_ip] : 'NULL';

            $id     = md5($current_ip . 'tc');
            $md5_ip = md5($current_ip);
            $this->db->execute(
                "INSERT INTO " . $this->log_table . " SET
					id = '$id',
					log_type = 0,
					ip = '$current_ip',
					md5_ip = '$md5_ip',
					entries = $entries,
					seek_end_on = $seek_end_on,
					block_end_on = $block_end_on
				ON DUPLICATE KEY UPDATE
					entries = $entries,
					seek_end_on = $seek_end_on,
					block_end_on = $block_end_on;"
            );
        }
    }

    /**
     * Clear TC log table. Chance to clean is 1 of 1000/$this->chance_to_clean. Limit is 100000 records.
     * @return void
     */
    private function clearTable()
    {
        $current_time = time();
        if ( rand(0, 1000) < $this->chance_to_clean ) {
            $clear_sql = "DELETE FROM $this->log_table 
                WHERE  ( 
                    ( seek_end_on IS NOT NULL AND $current_time > seek_end_on )
                    OR
                    ( block_end_on IS NOT NULL AND $current_time > block_end_on )
                )
                AND log_type = 0
				LIMIT 100000;";
            $this->db->execute($clear_sql);
        }
    }

    private function startFollowing($ip)
    {
        $this->entries_to_write[$ip] = 1;
        $this->seek_end_on[$ip]      = time() + $this->store_interval;
        $this->block_end_on[$ip]     = 'NULL';
    }

    private function processFollowing($ip, $entries, $seek_end_on)
    {
        $this->entries_to_write[$ip] = $entries + 1;
        $this->seek_end_on[$ip]      = $seek_end_on;
        $this->block_end_on[$ip]     = 'NULL';
    }

    private function removeBlock($ip)
    {
        $this->startFollowing($ip);
    }

    private function prolongBlock($ip, $entries)
    {
        $this->entries_to_write[$ip] = $entries + 1;
        $this->seek_end_on[$ip]      = 'NULL';
        $this->block_end_on[$ip]     = time() + $this->block_period;
    }

    private function checkIsAdmin()
    {
        if (spbc_user_is_admin()) {
            FirewallState::setIsAdmin(true);
        }
    }
}
