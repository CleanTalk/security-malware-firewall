<?php

namespace CleantalkSP\SpbctWP\Firewall;

use CleantalkSP\Security\Firewall\Result;

class WafBlocker extends FirewallModule
{
    public $module_name = 'WafBlocker';

    protected $is_logged_in = false;
    protected $waf_blocker_limit = 2; // Count of allowed wrong attempts
    protected $block_period = 86400; // Default block period for $bf_limit wrong attempts
    protected $chance_to_clean = 30; // Chance to clean log table from old entries. In percents.

    /**
     * @var bool
     */
    private $is_checked;

    public function __construct($params = [])
    {
        parent::__construct($params);
        $this->die_page__file = __DIR__ . DIRECTORY_SEPARATOR . 'die_page_fw.html';
    }

    public function check()
    {
        $results = array();

        if ( ! $this->is_logged_in ) {
            foreach ( $this->ip_array as $current_ip ) {
                $rand   = rand(1, 100000);
                $md5_ip = md5($current_ip);
                $query  = 'SELECT SUM(entries) as total_count
				         FROM ' . SPBC_TBL_TC_LOG . '
				         WHERE
				            md5_ip = \'' . $md5_ip . '\' AND
				            log_type = 2 AND
				            ' . $rand . ';';
                $result = $this->db->fetch($query, OBJECT);

                if ( isset($result->total_count) && $result->total_count > $this->waf_blocker_limit ) {
                    $results[] = new Result(
                        array(
                            'module' => $this->module_name,
                            'ip'     => end($this->ip_array),
                            'status' => 'DENY_BY_WAF_BLOCKER',
                        )
                    );
                }
            }
        }

        return $results;
    }

    public function updateLogs()
    {
        if ( $this->is_checked ) {
            return;
        }

        if ( ! FirewallState::$is_need_to_increment_entire ) {
            return;
        }

        foreach ( $this->ip_array as $current_ip ) {
            $id = md5($current_ip . 'WafBlocker');
            $md5_ip = md5($current_ip);
            $update_log_query = "INSERT INTO " . SPBC_TBL_TC_LOG . " SET
				id = %s,
				log_type = 2,
				ip = %s,
				md5_ip = %s,
				entries = 1,
				interval_start = %s
			ON DUPLICATE KEY UPDATE
				ip = ip,
				md5_ip = md5_ip,
				entries = entries + 1,
				interval_start = interval_start;";
            $this->db->prepare(
                $update_log_query,
                [
                    $id,
                    $current_ip,
                    $md5_ip,
                    time()
                ]
            )->execute();
        }

        $this->is_checked = true;
        FirewallState::setIsNeedToIncrementEntire(false);
    }

    public function clearTable()
    {
        if ( rand(0, 100) < $this->chance_to_clean ) {
            $query = "DELETE
				FROM " . SPBC_TBL_TC_LOG . "
				WHERE
					interval_start < " . (time() - $this->block_period) . " AND
					log_type  = 2
				LIMIT 100000;";
            $this->db->execute($query);
        }
    }
}
