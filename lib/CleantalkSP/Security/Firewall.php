<?php

namespace CleantalkSP\Security;

use CleantalkSP\Common\Helper;
use CleantalkSP\Security\Firewall\FirewallModule;
use CleantalkSP\SpbctWP\Variables\Cookie;
use CleantalkSP\Variables\Get;
use CleantalkSP\Security\Firewall\Result;
use CleantalkSP\SpbctWP\Helpers\IP;

/**
 * CleanTalk SpamFireWall base class.
 * Compatible with any CMS.
 *
 * @depends       \CleantalkSP\SpbctWP\Helper class
 * @depends       \CleantalkSP\SpbctWP\API class
 * @depends       \CleantalkSP\SpbctWP\DB class
 *
 * @version       4.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/php-antispam
 */
class Firewall
{
    public $ip_array = array();

    private $test_block;

    // Database
    protected $db;

    //Debug
    /**
     * @var bool
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $debug;

    private $statuses_priority = array(
        'PASS',
        'DENY',
        'DENY_BY_SEC_FW',
        'DENY_BY_SPAM_FW',
        'DENY_BY_NETWORK',
        'DENY_BY_BFP',
        'DENY_BY_DOS',
        'DENY_BY_WAF_BLOCKER',
        'DENY_BY_WAF_SQL',
        'DENY_BY_WAF_XSS',
        'DENY_BY_WAF_EXPLOIT',
        'DENY_BY_WAF_FILE',
        'PASS_BY_WHITELIST',
        'PASS_BY_TRUSTED_NETWORK', // Highest
    );

    private $fw_modules = array();

    /**
     * Creates Database driver instance.
     *
     * @param mixed $db database handler
     */
    public function __construct($db = null)
    {
        $this->debug    = (bool)Get::get('debug');
        $this->ip_array = $this->ipGet('real');

        if ( isset($db) ) {
            $this->db = $db;
        }
    }

    /**
     * Getting arrays of IP (REMOTE_ADDR, X-Forwarded-For, X-Real-Ip, Cf_Connecting_Ip)
     *
     * @param string $ip_type type of IP you want to receive
     *
     * @return array
     */
    public function ipGet($ip_type)
    {
        $result = IP::get($ip_type);

        return ! empty($result) ? array('real' => $result) : array();
    }

    /**
     * Loads the FireWall module to the array.
     * For inner usage only.
     * Not returns anything, the result is private storage of the modules.
     *
     * @param FirewallModule $module
     */
    public function loadFwModule(FirewallModule $module)
    {
        if ( ! in_array($module, $this->fw_modules, true) ) {
            $module->setDb($this->db);
            $module->ipAppendAdditional($this->ip_array);
            $this->fw_modules[$module->module_name] = $module;
            $module->setIpArray($this->ip_array);
        }
    }

    /**
     * Do main logic of the module.
     *
     * @return void   returns die page or set cookies
     */
    public function run()
    {
        global $spbc;

        $results = array();

        // Check requests by all enabled modules
        foreach ( $this->fw_modules as $module ) {
            // Perform module check
            $module_results = $module->check();

            // Check if it was test-page checking
            foreach ( $module_results as $result ) {
                if ($module->test_ip && $result->ip === $module->test_ip) {
                    $this->test_block = $result;
                }
                if (Get::get('spbct_test_waf') && $result->module === 'WAF') {
                    $this->test_block = $result;
                }
            }

            // Reduce module results to one
            $results[$module->module_name] = $this->reduceFirewallResultsByPriority($module_results);

            // Perform middle action if module provide it
            if ( method_exists($module, 'middleAction') ) {
                $module->middleAction($results[$module->module_name]);
            }

            // Don't use other modules if the IP is whitelisted
            if ( $this->isWhitelisted($results) && ! empty($this->test_block) ) {
                break;
            }
        }

        // Reduce all modules results to one
        $result = $this->reduceFirewallResultsByPriority($results);

        // Write log
        if ( (int) $spbc->settings['secfw__enabled'] ) {
            $this->updateLog($result);
        }

        // Do finish action - die or set cookies
        if ( isset($result->module) && isset($this->fw_modules[$result->module]) ) {
            // Blocked
            if ( strpos($result->status, 'DENY') !== false ) {
                $this->fw_modules[$result->module]->actionsForDenied($result);
                $this->fw_modules[$result->module]->_die($result);
            // Allowed
            } elseif ( (int) $spbc->settings['secfw__enabled'] ) {
                $this->fw_modules[$result->module]->actionsForPassed($result);
                //if this is a test, run block anyway
                if (!empty($this->test_block) && !empty($this->test_block->module) ) {
                    $this->fw_modules[ $this->test_block->module ]->_die($this->test_block);
                }
            }
        }
    }

    /**
     * Sets priorities for firewall results.
     * It generates one main result from multi-level results array.
     *
     * @param Result[] $firewall_results
     *
     * @return Result Single element array of result
     */
    private function reduceFirewallResultsByPriority(array $firewall_results)
    {
        $priority_final         = 0;
        $firewall_result__final = new Result(
            array(
                'module' => 'FW',
                'ip'     => end($this->ip_array),
                'status' => 'PASS',
            )
        );

        // 1) Select only personal listed results
        $priority_firewall_results = $this->filterResultsByLists($firewall_results);

        foreach ( $priority_firewall_results as $firewall_result__current ) {
            // 2) If ip is passed as SKIPPED_NETWORK (status 99) set this result as final and proceed next db result
            if ( $firewall_result__current->status === 'PASS_AS_SKIPPED_NETWORK' ) {
                //set status to passed to let other modules check this ip
                $firewall_result__current->status = 'PASSED';
                $firewall_result__final = $firewall_result__current;
                continue;
            }

            // 3) Calculate priority by masks and statuses
            $priority_current = $this->calculatePriorityForFirewallResult($firewall_result__current);

            if ( $priority_current >= $priority_final ) {
                $priority_final         = $priority_current;
                $firewall_result__final = $firewall_result__current;
            }
        }

        return $firewall_result__final;
    }

    /**
     * Selected only personal listed results its are provided in the results array.
     *
     * @param Result[] $firewall_results
     *
     * @return Result[]
     */
    private function filterResultsByLists(array $firewall_results)
    {
        $priority_results = [];
        foreach ( $firewall_results as $firewall_result__current ) {
            if ( (int) $firewall_result__current->is_personal === 1 ) {
                $priority_results[] = $firewall_result__current;
            }
        }
        return count($priority_results) ? $priority_results : $firewall_results;
    }

    /**
     * Calculates the priority of the passed Firewall Result
     *
     * @param Result $firewall_result
     *
     * @return int
     */
    private function calculatePriorityForFirewallResult(Result $firewall_result)
    {
        $point_for_status           = array_search($firewall_result->status, $this->statuses_priority, true);
        $points_for_trusted_network = $firewall_result->status === 'PASS_BY_TRUSTED_NETWORK' ? 100 : 0;
        $points_for_mask = $firewall_result->mask;

        return
            $point_for_status +
            $points_for_trusted_network +
            $points_for_mask;
    }

    /**
     * Check the result if it whitelisted or trusted network
     *
     * @param Result[] $results
     *
     * @return bool
     */
    private function isWhitelisted($results)
    {
        global $spbc;

        foreach ( $results as $fw_result ) {
            if (
                strpos($fw_result->status, 'PASS_BY_TRUSTED_NETWORK') !== false ||
                strpos($fw_result->status, 'PASS_BY_WHITELIST') !== false
            ) {
                if ( ! headers_sent() ) {
                    $cookie_val = md5($fw_result->ip . $spbc->spbc_key);
                    Cookie::set('spbc_secfw_ip_wl', $cookie_val, time() + 86400 * 25, '/', '', false, true);
                }

                return true;
            }
        }

        return false;
    }

    /**
     * Use this method to handle logs updating by the module.
     *
     * @param Result $fw_result
     *
     * @return void
     */
    public function updateLog(Result $fw_result)
    {
    }
}
