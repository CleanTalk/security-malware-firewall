<?php

namespace CleantalkSP\SpbctWP\Firewall;

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

use CleantalkSP\SpbctWP\Escape;
use CleantalkSP\Variables\Get;
use CleantalkSP\Variables\Server;
use CleantalkSP\Security\Firewall\Result;

class FirewallModule extends \CleantalkSP\Security\Firewall\FirewallModule
{
    public $result;
    /**
     * FireWall_module constructor.
     * Use this method to prepare any data for the module working.
     *
     * @param array $params
     */
    public function __construct($params = array())
    {
        $this->die_page__file = file_exists(
            __DIR__ . DIRECTORY_SEPARATOR . 'die_page_' . strtolower($this->module_name) . '.html'
        )
            ? __DIR__ . DIRECTORY_SEPARATOR . 'die_page_' . strtolower($this->module_name) . '.html'
            : null;

        parent::__construct($params);
    }

    /**
     * Shows DIE page.
     * Stops script executing.
     *
     * @param Result $result
     */
    public function _die(Result $result) // phpcs:ignore PSR2.Methods.MethodDeclaration.Underscore
    {
        global $spbc;

        // Common actions for all modules
        parent::_die($result);

        // Adding block reason
        switch ( $result->status ) {
            case 'DENY':
                $reason = __('Blacklisted', 'security-malware-firewall');
                break;
            case 'DENY_BY_NETWORK':
                $reason = __('Hazardous network', 'security-malware-firewall');
                break;
            case 'DENY_BY_DOS':
                $reason = __('Blocked by Traffic control', 'security-malware-firewall');
                break;
            case 'DENY_BY_WAF_XSS':
                $reason = __('Blocked by Web Application Firewall: XSS attack detected.', 'security-malware-firewall');
                break;
            case 'DENY_BY_WAF_SQL':
                $reason = __(
                    'Blocked by Web Application Firewall: SQL-injection detected.',
                    'security-malware-firewall'
                );
                break;
            case 'DENY_BY_WAF_EXPLOIT':
                $reason = __('Blocked by Web Application Firewall: Exploit detected.', 'security-malware-firewall');
                break;
            case 'DENY_BY_WAF_FILE':
                $reason = __(
                    'Blocked by Web Application Firewall: Malicious files upload.',
                    'security-malware-firewall'
                );
                break;
            case 'DENY_BY_BFP':
                $reason = __('Blocked by BruteForce Protection: Too many invalid logins.', 'security-malware-firewall');
                break;
            default:
                $reason = __('Blacklisted', 'security-malware-firewall');
                break;
        }

        if ( $this->die_page__file ) {
            $die_page_template = file_get_contents($this->die_page__file);

            $allowed_html = array(
                'h1' => array(),
                'h2' => array(),
                'h3' => array(),
                'h4' => array(),
                'h5' => array(),
                'p' => array(),
                'br' => array(),
                'a' => array(
                    'href'  => true,
                )
            );

            // Translation
            $replaces = array(
                '{TITLE}'                  => __('Blocked: ' . $spbc->data["wl_brandname"], 'security-malware-firewall'),
                '{CUSTOM_MESSAGE}'         => isset($this->state->settings['fw__custom_message']) ? Escape::escKses(
                    $this->state->settings['fw__custom_message'],
                    $allowed_html
                ) : '',
                '{TEST_TITLE}'             => Get::get('spbct_test')
                    ? __('This is the testing page for Security FireWall', 'security-malware-firewall')
                    : '',
                '{REASON}'                 => $reason,
                '{GENERATED_TIMESTAMP}'    => time(),
                '{FALSE_POSITIVE_WARNING}' => __(
                    'Maybe you\'ve been blocked by a mistake. Please refresh the page (press CTRL + F5) or try again later.',
                    'security-malware-firewall'
                ),

                '{REMOTE_ADDRESS}' => $result->ip,
                '{SERVICE_ID}'     => isset($this->state->data['service_id']) ? $this->state->data['service_id'] : '',
                '{HOST}'           => Server::get('HTTP_HOST'),
                '{GENERATED}'      => '<h2 class="second">The page was generated at '
                                      . date("D, d M Y H:i:s")
                                      . '</h2>',
                '{BRANDNAME}'      => $spbc->data["wl_brandname"],
            );

            foreach ( $replaces as $place_holder => $replace ) {
                $die_page_template = str_replace($place_holder, $replace, $die_page_template);
            }

            http_response_code(403);
            die($die_page_template);
        }

        http_response_code(403);
        die("IP BLACKLISTED. Blocked by Security Firewall " . $result->ip);
    }
}
