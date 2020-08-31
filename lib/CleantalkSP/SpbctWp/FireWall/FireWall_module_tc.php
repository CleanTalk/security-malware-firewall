<?php
/*
 * The abstract class for TC, BFP FireWall modules.
 * Compatible with WP only.
 *
 * @version       1.1
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @since 2.49
 */

namespace CleantalkSP\SpbctWp\FireWall;

abstract class FireWall_module_tc extends \CleantalkSP\Security\FireWall\FireWall_module {

	protected $chance_to_clean = 100;

	protected $tc_limit;

	protected $block_period = 3600;

	protected $was_logged_in = false;

	protected $spbc;

	public function __construct() {

		global $spbc;
		$this->spbc = $spbc;
		$this->service_id = $this->spbc->service_id;
		$this->was_logged_in = isset( $_COOKIE['spbc_is_logged_in'] ) && $_COOKIE['spbc_is_logged_in'] === md5( $this->spbc->data['salt'] . parse_url( get_option( 'siteurl' ), PHP_URL_HOST ) );
		$this->tc_limit = $this->spbc->settings['traffic_control_autoblock_amount'];
		$this->block_period = empty( $this->spbc->settings['traffic_control_autoblock_period'] ) ? 3600 : $this->spbc->settings['traffic_control_autoblock_period'];

	}

}