<?php
/*
 * The abstract class for SecFW, WAF FireWall modules.
 * Compatible with WP only.
 *
 * @version       1.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @since 2.49
 */

namespace CleantalkSP\SpbctWp\FireWall;


abstract class FireWall_module_fw extends \CleantalkSP\Security\FireWall\FireWall_module {

	protected $spbc;

	public function __construct() {

		global $spbc;
		$this->spbc = $spbc;
		$this->service_id = $this->spbc->service_id;

	}

}