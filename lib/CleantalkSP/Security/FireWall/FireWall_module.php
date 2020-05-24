<?php
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

namespace CleantalkSP\Security\FireWall;


abstract class FireWall_module {

	protected $db;

	protected $service_id;

	protected $result_code = '';

	protected $ip_array = array();

	protected $passed_ip;

	protected $blocked_ip;

	/**
	 * FireWall_module constructor.
	 * Use this method to prepare any data for the module working.
	 */
	abstract public function __construct();

	/**
	 * Use this method to execute main logic of the module.
	 *
	 * @return array  Array of the check results
	 */
	abstract public function check();

	/**
	 * @return mixed
	 */
	public function getServiceId() {
		return $this->service_id;
	}

	/**
	 * @return string
	 */
	public function getResultCode() {
		return $this->result_code;
	}

	/**
	 * @param array $ip_array
	 */
	public function setIpArray( array $ip_array ) {
		$this->ip_array = $ip_array;
	}

	/**
	 * @return mixed
	 */
	public function getPassedIp() {
		return $this->passed_ip;
	}

	/**
	 * @return mixed
	 */
	public function getBlockedIp() {
		return $this->blocked_ip;
	}

}