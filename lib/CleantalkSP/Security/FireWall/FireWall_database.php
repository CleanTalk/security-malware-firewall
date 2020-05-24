<?php
/**
 * CleanTalk Security FireWall database actions handler interface.
 * Compatible with any CMS.
 *
 * @version       1.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @since        2.49
 */

namespace CleantalkSP\Security\FireWall;


interface FireWall_database {

	public function fw_clear_table();

	public function fw_insert_data( $query );

	public function fw_logs_clear_table();

	public function fw_logs_insert_data( $log_item );

	public function fw_get_logs();

	public function get_last_error();

}