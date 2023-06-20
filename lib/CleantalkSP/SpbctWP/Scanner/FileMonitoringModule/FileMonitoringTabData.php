<?php

namespace CleantalkSP\SpbctWP\Scanner\FileMonitoringModule;

class FileMonitoringTabData
{
    public static function getDataToAccordion()
    {
        $data_to_accordion = array();

        $files = FileMonitoringRepository::getFilesFromDb();

        if ($files) {
            foreach ($files as $file) {
                $data_to_accordion[] = (object) array(
                    'path' => $file['path'],
                    'id' => $file['id'],
                );
            }
        }

        return $data_to_accordion;
    }

    public static function prepareDataToAccordion($table)
    {
        if ($table->items_count) {
            foreach ($table->rows as $row) {
                $table->items[] = array(
                    'path'        => '<span class="title">' . $row->path . '</span>',
                    'uid'         => $row->id,
                    'actions'     => $row->actions,
                );
            }
        }

        return $table;
    }

    public static function showCurrentSnapshot()
    {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');

        $snapshot_id = isset($_POST['snapshot_id']) ? (int)$_POST['snapshot_id'] : null;

        if (is_null($snapshot_id)) {
            wp_send_json_error(esc_html__('Error: Snapshot not founded.', 'security-malware-firewall'));
        }

        $snapshot = FileMonitoringRepository::getSnapshotById($snapshot_id);

        if (is_null($snapshot)) {
            wp_send_json_error(esc_html__('Error: Snapshot not founded.', 'security-malware-firewall'));
        }

        $snapshot['content'] = htmlspecialchars($snapshot['content']);
        wp_send_json_success($snapshot);
    }

    public static function showSnapshots()
    {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');

        $file_id = isset($_POST['file_id']) ? (int)$_POST['file_id'] : null;

        if (is_null($file_id)) {
            wp_send_json_error(esc_html__('Error: File not founded.', 'security-malware-firewall'));
        }

        $snapshots = FileMonitoringRepository::getSnapshotsByFileId($file_id);

        if (is_null($snapshots)) {
            wp_send_json_error(esc_html__('Error: Snapshots not founded.', 'security-malware-firewall'));
        }

        wp_send_json_success($snapshots);
    }

    public static function getModalTemplate()
    {
        ?>
        <div data-remodal-id="spbc-file-monitoring-modal">
            <button data-remodal-action="close" class="remodal-close"></button>
            <h3 id="spbc-fm-snapshot-file-name">...</h3>
            <div class="spbc-fm-container">
                <div class="spbc-fm-snapshot-list" id="spbc-fm-snapshot-list"></div>
                <div class="spbc-fm-snapshot-view" id="spbc-fm-snapshot-view">
                    <img id="spbc-file-monitoring-modal-preloader" style="display: none" src="<?php echo SPBC_PATH; ?>/images/preloader2.gif">
                </div>
            </div>
        </div>
        <?php
    }
}
