<?php

namespace CleantalkSP\SpbctWP\Scanner\ScannerInteractivity;

class ScannerInteractivityData
{
    /**
     * @var string
     */
    public static $scanner_stage;

    /**
     * @var RefreshDataDTO
     */
    public static $refresh_data;

    public static function prepare($stage, array $refresh_data)
    {
        self::$scanner_stage = $stage;

        try {
            self::$refresh_data = new RefreshDataDTO($refresh_data);
        } catch (\Exception $e) {
            self::$refresh_data = null;
        }

        return array(
            'scanner_stage' => self::$scanner_stage,
            'refresh_data' => self::$refresh_data instanceof RefreshDataDTO
                ? self::getDataArray(self::$refresh_data)
                : array(),
            'update_text' => __('Updated!', 'security_malware_firewall')
        );
    }

    public static function getDataArray(RefreshDataDTO $refresh_data)
    {
        return array(
            'do_refresh' => $refresh_data->do_refresh,
            'control_tab' => $refresh_data->control_tab,
        );
    }
}
