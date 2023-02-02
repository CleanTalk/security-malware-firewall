<?php

namespace CleantalkSP\Updater;

use CleantalkSP\SpbctWP\Transaction;
use CleantalkSP\SpbctWP\DB;

class Updater
{
    /**
     * Do updates in SQL database after plugin update.
     *
     * @param $current_version
     * @param $new_version
     *
     * @throws \Exception
     */
    public static function runUpdateScripts($current_version, $new_version)
    {
        $tables_analyzer = new \CleantalkSP\SpbctWP\DB\TablesAnalyzer();

        foreach ($tables_analyzer->getNotExistingTables() as $not_existing_table) {
            $db_tables_creator = new \CleantalkSP\SpbctWP\DB\TablesCreator();
            $db_tables_creator->createTable($not_existing_table);
        }

        foreach ($tables_analyzer->getExistingTables() as $existing_table) {
            $column_analyzer = new DB\ColumnsAnalyzer($existing_table);

            if ($column_analyzer->changes_required) {
                $column_creator = new DB\ColumnCreator($existing_table);
                $column_creator->assembleQuery(
                    $column_analyzer->columns_to_create,
                    $column_analyzer->columns_to_change,
                    $column_analyzer->columns_to_delete
                );
                $column_creator->execute();
            }
        }

        $current_version = self::versionStandardization($current_version);
        $new_version = self::versionStandardization($new_version);
        $current_version_str = implode('.', $current_version);
        $new_version_str = implode('.', $new_version);

        for ($ver_major = $current_version[0]; $ver_major <= $new_version[0]; $ver_major++) {
            for ($ver_minor = 0; $ver_minor <= 200; $ver_minor++) {
                for ($ver_fix = 0; $ver_fix <= 10; $ver_fix++) {
                    if (version_compare("{$ver_major}.{$ver_minor}.{$ver_fix}", $current_version_str, '<=')) {
                        continue;
                    }

                    if (method_exists(
                        "CleantalkSP\Updater\UpdaterScripts",
                        "updateTo_{$ver_major}_{$ver_minor}_{$ver_fix}"
                    )) {
                        $result = call_user_func(
                            "CleantalkSP\Updater\UpdaterScripts::updateTo_{$ver_major}_{$ver_minor}_{$ver_fix}"
                        );

                        if ( ! empty($result['error'])) {
                            break;
                        }
                    }

                    if (version_compare("{$ver_major}.{$ver_minor}.{$ver_fix}", $new_version_str, '>=')) {
                        break(2);
                    }
                }
            }
        }

        if ( ! DB::getInstance()->execute('SELECT COUNT(*) FROM ' . SPBC_TBL_FIREWALL_DATA . ';')) {
            spbc_security_firewall_update__init();
        }
    }

    /**
     * Split version to major, minor, fix parts.
     * Set it to 0 if not found
     *
     * @param string $version
     *
     * @return array
     */
    public static function versionStandardization($version)
    {
        $version = preg_replace('/(-dev|-fix)/', '', $version);
        $ver = explode('.', $version);

        // Version
        $ver[0] = ! empty($ver[0]) ? (int)$ver[0] : 0; // Major
        $ver[1] = ! empty($ver[1]) ? (int)$ver[1] : 0; // Minor
        $ver[2] = ! empty($ver[2]) ? (int)$ver[2] : 0; // Fix

        return $ver;
    }
}
