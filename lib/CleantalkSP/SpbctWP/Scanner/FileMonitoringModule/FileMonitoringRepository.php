<?php

namespace CleantalkSP\SpbctWP\Scanner\FileMonitoringModule;

class FileMonitoringRepository
{
    public static function saveFileIfNew(File $file)
    {
        global $wpdb;

        $exists_file = self::getFileByPathHash($file->path_hash);

        if (is_null($exists_file)) {
            $wpdb->insert(
                SPBC_TBL_IMPORTANT_FILES,
                array(
                    'path' => $file->path,
                    'path_hash' => $file->path_hash,
                    'started_at' => $file->started_at
                ),
                array(
                    '%s', '%s', '%d'
                )
            );

            $file->id = $wpdb->insert_id;
        } else {
            $file->id = $exists_file->id;
        }
    }

    public static function saveNewSnapshot(File $file)
    {
        global $wpdb;

        $last_snapshot_hash = self::getLastSnapshot($file);

        if (is_null($last_snapshot_hash) || $last_snapshot_hash->content_hash !== $file->content_hash) {
            $file_id = $file->id;
            $content = file_exists($file->path) ? file_get_contents($file->path) : null;
            $content_hash = $file->content_hash;
            $created_at = time();

            $wpdb->insert(
                SPBC_TBL_IMPORTANT_FILES_SNAPSHOTS,
                array(
                    'file_id' => $file_id,
                    'content' => $content,
                    'content_hash' => $content_hash,
                    'created_at' => $created_at
                ),
                array(
                    '%d', '%s', '%s', '%d'
                )
            );
        }
    }

    public static function getFileByPathHash($path_hash)
    {
        global $wpdb;

        return $wpdb->get_row(
            "SELECT * FROM "
            . SPBC_TBL_IMPORTANT_FILES
            . " WHERE path_hash = '" . $path_hash . "'"
        );
    }

    /**
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function getSnapshotByHash(File $file)
    {
        global $wpdb;

        return $wpdb->get_row(
            "SELECT * FROM "
            . SPBC_TBL_IMPORTANT_FILES_SNAPSHOTS
            . " WHERE content_hash = '" . $file->content_hash . "' AND file_id = " . $file->id
        );
    }

    public static function getFilePathsFromDb()
    {
        global $wpdb;

        $prepared_file_array = array();
        $files = $wpdb->get_results(
            "SELECT path FROM " . SPBC_TBL_IMPORTANT_FILES,
            ARRAY_A
        );

        foreach ($files as $file) {
            $prepared_file_array[] = str_replace(rtrim(ABSPATH, '/'), '', $file['path']);
        }

        return $prepared_file_array;
    }

    public static function getFilesFromDb()
    {
        global $wpdb;

        $files = $wpdb->get_results(
            "SELECT * FROM " . SPBC_TBL_IMPORTANT_FILES,
            ARRAY_A
        );

        foreach ($files as &$file) {
            $file['path'] = str_replace(rtrim(ABSPATH, '/'), '', $file['path']);
        }

        return $files;
    }

    public static function getCountFilesInDb()
    {
        global $wpdb;

        return $wpdb->get_var("SELECT COUNT(*) FROM " . SPBC_TBL_IMPORTANT_FILES . ";");
    }

    private static function getLastSnapshot(File $file)
    {
        global $wpdb;

        return $wpdb->get_row(
            "SELECT content_hash FROM "
            . SPBC_TBL_IMPORTANT_FILES_SNAPSHOTS
            . " WHERE file_id = " . $file->id
            . " ORDER BY created_at DESC LIMIT 1"
        );
    }

    public static function getSnapshotsByFileId($file_id)
    {
        global $wpdb;

        $snapshots =  $wpdb->get_results(
            "SELECT id, created_at FROM "
            . SPBC_TBL_IMPORTANT_FILES_SNAPSHOTS
            . " WHERE file_id = " . $file_id
            . " ORDER BY created_at DESC",
            ARRAY_A
        );

        // Changing the date format
        if (is_array($snapshots)) {
            foreach ($snapshots as $key => $snapshot) {
                $snapshots[$key]['created_at'] = date('F j, Y, H:i:s', $snapshot['created_at']);
            }
        }

        return $snapshots;
    }

    public static function getSnapshotById($snapshot_id)
    {
        global $wpdb;

        return $wpdb->get_row(
            "SELECT * FROM "
            . SPBC_TBL_IMPORTANT_FILES_SNAPSHOTS
            . " WHERE id = " . $snapshot_id,
            ARRAY_A
        );
    }
}
