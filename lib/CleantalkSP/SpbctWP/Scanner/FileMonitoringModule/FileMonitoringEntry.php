<?php

namespace CleantalkSP\SpbctWP\Scanner\FileMonitoringModule;

use CleantalkSP\SpbctWP\Scanner\ScanningLog\ScanningLogFacade;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\ScanningStagesStorage;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\FileMonitoring;

class FileMonitoringEntry
{
    private static $base_important_files = array(
        '/.htaccess',
        '/wp-config.php',
        '/wp-admin/admin.php',
        '/wp-includes/functions.php',
    );

    /**
     * @var string
     */
    private $site_root;

    /**
     * @var array
     */
    private $theme_functions_paths;

    /**
     * @var string[]
     */
    private $important_files;

    /**
     * @var array
     */
    private $stage_data_for_logging;

    public function __construct()
    {
        $this->site_root = rtrim(ABSPATH, '/');
        $this->theme_functions_paths = FileMonitoringHelper::getThemeFunctionsPaths();
        $this->important_files = $this->collectAllImportantFiles();
    }

    public function handle()
    {
        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->loadCollection();
        $stage_data_obj = $scanning_stages_storage->getStage(FileMonitoring::class);
        $stage_data_obj->set('count_files', count($this->important_files));
        $scanning_stages_storage->saveToDb();

        // Adding to log
        ScanningLogFacade::writeToLog(
            '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
        );

        $this->stage_data_for_logging = array(
            'title' => $stage_data_obj::getTitle(),
            'description' => $stage_data_obj->getDescription()
        );

        // Writing to the database of information about files
        // (_important_files, _important_file_snapshots)
        foreach ($this->important_files as $file) {
            $system_file_path = $this->site_root . $file;

            $file_data = new File($system_file_path);

            // Saved new file or added id to current File ($file_data)
            FileMonitoringRepository::saveFileIfNew($file_data);

            // Save snapshot
            FileMonitoringRepository::saveNewSnapshot($file_data);
        }

        return $this;
    }

    /**
     * @psalm-suppress PossiblyUnusedMethod
     * @return array
     */
    public function getResults()
    {
        return array(
            'stage_data_for_logging' => $this->stage_data_for_logging,
            'end' => 1,
        );
    }

    public function collectAllImportantFiles()
    {
        $important_files = array_merge(self::$base_important_files, $this->theme_functions_paths);
        $important_files_from_db = FileMonitoringRepository::getFilePathsFromDb();

        return array_merge($important_files, array_diff($important_files_from_db, $important_files));
    }
}
