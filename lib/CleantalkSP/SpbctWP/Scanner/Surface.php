<?php

namespace CleantalkSP\SpbctWP\Scanner;

class Surface
{
    /**
     * Main path
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $path = '';

    public $path_lenght = 0;

    /**
     * Description Extensions to check
     * @var array
     */
    public $ext = array();

    /**
     * Exception for extensions
     * @var array
     */
    public $ext_except = array();

    /**
     * Exception for files paths
     * @var array
     */
    public $files_except = array();

    /**
     * Exception for directories
     * @var array
     */
    public $dirs_except = array();

    /**
     * Mandatory check for files paths
     * @var array
     */
    public $files_mandatory = array();

    /**
     * Mandatory check for directories
     * @var array
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $dirs_mandatory = array();

    public $output_files = array();
    public $dirs = array();

    public $output_files_count = 0;

    /**
     * @var int
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $dirs_count = 0;

    /**
     * @var int
     */
    private $output_files_offset = 0;
    /**
     * @var int
     */
    private $output_counter_files = 0;
    /**
     * @var int
     */
    private $output_files_maximum = 1000000;
    /**
     * @var array|null
     * @psalm-suppress UnusedProperty
     */
    private $output_file_details;

    /**
     * @var bool
     */
    public $stage_end = false;

    /**
     * @var string
     */
    private $last_dir_on_exit;

    /**
     * @var IteratorResult
     */
    public $last_iterator_result;
    /**
     * @var bool
     * @psalm-suppress UnusedProperty
     */
    private $do_count_only;

    /**
     * @var bool
     */
    public $has_errors = false;

    /**
     * @var string
     */
    public $data_option_name;

    /**
     * @var bool
     */
    private $running_due_stage = false;

    private static $completed_dirs_table_name = SPBC_SURFACE_COMPLETED_DIRS;

    public function __construct($path, $rootpath, $params = array('count' => true))
    {
        /**
         * Init class vars
         */
        $this->init($path, $rootpath, $params);
        if ($this->has_errors === true) {
            return;
        }

        /**
         * Only count files if flag provided
         */
        if ( $this->do_count_only ) {
            $this->countFilesMandatory($this->files_mandatory);
            $this->countFilesInDir($path);
            return;
        }

        // Getting files and dirs considering filters
        /**
         * Count mandatory files
         */
        $this->getFilesMandatory($this->files_mandatory);

        /**
         * Root iterator start - enter point
         */
        $this->last_iterator_result = $this->getFileStructure($path, $this->last_iterator_result, true);

        /**
         * Collapse completed dirs
         * @psalm-suppress InvalidPropertyFetch
         */
        $this->last_iterator_result->completed_dirs = static::collapseCompletedDirectories($this->last_iterator_result->completed_dirs);

        /**
         * Set if stage is ended (iterator reached and competed the root dir)
         * @psalm-suppress InvalidPropertyFetch
         */
        $this->stage_end = $this->last_iterator_result->is_stage_end;

        /**
         * Save option. Contains offset data and completed dirs data.
         */
        $save_result = $this->saveIteratorData($this->last_iterator_result);
        if (false === $save_result) {
            $this->has_errors = true;
            return;
        }

        /**
         * Process found files info.
         */
        $this->handleFilesInfo();

        //todo what this commented code for?
        // Directories
        // $this->dirs[]['path'] = $path;
        // $this->dirs_count = count($this->dirs);
        // $this->dir__details($this->dirs, $this->path_lenght);
    }

    /**
     * @param string $path
     * @param string $rootpath
     * @param array $params
     * @return void
     */
    private function init($path, $rootpath, $params)
    {
        // Ident the caller and set the option name to save the iterator data
        $this->running_due_stage = isset($params['running_due_stage'])
            ? $params['running_due_stage']
            : $this->running_due_stage;
        $this->data_option_name = $this->running_due_stage
            ? 'scanner__surface_last_iterator_data__stage'
            : 'scanner__surface_last_iterator_data__other';

        // Reset iteration data on first run
        if (empty($params['offset']) && empty($params['count'])) {
            $this->resetIteratorDataOption();
            $this->clearIteratorCompletedDirs(true);
        }

        // Get last iteration data
        $load_result = $this->loadIteratorData();
        if (!$load_result) {
            $this->has_errors = true;
            return;
        }
        $this->last_iterator_result = $load_result;

        // Get main directory
        $path = realpath($path);
        if ( ! is_dir($path) ) {
            die("Scan '$path' isn't directory");
        }
        if ( ! is_dir($rootpath) ) {
            die("Root '$rootpath' isn't directory");
        }
        $this->path_lenght = strlen($rootpath);

        // extract last dir name interrupted from saved offset data
        $this->last_dir_on_exit = $this->last_iterator_result->on_exit_dir_path;

        // extract last dir offset interrupted from saved offset data
        $this->output_files_offset = $this->last_iterator_result->on_exit_dir_offset;

        // Processing filters
        $this->ext          = ! empty($params['extensions']) ? $this->filterParams($params['extensions']) : array();
        $this->ext_except   = ! empty($params['extensions_exceptions']) ? $this->filterParams(
            $params['extensions_exceptions']
        ) : array();
        $this->files_except = ! empty($params['file_exceptions']) ? $this->filterParams(
            $params['file_exceptions']
        ) : array();
        $this->dirs_except  = ! empty($params['dir_exceptions']) ? $this->filterParams(
            $params['dir_exceptions']
        ) : array();

        // Mandatory files and dirs
        $this->files_mandatory = ! empty($params['files_mandatory']) ? $this->filterParams(
            $params['files_mandatory']
        ) : array();
        $this->dirs_mandatory  = ! empty($params['dirs_mandatory']) ? $this->filterParams(
            $params['dirs_mandatory']
        ) : array();

        // Initilazing output counters
        $this->output_files_maximum = isset($params['amount'])
            ? $this->output_files_offset + $params['amount']
            : 1000000;
        $this->output_file_details = ! empty($params['output_file_details'])
            ? $this->filterParams($params['output_file_details'])
            : array();

        $this->do_count_only = ! empty($params['count']);
    }

    /**
     * Loads last iterator data between stage calls.
     * @return false|IteratorResult
     */
    private function loadIteratorData()
    {
        global $spbc;
        // get from option depending on caller
        $last_iterator_result = isset($spbc->data[$this->data_option_name]) && $spbc->data[$this->data_option_name] instanceof IteratorResult
        ? $spbc->data[$this->data_option_name]
        : new IteratorResult();

        if ( !($last_iterator_result instanceof IteratorResult) ) {
            $last_iterator_result = new IteratorResult();
        }

        $load_saved_dirs_result = $this->loadIteratorCompletedDirs();

        if ( $load_saved_dirs_result === false ) {
            return false;
        }
        $last_iterator_result->completed_dirs = $load_saved_dirs_result;
        return $last_iterator_result;
    }

    /**
     * Save last iterator data between stage calls.
     * @param IteratorResult $iterator_result
     * @return bool
     */
    private function saveIteratorData($iterator_result)
    {
        global $spbc;

        $save_dirs_result = $this->saveIteratorCompletedDirs($iterator_result);

        if ( $save_dirs_result === false ) {
            return false;
        }

        // important - do not save completed dirs to the wp options table!
        $iterator_result->completed_dirs = [];

        // save option without dirs
        $spbc->data[$this->data_option_name] = $iterator_result;
        $spbc->save('data');

        return true;
    }

    /**
     * Separated method to save completed dirs to the database table.
     * @param IteratorResult $iterator_result
     * @return bool
     */
    private function saveIteratorCompletedDirs($iterator_result)
    {
        global $wpdb;

        $values = array();
        if ( empty($iterator_result->completed_dirs) ) {
            return $iterator_result->max_files_interrupt;
        }

        foreach ($iterator_result->completed_dirs as $dir_path) {
            $value = '(';
            $value .= $wpdb->prepare('%s', $dir_path);
            $value .= ', ';
            $value .= (int)$this->running_due_stage;
            $value .= ')';
            $values[] = $value;
        }

        $completed_dirs_string = implode(',', $values);

        $clearing_result = $this->clearIteratorCompletedDirs();
        if ($clearing_result === false) {
            return false;
        }

        $insert_query = 'INSERT INTO ' . self::$completed_dirs_table_name  . ' (dir_path, running_due_stage) VALUES ' . $completed_dirs_string ;
        $insert_result = $wpdb->query($insert_query);

        return (bool)$insert_result;
    }

    /**
     * Separated method to load completed dirs from the database table.
     * @return false|array
     */
    private function loadIteratorCompletedDirs()
    {
        global $wpdb;

        $select_query = 'SELECT dir_path FROM ' . static::$completed_dirs_table_name . ' WHERE running_due_stage = ' . (int)$this->running_due_stage;

        $select_result = $wpdb->get_results($select_query, ARRAY_A);
        if (!is_array($select_result)) {
            return false;
        }

        $select_result = array_map(function ($item) {
            return $item['dir_path'];
        }, $select_result);

        return $select_result;
    }

    /**
     * @return bool
     */
    private function clearIteratorCompletedDirs($reset_increment = false)
    {
        global $wpdb;

        // run query
        $delete_query = 'DELETE FROM ' . self::$completed_dirs_table_name . ' WHERE running_due_stage = ' . (int)$this->running_due_stage . ';';
        $delete_result = $wpdb->query($delete_query);
        if ($delete_result === false) {
            return false;
        }

        if ($reset_increment) {
            $count = $wpdb->get_var('SELECT COUNT(*) FROM ' . self::$completed_dirs_table_name);
            if ($count === '0') {
                $wpdb->query('ALTER TABLE ' . self::$completed_dirs_table_name . ' AUTO_INCREMENT = 1;');
            }
        }

        return true;
    }

    private function resetIteratorDataOption()
    {
        global $spbc;
        $spbc->data[$this->data_option_name] = new IteratorResult();
        $spbc->save('data');
    }

    /**
     * Collect file details and prepare to output.
     * @return void
     */
    private function handleFilesInfo()
    {
        $this->output_files_count = count($this->output_files);
        $this->fileDetails($this->output_files, $this->path_lenght);

        if ( $this->output_file_details ) {
            foreach ( $this->output_files as &$file ) {
                $file_tmp = array();
                foreach ( $this->output_file_details as $detail ) {
                    $file_tmp[$detail] = $file[$detail];
                }
                $file = $file_tmp;
            }
            unset($file);
        }
    }

    /**
     * This method checks every path and unset a dir if parent dir is provided in list.
     * @param array $dirs_to_filter
     * @return array
     */
    public static function collapseCompletedDirectories($dirs_to_filter)
    {
        $final = $dirs_to_filter;

        foreach ($dirs_to_filter as $_possible_root_key => $possible_root) {
            foreach ($dirs_to_filter as $completed_key => $completed) {
                if ($completed !== $possible_root) {
                    if ( strpos($completed, $possible_root . DIRECTORY_SEPARATOR) !== false) {
                        unset($final[$completed_key]);
                    }
                }
            }
        }

        return array_unique($final);
    }

    /**
     * * Function coverting icoming parametrs to array even if it is a string like 'some, example, string'
     *
     * @param $filter
     *
     * @return array|null
     */
    public function filterParams($filter)
    {
        if ( ! empty($filter) ) {
            if ( ! is_array($filter) ) {
                if ( strlen($filter) ) {
                    $filter = explode(',', $filter);
                }
            }
            foreach ( $filter as $_key => &$val ) {
                $val = trim($val);
            }

            return $filter;
        }

        return null;
    }

    /**
     * Counts given mandatory files
     *
     * @param array $files Files to count
     */
    public function countFilesMandatory($files)
    {
        foreach ( $files as $file ) {
            if ( is_file($file) ) {
                $this->output_files_count++;
            }
        }
    }

    /**
     * Count files in directory
     *
     * @param string $main_path Path to count files in
     */
    public function countFilesInDir($main_path)
    {
        try {
            foreach (
                @new \FilesystemIterator(
                    $main_path,
                    \FilesystemIterator::CURRENT_AS_PATHNAME | \FilesystemIterator::KEY_AS_FILENAME
                ) as $file_name => $path
            ) {
                // Skip bad paths
                if ( ! $file_name || ! $path ) {
                    continue;
                }

                if ( $file_name === ".." || $file_name === "." ) {
                    continue;
                }

                $path = (string) $path;

                if ( is_dir($path) ) {
                    // Directory names filter
                    foreach ( $this->dirs_except as $dir_except ) {
                        if ( strpos($path, $dir_except) ) {
                            continue(2);
                        }
                    }

                    $this->countFilesInDir($path);
                } else {
                    // Extensions filter
                    if ( $this->ext_except || $this->ext ) {
                        $tmp = explode('.', $path);
                        $currentFileExtension = $tmp[count($tmp) - 1];
                        if (
                            ! $this->hasFileAllowedExtension(
                                $currentFileExtension,
                                $this->ext_except,
                                $this->ext
                            )
                        ) {
                            continue;
                        }
                    }

                    // Filenames exception filter
                    if ( ! empty($this->files_except) && in_array($file_name, $this->files_except, true) ) {
                        continue;
                    }

                    $this->output_files_count++;
                }
            }
        } catch ( \Exception $e ) {
        }
    }

    /**
     * Getting mandatory files
     *
     * @param array $files Files to get
     */
    public function getFilesMandatory($files)
    {
        foreach ( $files as $file ) {
            if ( is_file($file) ) {
                $this->output_files[]['path'] = $file;
                $this->output_counter_files++;
            }
        }
    }

    /**
     * @param $main_path
     * @param IteratorResult $iterator_result
     * @param $is_root_dir
     * @return array|mixed
     * @psalm-suppress InvalidPropertyFetch
     */
    public function getFileStructure($main_path, $iterator_result, $is_root_dir)
    {
        // set interrupt status to false
        $iterator_result->max_files_interrupt = false;

        // if dir is empty
        if ( is_dir($main_path) && $this::dirIsEmpty($main_path) ) {
            $iterator_result->completed_dirs[] = $main_path;
            return $iterator_result;
        }

        try {
            $it = new \FilesystemIterator(
                $main_path,
                \FilesystemIterator::CURRENT_AS_PATHNAME | \FilesystemIterator::KEY_AS_FILENAME
            );

            if (!$is_root_dir) {
                $iterator_last_dir_offset = 0;
            }

            foreach ( $it as $file_name => $path ) {
                if ( ! $path ) {
                    continue;
                }

                if ( $file_name === ".." || $file_name === "." ) {
                    continue;
                }

                $path = (string) $path;

                if ( is_file($path) ) {
                    // Extensions filter
                    if ( $this->ext_except || $this->ext ) {
                        $tmp = explode('.', $path);
                        $currentFileExtension = $tmp[count($tmp) - 1];
                        if (
                            ! $this->hasFileAllowedExtension(
                                $currentFileExtension,
                                $this->ext_except,
                                $this->ext
                            )
                        ) {
                            continue;
                        }
                    }

                    // Filenames exception filter
                    if ( ! empty($this->files_except) && in_array($file_name, $this->files_except, true) ) {
                        continue;
                    }

                    $this->output_counter_files++;

                    // Skip if start is not reached for inner last dir
                    if ( !$is_root_dir ) {
                        $iterator_last_dir_offset++;
                        if ( $it->getPath() === $this->last_dir_on_exit && $iterator_last_dir_offset - 1 < $this->output_files_offset ) {
                            continue;
                        }
                    }

                    $this->output_files[]['path'] = $path;

                    // Return if file limit is reached
                    if ($this->output_counter_files >= $this->output_files_maximum ) {
                        $iterator_result->max_files_interrupt = true;
                        $iterator_result->on_exit_dir_path = $it->getPath();
                        $iterator_result->on_exit_dir_offset = isset($iterator_last_dir_offset) ? $iterator_last_dir_offset : 0;
                        return $iterator_result;
                    }
                } elseif ( is_dir($path) ) {
                    // Directory names filter
                    foreach ( $this->dirs_except as $dir_except ) {
                        if ( strpos($path, $dir_except) ) {
                            continue(2);
                        }
                    }
                    //skip already handled dirs
                    if (in_array($path, $iterator_result->completed_dirs)) {
                        continue;
                    }
                    // new sub-dir iteration start
                    $iterator_result = $this->getFileStructure($path, $iterator_result, false);
                    // if iteration is interrupted by files limit, return current results
                    if ($iterator_result->max_files_interrupt) {
                        return $iterator_result;
                    }
                    $this->dirs[]['path'] = $path;
                } elseif ( is_link($path) ) {
                    error_log('LINK FOUND: ' . $path);
                }
            }
            // foreach is finished - iterator completed with no interrupts, save the dir to the completed set
            if (!$is_root_dir) {
                $iterator_result->completed_dirs[] = $main_path;
            }
        } catch ( \Exception $exception ) {
            return $iterator_result;
        }
        // root dir reached and completed - end stage
        if ($is_root_dir && $iterator_result->max_files_interrupt === false) {
            $iterator_result->is_stage_end = true;
            $iterator_result->completed_dirs[] = $main_path;
        }
        return $iterator_result;
    }

    /**
     * Getting file details like last modified time, size, permissions
     *
     * @param array $file_list Array of abolute paths to files
     * @param int $path_offset Length of CMS root path
     */
    public function fileDetails($file_list, $path_offset)
    {
        global $wpdb, $spbc;

        foreach ( $file_list as $key => $val ) {
            // Cutting file's path, leave path from CMS ROOT to file

            // This order is important!!!
            $this->output_files[$key]['path']  = substr(
                $spbc->is_windows ? str_replace('/', '\\', $val['path']) : $val['path'],
                $path_offset
            );
            $this->output_files[$key]['size']  = filesize($val['path']);
            $this->output_files[$key]['perms'] = substr(decoct(fileperms($val['path'])), 3);
            $mtime = @filemtime($val['path']);
            if ( empty($mtime) ) {
                clearstatcache($val['path']);
                $mtime = @filemtime($val['path']);
                if ( empty($mtime) ) {
                    $mtime = @filectime($val['path']);
                    if ( empty($mtime) ) {
                        $mtime = time();
                    }
                }
            }

            $this->output_files[$key]['mtime'] = $mtime;

            // Fast hash
            $this->output_files[$key]['fast_hash'] = md5($this->output_files[$key]['path']);
            $fast_hash                      = $this->output_files[$key]['fast_hash'];

            // Full hash
            /**
             * Added SQL query to get the full hash of the file from the database.
             * If full hashes does not match, then the file is resaved with LF line ends
             */
            if ( ! is_readable($val['path']) ) {
                $this->output_files[$key]['full_hash'] = 'unknown';
                continue;
            }

            $current_file_full_hash = md5_file($val['path']);

            $sql = $wpdb->prepare(
                'SELECT `full_hash` FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE `fast_hash` = %s',
                $fast_hash
            );

            $db_full_hash = $wpdb->get_var($sql);

            if ( $db_full_hash && $current_file_full_hash !== $db_full_hash ) {
                $current_file_content  = file_get_contents($val['path']);
                $current_file_eol_type = spbc_PHP_logs__detect_EOL_type($val['path']);

                if ( $current_file_content ) {
                    $file_content = $current_file_content;

                    // LF
                    if ( $current_file_eol_type === 'LF' ) {
                        $file_content = str_replace(array("\r\n", "\r", "\n"), "\r\n", $current_file_content);
                    }
                    // CRLF
                    if ( $current_file_eol_type === 'CRLF' ) {
                        $file_content = str_replace(array("\r\n", "\r", "\n"), "\n", $current_file_content);
                    }

                    $file_content_hash = md5($file_content);

                    // All fine, changed EOL
                    if ( $file_content_hash === $db_full_hash ) {
                        $this->output_files[$key]['full_hash'] = $file_content_hash;
                        continue;
                    }
                }
            }

            $this->output_files[$key]['full_hash'] = $current_file_full_hash;
        }
    }

    /**
     * Getting dir details
     *
     * @param array $dir_list Array of abolute paths to directories
     * @param int $path_offset Length of CMS root path
     *
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function dirDetails($dir_list, $path_offset)
    {
        global $spbc;

        foreach ( $dir_list as $key => $val ) {
            $this->dirs[$key]['path']  = substr(
                $spbc->is_windows ? str_replace('/', '\\', $val['path']) : $val['path'],
                $path_offset
            );
            $this->dirs[$key]['mtime'] = filemtime($val['path']);
            $this->dirs[$key]['perms'] = substr(decoct(fileperms($val['path'])), 2);
        }
    }


    /**
     * Check dir is empty
     *
     * @param $dir
     *
     * @return bool
     */
    public static function dirIsEmpty($dir)
    {
        //return false if permission denied
        $handle = @opendir($dir);
        if ( false === $handle ) {
            return false;
        }

        while ( false !== ($entry = readdir($handle)) ) {
            if ( $entry !== "." && $entry !== ".." ) {
                closedir($handle);

                return false;
            }
        }
        closedir($handle);

        return true;
    }

    public function filterFileExtensionUsingRegexp($extension, array $extensions)
    {
        foreach ($extensions as $extensionItem) {
            $fsymbol = strpos($extensionItem, '[');
            $lsymbol = strpos($extensionItem, ']');

            $regexpExpression = substr($extensionItem, $fsymbol, $lsymbol);
            if ($regexpExpression) {
                $regexpExpression = '/' . trim($regexpExpression, "][") . '/';

                if (\CleantalkSP\SpbctWP\Helpers\Helper::isRegexp($regexpExpression) && preg_match($regexpExpression, $extension)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function hasFileAllowedExtension($currentFileExtension, array $ext_except, array $ext)
    {
        if (in_array($currentFileExtension, $ext_except, true)) {
            return false;
        }

        if (in_array($currentFileExtension, $ext, true)) {
            return true;
        }

        if ($this->filterFileExtensionUsingRegexp($currentFileExtension, $ext)) {
            return true;
        }

        return false;
    }
}
