<?php

namespace CleantalkSP\SpbctWP\Scanner\UnsafePermissionsModule;

use CleantalkSP\SpbctWP\State;

class UnsafePermissionFunctions
{
    /**
     * @var State
     */
    private $spbc;

    /**
     * @param $spbc
     */
    public function __construct($spbc)
    {
        $this->spbc = $spbc;
    }

    public function handle()
    {
        $files = UnsafePermissionsContainer::getFiles();
        $dirs = UnsafePermissionsContainer::getDirs();
        $checking_list = array(
            'files' => $this->checkFiles($files),
            'dirs' => $this->checkDirs($dirs),
        );

        $this->spbc->data['unsafe_permissions'] = $checking_list;
        $this->spbc->save('data');
    }

    /**
     * @param array $files
     *
     * @return array
     */
    private function checkFiles($files = array())
    {
        $checking_list = array();

        foreach ($files as $path => $base_permission) {
            $abs_path = ABSPATH . ltrim($path, '/');

            if (file_exists($abs_path)) {
                $permission = (int)substr(decoct(fileperms($abs_path)), 3);

                if ($permission > $base_permission) {
                    // add to $checking_list
                    $checking_list[] = array(
                        $path => $permission
                    );
                }
            }
        }

        return $checking_list;
    }

    /**
     * @param array $dirs
     *
     * @return array
     */
    private function checkDirs($dirs = array())
    {
        $checking_list = array();

        foreach ($dirs as $path => $base_permission) {
            $abs_path = ABSPATH . ltrim($path, '/');

            if (is_dir($abs_path)) {
                $permission = (int)substr(decoct(fileperms($abs_path)), 2);

                if ($permission > $base_permission) {
                    // add to $checking_list
                    $checking_list[] = array(
                        $path => $permission
                    );
                }
            }
        }

        return $checking_list;
    }

    /**
     * @return int|void
     */
    public function getCountData()
    {
        $data = $this->spbc->data['unsafe_permissions'];

        if ($data) {
            $count_files = isset($data['files']) ? count($data['files']) : 0;
            $count_dirs = isset($data['dirs']) ? count($data['dirs']) : 0;

            return $count_files + $count_dirs;
        }

        return 0;
    }

    /**
     * @return array
     */
    public function getDataToAccordion()
    {
        $data = $this->spbc->data['unsafe_permissions'];
        $data_to_accordion = array();

        if ($data) {
            // Files
            if (isset($data['files'])) {
                foreach ($data['files'] as $file) {
                    $data_to_accordion[] = (object) array(
                        'path' => array_keys($file)[0],
                        'perms' => $file[array_keys($file)[0]]
                    );
                }
            }

            // Dirs
            if (isset($data['dirs'])) {
                foreach ($data['dirs'] as $dir) {
                    $data_to_accordion[] = (object) array(
                        'path' => array_keys($dir)[0],
                        'perms' => $dir[array_keys($dir)[0]]
                    );
                }
            }
        }

        return $data_to_accordion;
    }
}
