<?php

namespace CleantalkSP\Common\FSWatcher\Analyzer;

use CleantalkSP\Common\FSWatcher\Logger;
use CleantalkSP\Common\FSWatcher\Controller;

class Analyzer
{
    /**
     * @return array|false
     */
    public static function getCompareResult()
    {
        $first = filter_var($_POST['fswatcher__first_date'], FILTER_VALIDATE_INT);
        $second = filter_var($_POST['fswatcher__second_date'], FILTER_VALIDATE_INT);

        if ($first > $second) {
            $tmp = $first;
            $first = $second;
            $second = $tmp;
        }
        $storage = Controller::$storage;
        $first_journal = $storage::getJournal($first);
        $second_journal = $storage::getJournal($second);

        if (!$first_journal || !$second_journal) {
            return false;
        }

        if (Controller::$debug) {
            Logger::log('first journal ' . $first_journal);
            Logger::log('second journal ' . $second_journal);
        }

        return self::compare($first_journal, $second_journal);
    }

    /**
     * @param $first_journal
     * @param $second_journal
     * @return array|false
     */
    protected static function compare($first_journal, $second_journal)
    {
        $result = array(
            'added' => array(),
            'deleted' => array(),
            'changed' => array(),
        );

        //return no diff if csv names is equal
        if ( $first_journal === $second_journal) {
            return $result;
        }

        //return no diff if md5 sums is equal
        if (md5(@file_get_contents($first_journal)) === md5(@file_get_contents($second_journal))) {
            return $result;
        }

        $first_journal = self::uncompress($first_journal);
        $second_journal = self::uncompress($second_journal);

        if ( !$first_journal || !$second_journal) {
            return false;
        }

        $first_array = [];
        $second_array = [];

        try {
            $fp_first = fopen($first_journal, 'r');
            while ($first = fgetcsv($fp_first)) {
                $first_array[$first[0]] = $first[1];
            }
            fclose($fp_first);
            @unlink($first_journal);

            $fp_second = fopen($second_journal, 'r');
            while ($second = fgetcsv($fp_second)) {
                $second_array[$second[0]] = $second[1];
            }
            fclose($fp_second);
            @unlink($second_journal);

            foreach ($first_array as $path => $time) {
                if ((isset($second_array[$path]) && $time !== $second_array[$path])) {
                    $result['changed'][] = [$path, $second_array[$path]];
                }
            }

            $keys_differ = array_merge(array_diff_key($first_array, $second_array), array_diff_key($second_array, $first_array));

            foreach ($keys_differ as $path => $time) {
                if ( in_array($path, array_keys($first_array)) && !in_array($path, array_keys($second_array))) {
                    $result['deleted'][] = [$path,$time];
                }

                if ( !in_array($path, array_keys($first_array)) && in_array($path, array_keys($second_array))) {
                    $result['added'][] = [$path,$time];
                }
            }

            return $result;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * @param $file
     * @return false|string
     */
    protected static function uncompress($file, $do_return_uncompressed_content = false)
    {
        if ( substr($file, -3) === '.gz' ) {
            $content = @gzopen($file, 'r');
            if ( false === $content ) {
                return false;
            }
            $gz_result = @gzread($content, 1024 * 1024 * 10);
            if ( !is_string($gz_result) ) {
                @gzclose($content);
                return false;
            }
            if ($do_return_uncompressed_content) {
                gzclose($content);
                return $gz_result;
            }
            $write_result = @file_put_contents(substr($file, 0, -3), $gz_result);
            gzclose($content);
            if ( false === $write_result ) {
                return false;
            }
            $file = substr($file, 0, -3);
        }

        return $file;
    }
}
