<?php

namespace CleantalkSP\Common\Scanner\SignaturesAnalyser;

use CleantalkSP\Common\Helpers\Arr;
use CleantalkSP\Common\Helpers\Helper;
use CleantalkSP\Common\Scanner\SignaturesAnalyser\Structures\FileInfo;
use CleantalkSP\Common\Scanner\SignaturesAnalyser\Structures\Verdict;
use CleantalkSP\Common\Scanner\SignaturesAnalyser\Exceptions\SignaturesScannerException;

class Controller
{
    const FILE_MAX_SIZE = 524288; // 512 KB

    public function __construct()
    {
    }

    public function scanFile(FileInfo $file_info, $root_path, &$signatures)
    {
        try {
            $output = $this->scanFileForSignatures($file_info, $root_path, $signatures);
        } catch (SignaturesScannerException $e) {
            //$output = array('error' => $e->getMessage());
            $output = new Verdict();
        }

        return $output;
    }

    /**
     * @param int|string $file_size_or_path
     *
     * @return void
     * @throws SignaturesScannerException
     */
    private static function checkFileSize($file_size_or_path)
    {
        $file_size = ! is_int($file_size_or_path) ? filesize($file_size_or_path) : $file_size_or_path;

        if ( ! (int)$file_size ) {
            throw new SignaturesScannerException('FILE_SIZE_ZERO');
        }

        if ( (int)$file_size > self::FILE_MAX_SIZE ) {
            throw new SignaturesScannerException('FILE_SIZE_TO_LARGE');
        }
    }

    /**
     * Scan file against malware signatures
     *
     * @param FileInfo $file_info Array with files data (path, real_full_hash, source_type, source, version), other is optional
     * @param string $root_path Path to CMS's root folder
     * @param array $signatures Set of signatures
     *
     * @return Verdict Verdict or Error Array
     * @throws SignaturesScannerException
     */
    private function scanFileForSignatures(FileInfo $file_info, $root_path, &$signatures)
    {
        $output = new Verdict();

        if ( file_exists($root_path . $file_info->path) ) {
            if ( is_readable($root_path . $file_info->path) ) {
                self::checkFileSize($root_path . $file_info->path);

                $verdict      = array();
                $file_content = file_get_contents($root_path . $file_info->path);

                foreach ( (array)$signatures as $signature ) {
                    if ( $signature['type'] === 'FILE' ) {
                        if ( $file_info->full_hash === $signature['body'] ) {
                            $verdict['SIGNATURES'][1][] = $signature['id'];
                        }
                    }

                    if ( in_array($signature['type'], array('CODE_PHP', 'CODE_JS', 'CODE_HTML')) ) {
                        $is_regexp = Helper::isRegexp($signature['body']);

                        if (
                            ( $is_regexp && preg_match($signature['body'], $file_content) ) ||
                            ( ! $is_regexp &&
                            ( strripos($file_content, stripslashes($signature['body'])) !== false ||
                              strripos($file_content, $signature['body']) !== false) )
                        ) {
                            $line_number                           = Helper::getNeedleStringNumberFromFile(
                                $root_path . $file_info->path,
                                $signature['body'],
                                $is_regexp
                            );
                            $verdict['SIGNATURES'][$line_number][] = $signature['id'];
                        }
                    }
                }
                // Removing signatures from the previous result
                $file_info->weak_spots = ! empty($file_info->weak_spots) ? json_decode(
                    $file_info->weak_spots,
                    true
                ) : array();
                if ( isset($file_info->weak_spots['SIGNATURES']) ) {
                    unset($file_info->weak_spots['SIGNATURES']);
                }

                $verdict = Arr::mergeWithSavingNumericKeysRecursive($file_info->weak_spots, $verdict);

                // Processing results
                if ( ! empty($verdict) ) {
                    $output->weak_spots = $verdict;
                    $output->severity   = 'CRITICAL';
                    $output->status     = 'INFECTED';
                } else {
                    $output->weak_spots = 'NULL';
                    $output->severity   = 'NULL';
                    $output->status     = 'OK';
                }
            } else {
                throw new SignaturesScannerException('NOT_READABLE');
            }
        } else {
            throw new SignaturesScannerException('NOT_EXISTS');
        }

        return $output;
    }
}
