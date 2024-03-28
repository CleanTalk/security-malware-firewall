<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser;

use CleantalkSP\Common\Helpers\Arr;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Exceptions\HeuristicScannerException;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Structures\FileInfo;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Structures\Verdict;

class Controller
{
    /**
     * @var string
     *
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $final_code;

    public function __construct()
    {
    }

    public function scanFile(FileInfo $file_info, $root_path)
    {
        $output = new Verdict();
        $output->weak_spots = null;
        $output->severity   = null;
        $output->status     = 'ERROR';
        $output->includes   = array();
        try {
            $output = $this->scanFileForHeuristic($file_info, $root_path);
        } catch (HeuristicScannerException $e) {
            $output->error_msg = $e->getMessage();
            return $output;
        } catch (\Exception $e) {
            $output->error_msg = 'UNKNOWN_INTERNAL_ERROR';
        }

        return $output;
    }

    /**
     * Scan file against the heuristic
     *
     * @param FileInfo $file_info Array with files data (path, real_full_hash, source_type, source, version), other is optional
     * @param string $root_path Path to CMS's root folder
     *
     * @return Verdict False or Array of found bad constructs sorted by severity
     * @throws HeuristicScannerException
     */
    private function scanFileForHeuristic(FileInfo $file_info, $root_path)
    {
        if ( ! empty($file_info->content) ) {
            $params = ['content' => $file_info->content];
        } else {
            $params = ['path' => $root_path . $file_info->path];
        }

        $scanner = new HeuristicAnalyser($params);

        $output = new Verdict();

        $scanner->processContent();

        // Saving only signatures from the previous result
        $file_info->weak_spots = ! empty($file_info->weak_spots) ? json_decode(
            $file_info->weak_spots,
            true
        ) : array();
        $file_info->weak_spots = isset($file_info->weak_spots['SIGNATURES'])
            ? array('SIGNATURES' => $file_info->weak_spots['SIGNATURES'])
            : array();

        $verdict = Arr::mergeWithSavingNumericKeysRecursive($file_info->weak_spots, $scanner->verdict);

        $output->includes = $scanner->getIncludes();

        // Processing results
        if ( !empty($verdict) ) {
            $output->weak_spots = $verdict;
            $output->severity = array_key_exists('SIGNATURES', $verdict)
                ? 'CRITICAL'
                : 'SUSPICIOUS';
            $output->status = (
                array_key_exists('CRITICAL', $verdict) ||
                array_key_exists('SIGNATURES', $verdict) ||
                array_key_exists('SUSPICIOUS', $verdict)
            )
                ? 'INFECTED'
                : 'OK';
        } else {
            $output->weak_spots = null;
            $output->severity = null;
            $output->status = 'OK';
        }

        $this->final_code = $scanner->deobfuscated_code;
        return $output;
    }
}
