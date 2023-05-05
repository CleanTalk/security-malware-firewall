<?php

namespace CleantalkSP\Common;

use CleantalkSP\Common\HTTP\Request;
use CleantalkSP\SpbctWP\DTO\MScanFilesDTO;

/**
 * CleanTalk API class.
 * Mostly contains wrappers for API methods. Check and send methods.
 * Compatible with any CMS.
 *
 * @version       3.2.1
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/php-antispam
 */
class API
{
    /* Default params  */
    const URL = 'https://api.cleantalk.org';
    const DEFAULT_AGENT = 'cleantalk-api-321';
    const SECURITY_CLUSTER_URL = 'https://api-security.cleantalk.org';

    private static function getProductID($product_name)
    {
        $product_id = null;
        $product_id = $product_name === 'antispam' ? 1 : $product_id;
        $product_id = $product_name === 'security' ? 4 : $product_id;

        return $product_id;
    }

    public static function sendRequest($data, $presets = array(), $use_security_cluster_url = false)
    {
        $http = new Request();

        return $http->setUrl($use_security_cluster_url ? static::SECURITY_CLUSTER_URL : static::URL)
                    ->setData($data)
                    ->setPresets(array_merge($presets, ['retry_with_socket']))
                    ->addCallback(
                        __CLASS__ . '::processResponse',
                        [$data['method_name']]
                    )
                    ->request();
    }

    /**
     * Function checks API response
     *
     * @param string $request_result
     * @param string $_url
     * @param string $method_name
     *
     * @return mixed (array || array('error' => true))
     */
    public static function processResponse($request_result, $_url, $method_name)
    {
        // Errors handling
        // Bad connection
        if (is_array($request_result) && isset($request_result['error'])) {
            return array(
                'error' => 'CONNECTION_ERROR' . (isset($request_result['error']) ? ': "' . $request_result['error'] . '"' : ''),
            );
        }

        // JSON decode errors
        $request_result = json_decode($request_result, true);
        if (empty($request_result)) {
            return array(
                'error' => 'JSON_DECODE_ERROR',
            );
        }

        // Server errors
        if ($request_result && (isset($request_result['error_no'], $request_result['error_message']))) {
            if ($request_result['error_no'] !== 12) {
                return array(
                    'error'         => "SERVER_ERROR NO: {$request_result['error_no']} MSG: {$request_result['error_message']}",
                    'error_no'      => $request_result['error_no'],
                    'error_message' => $request_result['error_message'],
                );
            }
        }

        // Patches for different methods
        switch ($method_name) {
            // notice_paid_till
            case 'notice_paid_till':
                $request_result = isset($request_result['data']) ? $request_result['data'] : $request_result;

                if ((isset($request_result['error_no']) && $request_result['error_no'] == 12) ||
                    (
                        ! (isset($request_result['service_id']) && is_int($request_result['service_id'])) &&
                        empty($request_result['moderate_ip'])
                    )
                ) {
                    $request_result['valid'] = 0;
                } else {
                    $request_result['valid'] = 1;
                }

                return $request_result;
            // get_antispam_report_breif
            case 'get_antispam_report_breif':
                $out = isset($request_result['data']) && is_array($request_result['data'])
                    ? $request_result['data']
                    : array('error' => 'NO_DATA');

                for ($tmp = array(), $i = 0; $i < 7; $i++) {
                    $tmp[ date('Y-m-d', time() - 86400 * 7 + 86400 * $i) ] = 0;
                }
                $out['spam_stat']    = array_merge($tmp, isset($out['spam_stat']) ? $out['spam_stat'] : array());
                $out['top5_spam_ip'] = isset($out['top5_spam_ip']) ? $out['top5_spam_ip'] : array();

                return $out;
            case 'services_templates_add':
            case 'services_templates_update':
                return isset($request_result['data']) && is_array($request_result['data']) && count($request_result['data']) === 1
                    ? $request_result['data'][0]
                    : array('error' => 'NO_DATA');
            case 'security_mscan_status':
                $data = array();
                foreach ($request_result['data'] as $_key => &$datum) {
                    // Do not process bad response without correct status
                    if ( ! isset($datum['file_status']) || ! in_array($datum['file_status'], array(
                            'SAFE',
                            'NEW',
                            'DANGEROUS'
                        ), true)) {
                        return array('error' => 'DATA_IS_BAD__STATUS');
                    }

                    $datum['comment'] = is_null($datum['comment']) ? '' : $datum['comment'];
                    // Do not process bad comments
                    if ( ! isset($datum['comment']) || ! Validate::isText($datum['comment'])) {
                        return array('error' => 'DATA_IS_BAD__COMMENT');
                    }

                    // Return only the latest submitted files
                    if (isset($data[ $datum['file_path'] ]) && $datum['submited'] > $data[ $datum['file_path'] ]['submited']) {
                        $data[ $datum['file_path'] ] = $datum;
                    }
                    if ( ! isset($data[ $datum['file_path'] ])) {
                        $data[ $datum['file_path'] ] = $datum;
                    }
                }

                return array_values($data);
            case 'service_get':
                return [
                    'server_response'         => isset($request_result['data'][0]['server_response'])
                        ? strip_tags($request_result['data'][0]['server_response'], '<p><a><br><h1><h2><h3><h4><h5>')
                        : '',
                ];
            default:
                return isset($request_result['data']) && is_array($request_result['data'])
                    ? $request_result['data']
                    : array('error' => 'NO_DATA');
        }
    }

    /**
     * Wrapper for 2s_blacklists_db API method.
     * Gets data for SpamFireWall.
     *
     * @param string $api_key
     * @param null|string $out Data output type (JSON or file URL)
     *
     * @return array
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function method__get_2s_blacklists_db($api_key, $out = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => '2s_blacklists_db',
            'auth_key'    => $api_key,
            'out'         => $out,
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for get_api_key API method.
     * Gets access key automatically.
     *
     * @param string $product_name Type of product
     * @param string $email Website admin email
     * @param string $website Website host
     * @param string $platform Website platform
     * @param string|null $timezone
     * @param string|null $language
     * @param string|null $user_ip
     * @param bool $wpms
     * @param bool $white_label
     * @param string $hoster_api_key
     *
     * @return array|bool|mixed
     */
    public static function method__get_api_key( // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
        $product_name,
        $email,
        $website,
        $platform,
        $timezone = null,
        $language = null,
        $user_ip = null,
        $wpms = false,
        $white_label = false,
        $hoster_api_key = ''
    ) {
        $request = array(
            'method_name'          => 'get_api_key',
            'product_name'         => $product_name,
            'email'                => $email,
            'website'              => $website,
            'platform'             => $platform,
            'timezone'             => $timezone,
            'http_accept_language' => $language,
            'user_ip'              => $user_ip,
            'wpms_setup'           => $wpms,
            'hoster_whitelabel'    => $white_label,
            'hoster_api_key'       => $hoster_api_key,
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for get_antispam_report API method.
     * Gets spam report.
     *
     * @param string $host website host
     * @param integer $period report days
     *
     * @return array|bool|mixed
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function method__get_antispam_report($host, $period = 1) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'get_antispam_report',
            'hostname'    => $host,
            'period'      => $period,
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for get_antispam_report_breif API method.
     * Gets spam statistics.
     *
     * @param string $api_key
     *
     * @return array|bool|mixed
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function method__get_antispam_report_breif($api_key) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'get_antispam_report_breif',
            'auth_key'    => $api_key,
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for notice_paid_till API method.
     * Gets information about renew notice.
     *
     * @param string $api_key API key
     * @param string $path_to_cms Website URL
     * @param string $product_name
     *
     * @return array|bool|mixed
     */
    public static function method__notice_paid_till($api_key, $path_to_cms, $product_name = 'antispam') // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'notice_paid_till',
            'path_to_cms' => $path_to_cms,
            'auth_key'    => $api_key,
        );

        if (self::getProductID($product_name)) {
            $request['product_id'] = self::getProductID($product_name);
        }

        return static::sendRequest($request);
    }

    /**
     * Wrapper for ip_info API method.
     * Gets IP country.
     *
     * @param string $data
     *
     * @return array|bool|mixed
     */
    public static function method__ip_info($data) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'ip_info',
            'data'        => $data,
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for spam_check_cms API method.
     * Checks IP|email via CleanTalk's database.
     *
     * @param string $api_key
     * @param array $data
     * @param null|string $date
     *
     * @return array|bool|mixed
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function method__spam_check_cms($api_key, $data, $date = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'spam_check_cms',
            'auth_key'    => $api_key,
            'data'        => is_array($data) ? implode(',', $data) : $data,
        );

        if ($date) {
            $request['date'] = $date;
        }

        return static::sendRequest($request);
    }

    /**
     * Wrapper for spam_check API method.
     * Checks IP|email via CleanTalk's database.
     *
     * @param string $api_key
     * @param array $data
     * @param null|string $date
     *
     * @return array|bool|mixed
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function method__spam_check($api_key, $data, $date = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'spam_check',
            'auth_key'    => $api_key,
            'data'        => is_array($data) ? implode(',', $data) : $data,
        );

        if ($date) {
            $request['date'] = $date;
        }

        return static::sendRequest($request);
    }

    /**
     * Wrapper for sfw_logs API method.
     * Sends SpamFireWall logs to the cloud.
     *
     * @param string $api_key
     * @param array $data
     *
     * @return array|bool|mixed
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function method__sfw_logs($api_key, $data) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'auth_key'    => $api_key,
            'method_name' => 'sfw_logs',
            'data'        => json_encode($data),
            'rows'        => count($data),
            'timestamp'   => time(),
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for security_logs API method.
     * Sends security logs to the cloud.
     *
     * @param string $api_key
     * @param array $data
     *
     * @return array|bool|mixed
     */
    public static function method__security_logs($api_key, $data) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'auth_key'    => $api_key,
            'method_name' => 'security_logs',
            //TODO Probably the better way is to send this in time() however, dashboard does not apply the offset,
            // because dashboard do not know the offset for the site
            'timestamp'   => current_time('timestamp'),
            'data'        => json_encode($data),
            'rows'        => count($data),
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for security_logs API method.
     * Sends Securitty Firewall logs to the cloud.
     *
     * @param string $api_key
     * @param array $data
     *
     * @return array|bool|mixed
     */
    public static function method__security_logs__sendFWData($api_key, $data) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'auth_key'    => $api_key,
            'method_name' => 'security_logs',
            //TODO Probably the better way is to send this in time() however, dashboard does not apply the offset,
            // because dashboard do not know the offset for the site
            'timestamp'   => current_time('timestamp'),
            'data_fw'     => json_encode($data),
            'rows_fw'     => count($data),
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for security_logs API method.
     * Sends empty data to the cloud to syncronize version.
     *
     * @param string $api_key
     *
     * @return array|bool|mixed
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function method__security_logs__feedback($api_key) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'auth_key'    => $api_key,
            'method_name' => 'security_logs',
            'data'        => '0',
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for security_firewall_data API method.
     * Gets Securitty Firewall data to write to the local database.
     *
     * @param string $api_key
     *
     * @return array|bool|mixed
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function method__security_firewall_data($api_key) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'auth_key'    => $api_key,
            'method_name' => 'security_firewall_data',
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for security_firewall_data_file API method.
     * Gets URI with security firewall data in .csv.gz file to write to the local database.
     *
     * @param string $api_key
     *
     * @return array|bool|mixed
     */
    public static function method__security_firewall_data_file($api_key, $out = null, $version = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'auth_key'    => $api_key,
            'method_name' => 'security_firewall_data_file',
            'version'     => $version,
        );

        if ($out) {
            $request['out'] = $out;
        }

        return static::sendRequest($request);
    }

    /**
     * Wrapper for security_linksscan_logs API method.
     * Send data to the cloud about scanned links.
     *
     * @param string $api_key
     * @param int|string $scan_time Datetime of scan
     * @param string $scan_result 'failed'|'passed'
     * @param int $links_total
     * @param string $links_list JSON string
     *
     * @return array|bool|mixed
     */
    public static function method__security_linksscan_logs($api_key, $scan_time, $scan_result, $links_total, $links_list) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'auth_key'          => $api_key,
            'method_name'       => 'security_linksscan_logs',
            'started'           => $scan_time,
            'result'            => $scan_result,
            'total_links_found' => $links_total,
            'links_list'        => $links_list,
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for security_fms_logs API method.
     * Sends result of frontend scan to the cloud.
     *
     * @param string $api_key
     * @param int $urls_checked
     * @param int $urls_infected
     * @param int|string $started_gmt Datetime of scan
     * @param false|string $urls_details List of modified files with details
     *
     * @return array|bool|mixed
     */
    public static function method__security_fms_logs( // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
        $api_key,
        $urls_checked,
        $urls_infected,
        $started_gmt,
        $urls_details
    ) {
        $request = array(
            'method_name'   => 'security_fms_logs',
            'auth_key'      => $api_key,
            'urls_checked'  => $urls_checked,
            'urls_infected' => $urls_infected,
            'started_gmt'   => $started_gmt,
            'urls_details'  => $urls_details,
        );

        return static::sendRequest($request);
    }


    /**
     * Wrapper for security_mscan_logs API method.
     * Sends result of file scan to the cloud.
     *
     * @param string $api_key
     * @param int $list_unknown
     * @param int $service_id
     * @param int|string $scan_time Datetime of scan
     * @param string $scan_result "passed"|"warning"
     * @param int $scanned_total
     * @param array $modified List of modified files with details
     * @param array $unknown List of modified files with details
     *
     * @return array|bool|mixed
     */
    public static function method__security_mscan_logs( // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
        $api_key,
        $list_unknown,
        $service_id,
        $scanner_start_local_date,
        $scan_result,
        $total_core_files,
        $total_site_files,
        $modified,
        $unknown,
        $scan_type,
        $checksums_count_ct,
        $checksums_count_user,
        $signatures_count,
        $scanned_total,
        $total_site_pages,
        $scanned_site_pages
    ) {
        $request = array(
            'method_name'          => 'security_mscan_logs',
            'auth_key'             => $api_key,
            'list_unknown'         => (int) $list_unknown,
            'service_id'           => $service_id,
            'started'              => $scanner_start_local_date,
            'result'               => $scan_result,
            'total_core_files'     => $total_core_files,
            'total_site_files'     => $total_site_files,
            'scan_type'            => $scan_type,
            'checksums_count_ct'   => $checksums_count_ct,
            'checksums_count_user' => $checksums_count_user,
            'signatures_count'     => $signatures_count,
            'total_scan_files'     => $scanned_total,
            'total_site_pages'     => $total_site_pages,
            'scanned_site_pages'   => $scanned_site_pages
        );

        if ( ! empty($modified)) {
            $request['failed_files']      = json_encode($modified);
            $request['failed_files_rows'] = count($modified);
        }
        if ( ! empty($unknown)) {
            $request['unknown_files']      = json_encode($unknown);
            $request['unknown_files_rows'] = count($unknown);
        }

        return static::sendRequest($request);
    }

    /**
     * Wrapper for security_mscan_files API method.
     * Sends file to the cloud for analysis.
     * @Deprecated 2.105 New cloud analytics implemented in method__security_pscan_files_send
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function method__security_mscan_files( // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
        $access_key,
        MScanFilesDTO $dto
    ) {
        $request = array(
            'auth_key' => $access_key,
            'method_name' => $dto->method_name,
            'path_to_sfile' => $dto->path_to_sfile,
            'attached_sfile' => $dto->attached_sfile,
            'md5sum_sfile' => $dto->md5sum_sfile,
            'dangerous_code' => $dto->dangerous_code,
            'version' => $dto->version,
            'source' => $dto->source,
            'source_type' => $dto->source_type,
            'source_status' => $dto->source_status,
            'real_hash' => $dto->real_hash,
        );

        return static::sendRequest($request);
    }

    /**
     * Api method security_pscan_files implementation. Send new files to the cloud.
     * @param $access_key
     * @param MScanFilesDTO $dto
     * @return array|string[]
     */
    public static function method__security_pscan_files_send( // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
        $access_key,
        MScanFilesDTO $dto
    ) {
        $request = array(
            'auth_key' => $access_key,
            'method_name' => $dto->method_name,
            'path_to_sfile' => $dto->path_to_sfile,//
            'attached_sfile' => $dto->attached_sfile,//
            'md5sum_sfile' => $dto->md5sum_sfile,//
            'source_type' => $dto->source_type,//
            'source' => $dto->source,//
            'source_version' => $dto->version, //
            'source_relevance' => $dto->source_status,
            'weak_spots' => $dto->dangerous_code, //
            //'real_hash' => $dto->real_hash,
        );
        return static::sendRequest($request, array(), true);
    }

    /**
     * Wrapper for get_antispam_report API method.
     * Function gets spam domains report.
     *
     * @param string $api_key
     * @param array|string|mixed $data
     * @param string $date
     *
     * @return array|bool|mixed
     */
    public static function method__backlinks_check_cms($api_key, $data, $date = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'backlinks_check_cms',
            'auth_key'    => $api_key,
            'data'        => is_array($data) ? implode(',', $data) : $data,
        );

        if ($date) {
            $request['date'] = $date;
        }

        return static::sendRequest($request);
    }

    /**
     * Wrapper for get_antispam_report API method.
     * Function gets spam domains report
     *
     * @param string $api_key
     * @param array $logs
     *
     * @return array|bool|mixed
     */
    public static function method__security_backend_logs($api_key, $logs) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'security_backend_logs',
            'auth_key'    => $api_key,
            'logs'        => json_encode($logs),
            'total_logs'  => count($logs),
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for get_antispam_report API method.
     * Sends data about auto repairs
     *
     * @param string $api_key
     * @param string $repair_result
     * @param string $repair_comment
     * @param array $repaired_processed_files
     * @param int $repaired_total_files_processed
     * @param int $backup_id
     * @param int $scanner_start_local_date
     *
     * @return array|bool|mixed
     */
    public static function method__security_mscan_repairs( // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
        $api_key,
        $repair_result,
        $repair_comment,
        $repaired_processed_files,
        $repaired_total_files_processed,
        $backup_id,
        $scanner_start_local_date
    ) {
        $request = array(
            'method_name'                  => 'security_mscan_repairs',
            'auth_key'                     => $api_key,
            'repair_result'                => $repair_result,
            'repair_comment'               => $repair_comment,
            'repair_processed_files'       => json_encode($repaired_processed_files),
            'repair_total_files_processed' => $repaired_total_files_processed,
            'backup_id'                    => $backup_id,
            'started'                      => $scanner_start_local_date,
        );

        return static::sendRequest($request);
    }

    /**
     * Wrapper for get_antispam_report API method.
     * Force server to update checksums for specific plugin\theme
     *
     * @param string $api_key
     * @param string $plugins_and_themes_to_refresh
     */
    public static function method__request_checksums($api_key, $plugins_and_themes_to_refresh) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'request_checksums',
            'auth_key'    => $api_key,
            'data'        => $plugins_and_themes_to_refresh,
        );

        static::sendRequest($request);
    }

    /**
     * Settings templates get API method wrapper
     *
     * @param string $api_key
     * @param string $product_name
     *
     * @return array|bool|mixed
     */
    public static function method__services_templates_get($api_key, $product_name = 'antispam') // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name'        => 'services_templates_get',
            'auth_key'           => $api_key,
            'search[product_id]' => self::getProductID($product_name),
        );

        return static::sendRequest($request);
    }

    /**
     * Settings templates add API method wrapper
     *
     * @param string $api_key
     * @param string $template_name
     * @param string $options
     * @param string $product_name
     *
     * @return array|bool|mixed
     */
    public static function method__services_templates_add($api_key, $template_name = '', $options = '', $product_name = 'antispam') // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name'        => 'services_templates_add',
            'auth_key'           => $api_key,
            'name'               => $template_name,
            'options_site'       => $options,
            'search[product_id]' => self::getProductID($product_name),
        );

        return static::sendRequest($request);
    }

    /**
     * Settings templates add API method wrapper
     *
     * @param string $api_key
     * @param int $template_id
     * @param string $options
     * @param string $product_name
     *
     * @return array|bool|mixed
     */
    public static function method__services_templates_update($api_key, $template_id, $options = '', $product_name = 'antispam') // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name'        => 'services_templates_update',
            'auth_key'           => $api_key,
            'template_id'        => $template_id,
            'name'               => null,
            'options_site'       => $options,
            'search[product_id]' => self::getProductID($product_name),
        );

        return static::sendRequest($request);
    }

    /**
     *
     *
     * @param $user_token
     * @param $ip
     * @param $service_id
     *
     * @return array|string[]
     */
    public static function method__private_list_add($user_token, $ip, $service_id, $additional_params = []) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name'  => 'private_list_add',
            'user_token'   => $user_token,
            'service_id'   => $service_id,
            'records'      => $ip,
            'service_type' => 'securityfirewall',
            'product_id'   => 4,
            'record_type'  => 1,
            'note'         => 'Added by website admin on ' . date('M j, Y')
        );

        $request = array_merge($request, $additional_params);

        return static::sendRequest($request);
    }

    /**
     * Adding admin IP to the Security FW WL
     *
     * @param $user_token
     * @param $ip
     * @param $service_id
     *
     * @return array|bool|mixed
     */
    public static function method__private_list_add__secfw_wl($user_token, $ip, $service_id) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $params = array(
            'note'         => 'Website admin IP. Added automatically.',
            'status'       => 'allow',
            'expired'      => date('Y-m-d H:i:s', time() + 86400 * 30),
            'update_record' => 1
        );
        return static::method__private_list_add($user_token, $ip, $service_id, $params);
    }

    /**
     * Api method security_pscan_files implementation. Update status of sent files.
     * @param $access_key
     * @param MScanFilesDTO $dto
     * @return array|string[]
     */
    public static function method__security_pscan_status($api_key, $file_id) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'security_pscan_files',
            'auth_key' => $api_key,
            'file_id' => $file_id,
        );

        return static::sendRequest($request, array(), true);
    }

    /**
     * Receiving some data about service
     *
     * @param string $api_key
     * @param string $user_token
     *
     * @return array|bool|mixed
     */
    public static function method__service_get($api_key, $user_token) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $request = array(
            'method_name' => 'service_get',
            'auth_key'    => $api_key,
            'user_token'  => $user_token,
        );

        return static::sendRequest($request);
    }

    /**
     * Sending of local settings API method wrapper
     *
     * @param string $api_key
     * @param string $hostname
     * @param string $settings
     *
     * @return array|bool|mixed
     *
     * @psalm-suppress PossiblyUnusedMethod
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function methodSendLocalSettings( // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
        $api_key,
        $hostname,
        $settings
    ) {
        $request = array(
            'method_name' => 'service_update_local_settings',
            'auth_key'    => $api_key,
            'hostname'    => $hostname,
            'settings'    => $settings
        );

        return static::sendRequest($request, ['async']);
    }
}
