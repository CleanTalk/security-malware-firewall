<?php

namespace CleantalkSP\SpbctWP\Settings;

use CleantalkSP\SpbctWP\Scanner;
use CleantalkSP\SpbctWP\Helpers\CSV;

class FrontendScanDomainExclusion
{
    private $DOMAIN_EXCLUSION_FILE_NAME = 'spbct_allowed_domains.txt';

    public function frontendScanDomainExclusionsView($exclusions)
    {
        $urls = CSV::parseNSV($exclusions);

        foreach ($urls as $key => $url) {
            $parsed_url = parse_url($url);
            if (isset($parsed_url['scheme'])) {
                $url = preg_replace('#^' . $parsed_url['scheme'] . '://#', '', $url);
            }
            $urls[$key] = $url;
        }

        $result = [];
        foreach ($urls as $url) {
            if (preg_match('/\S+?\.\S+/', $url)) {
                $result[] = $url;
            }
        }

        $result = array_unique($result);

        return implode("\n", $result);
    }

    public function domainExclusions($exclusions)
    {
        $urls = CSV::parseNSV($exclusions);
        $result = [];

        $upload_urls = [];
        foreach ($urls as $key => $url) {
            if (substr($url, -strlen($this->DOMAIN_EXCLUSION_FILE_NAME)) === $this->DOMAIN_EXCLUSION_FILE_NAME) {
                $upload_urls[] = $url;
                unset($urls[$key]);
            }
        }

        $upload_urls = $this->getUploadUrls($upload_urls);

        $urls = array_merge($urls, $upload_urls);
        $urls = array_unique($urls);

        foreach ($urls as $url) {
            $url = preg_replace('#\\\\+|\/+#', '/', $url);
            $url = trim($url, "/");
            $result[] = $url;
        }

        return implode("\n", $result);
    }

    public function resetScannerFrontendResult($settings)
    {
        global $spbc;

        if (
            is_main_site() &&
            (
                $settings['scanner__frontend_analysis__domains_exclusions'] !== $spbc->settings['scanner__frontend_analysis__domains_exclusions'] ||
                $settings['scanner__frontend_analysis__csrf'] !== $spbc->settings['scanner__frontend_analysis__csrf']
            )
        ) {
            Scanner\Frontend::resetCheckResult();
            $spbc->data['scanner']['first_scan__front_end'] = 1;
        }
    }

    private function getUploadUrl($url)
    {
        if (parse_url($url, PHP_URL_SCHEME) === null) {
            $url = 'http://' . $url;
        }

        $context = stream_context_create([
        'http' => [
            'timeout' => 5 // Timeout in seconds
            ]
        ]);
        $file_content = @file_get_contents($url, false, $context);

        if ($file_content === false) {
            return false;
        }

        return CSV::parseNSV($file_content);
    }

    private function getUploadUrls($urls)
    {
        $results = [];
        $upload_urls_stat = [];

        foreach ($urls as $url) {
            $results[$url] = $this->getUploadUrl($url);
        }

        foreach ($results as $url => $url_content) {
            if ($url_content === false) {
                $upload_urls_stat[$url] = __('Unable to download content.', 'security-malware-firewall');
                unset($results[$url]);
                continue;
            }

            $url_content = array_filter($url_content, function ($url) {
                return $url !== '';
            });

            $upload_urls_stat[$url] = count($url_content);
        }
        update_option('spbc_upload_urls_stat', $upload_urls_stat);

        $upload_urls_merged = [];
        foreach ($results as $url) {
            $upload_urls_merged = array_merge($upload_urls_merged, array_values($url));
        }

        return $upload_urls_merged;
    }
}
