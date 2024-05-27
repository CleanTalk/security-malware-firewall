<?php

namespace CleantalkSP\SpbctWP\Scanner\Stages\Repositories;

use CleantalkSP\SpbctWP\API;

class LinksRepository extends GlobalRepository
{
    /**
     * LinksRepository constructor.
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Handle sub stage to send links to the cloud
     */
    public function handle($error)
    {
        if ($this->isNeedToGet()) {
            $links = $this->getResultData();

            $result = $this->sendResult($links);

            $error = $this->writeLog($error, $result, $links);
        }

        return $error;
    }

    /**
     * Checking if we need to get data from the database
     *
     * @return bool
     */
    protected function isNeedToGet()
    {
        if ($this->spbc->settings['scanner__outbound_links']) {
            return true;
        }

        return false;
    }

    /**
     * Getting data from the database
     *
     * @return array|object|null
     */
    protected function catchResultData()
    {
        return $this->db->fetchAll(
            'SELECT `link`, `link_text`, `page_url`'
            . ' FROM ' . SPBC_TBL_SCAN_LINKS
            . ' WHERE scan_id = (SELECT MAX(scan_id) FROM ' . SPBC_TBL_SCAN_LINKS . ');',
            OBJECT
        );
    }

    /**
     * Prepare result data
     *
     * @param $data
     *
     * @return array
     */
    protected function prepareResultData($data)
    {
        $links = [];

        foreach ($data as $link) {
            $links[$link->link] = array(
                'link_text' => $link->link_text,
                'page_url'  => $link->page_url,
            );
        }

        return $links;
    }

    /**
     * Send result to the cloud
     *
     * @param $links
     *
     * @return array<array-key, mixed>|bool|mixed
     */
    private function sendResult($links)
    {
        return API::method__security_linksscan_logs(
            $this->spbc->settings['spbc_key'],
            $this->getScannerStartLocalDate(),
            count($links) ? 'failed' : 'passed',
            count($links),
            json_encode($links)
        );
    }

    /**
     * Write log
     *
     * @param $error
     * @param $result
     * @param $links
     *
     * @return string
     */
    private function writeLog($error, $result, $links)
    {
        if ( ! empty($result['error']) ) {
            $error .= ' Links result send: ' . $result['error'];
        } else {
            $this->spbc->data['scanner']['last_scan_links_amount'] = count($links);
        }

        return $error;
    }
}
