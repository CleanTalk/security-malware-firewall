<?php

namespace CleantalkSP\SpbctWP\HTTP;

use CleantalkSP\Common\Helpers\HTTP;
use CleantalkSP\Common\HTTP\Response;

class Request extends \CleantalkSP\Common\HTTP\Request
{
    public function __construct()
    {
    }

    /**
     * @inheritDoc
     */
    public function request()
    {
        global $spbc;

        // Make a request via builtin WordPress HTTP API
        if ( $spbc->settings['wp__use_builtin_http_api'] ) {
            $this->appendOptionsObligatory();
            $this->processPresets();

            // Call cURL multi request if many URLs passed
            $this->response = is_array($this->url)
                ? $this->requestMulti()
                : $this->requestSingle();

            return $this->runCallbacks();
        }

        return parent::request();
    }

    /**
     * @inheritDoc
     *
     * @psalm-suppress UndefinedDocblockClass
     * @psalm-suppress UndefinedClass
     */
    protected function requestSingle()
    {
        global $spbc;

        if ( ! $spbc->settings['wp__use_builtin_http_api'] ) {
            return parent::requestSingle();
        }

        $type = in_array('get', $this->presets, true) ? 'GET' : 'POST';

        // WP 6.2 support: Requests/Response classes has been replaced into the another namespace in the core
        if ( class_exists('\WpOrg\Requests\Requests') ) {
            /** @var \WpOrg\Requests\Requests $requests_class */
            $requests_class = '\WpOrg\Requests\Requests';
            /** @var \WpOrg\Requests\Response $response_class */
            $response_class = '\WpOrg\Requests\Response';
        } else {
            /** @var \Requests $requests_class */
            $requests_class = '\Requests';
            /** @var \Requests_Response $response_class */
            $response_class = '\Requests_Response';
        }

        try {
            $response = $requests_class::request(
                $this->url,
                $this->options[CURLOPT_HTTPHEADER],
                $this->data,
                $type,
                $this->options
            );
        } catch ( \Exception $e ) {
            return new Response(['error' => $e->getMessage()], []);
        }

        if ( $response instanceof $response_class ) {
            return new Response($response->body, ['http_code' => $response->status_code]);
        }

        // String passed
        return new Response($response, []);
    }

    /**
     * @inheritDoc
     *
     * @psalm-suppress InvalidReturnType
     * @psalm-suppress InvalidReturnStatement
     * @psalm-suppress UndefinedDocblockClass
     * @psalm-suppress UndefinedClass
     */
    protected function requestMulti()
    {
        global $spbc;

        if ( ! $spbc->settings['wp__use_builtin_http_api'] ) {
            return parent::requestMulti();
        }

        $responses = [];
        $requests  = [];
        $options   = [];

        // Prepare options
        foreach ( $this->url as $url ) {
            $requests[] = [
                'url'     => $url,
                'headers' => $this->options[CURLOPT_HTTPHEADER],
                'data'    => $this->data,
                'type'    => $type = in_array('get', $this->presets, true) ? 'GET' : 'POST',
                'cookies' => [],
            ];
            $options[]  = [

            ];
        }

        // WP 6.2 support: Requests/Response classes has been replaced into the another namespace in the core
        if ( class_exists('\WpOrg\Requests\Requests') ) {
            /** @var \WpOrg\Requests\Requests $requests_class */
            $requests_class = '\WpOrg\Requests\Requests';
            /** @var \WpOrg\Requests\Response $response_class */
            $response_class = '\WpOrg\Requests\Response';
        } else {
            /** @var \Requests $requests_class */
            $requests_class = '\Requests';
            /** @var \Requests_Response $response_class */
            $response_class = '\Requests_Response';
        }

        $responses_raw = $requests_class::request_multiple($requests, $options);

        foreach ( $responses_raw as $response ) {
            if ( $response instanceof \Exception ) {
                $responses[$this->url] = new Response(['error' => $response->getMessage()], []);
                continue;
            }
            if ( $response instanceof $response_class ) {
                $responses[$response->url] = new Response($response->body, ['http_code' => $response->status_code]);
                continue;
            }

            // String passed
            $responses[$response->url] = new Response($response, []);
        }

        return $responses;
    }

    /**
     * Set default options to make a request
     */
    protected function appendOptionsObligatory()
    {
        parent::appendOptionsObligatory();

        global $spbc;

        if ( $spbc->settings['wp__use_builtin_http_api'] ) {
            $this->options['useragent'] = self::AGENT;
        }
    }

    /**
     * Append options considering passed presets
     */
    protected function processPresets()
    {
        parent::processPresets();

        global $spbc;

        if ( $spbc->settings['wp__use_builtin_http_api'] ) {
            foreach ( $this->presets as $preset ) {
                switch ( $preset ) {
                    // Do not follow redirects
                    case 'dont_follow_redirects':
                        $this->options['follow_redirects'] = false;
                        $this->options['redirects']        = 0;
                        break;

                    // Make a request, don't wait for an answer
                    case 'async':
                        $this->options['timeout']         = 3;
                        $this->options['connect_timeout'] = 3;
                        $this->options['blocking']        = false;
                        break;

                    case 'ssl':
                        $this->options['verifyname'] = true;
                        if ( defined('CLEANTALK_CASERT_PATH') && CLEANTALK_CASERT_PATH ) {
                            $this->options['verify'] = CLEANTALK_CASERT_PATH;
                        }
                        break;

                    case 'no_cache':
                        // Append parameter in a different way for single and multiple requests
                        if ( is_array($this->url) ) {
                            $this->url = array_map(static function ($elem) {
                                return HTTP::appendParametersToURL($elem, ['spbct_no_cache' => mt_rand()]);
                            }, $this->url);
                        } else {
                            $this->url = HTTP::appendParametersToURL(
                                $this->url,
                                ['spbct_no_cache' => mt_rand()]
                            );
                        }
                        break;
                }
            }
        }
    }
}
