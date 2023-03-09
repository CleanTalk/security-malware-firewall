<?php

namespace CleantalkSP\SpbctWP\Scanner;

use CleantalkSP\SpbctWP\Helpers\HTTP;

class Links
{
    // Counters
    public $posts_total = 0;
    public $posts_checked = 0;
    public $links_found = 0;

    // Params
    public $check_default = false;

    // Work's stuff
    public $post_checked = array(); // Posts IDs that have been checked
    public $content = array(); // Content to check
    public $hosts = array(); // This websites mirrors
    public $links = array(); // Links found

    // Default pages to check
    private $default_pages = array(
        '/index.php',
        '/wp-signup.php',
        '/wp-login.php',
    );

    /**
     * @param array $params
     */
    public function __construct($params = array())
    {
        // Setting params

        // Amount of pages to check in execution
        $amount = isset($params['amount']) ? $params['amount'] : 10;

        // Filter input params
        $this->hosts = ! empty($params['mirrors']) ? $this->processFilter($params['mirrors']) : array();

        // Should we check default pages
        $this->check_default = isset($params['check_default']) ? $params['check_default'] : false;

        // Only count all posts + default pages
        if ( ! empty($params['count']) ) {
            $this->countAllPosts();

            return;
        }

        // Do all the work
        $this->getPosts($amount);  // Get content to chceck
        $this->getAllHostnames(); // Get all links content URLs and add it to exceptions
        $this->getLinks();         // Get all links from content except exclusions
        if ( count($this->post_checked) ) {
            $this->postMarkAsChecked();
        }

        // Count everything
        $this->posts_checked = count($this->content);
        $this->links_found   = count($this->links);
    }

    /**
     * Filters input params cast it to array of trimmed strings
     *
     * @param array|string $filter [1 => 'one', 2 => 'two', ..] or 'one,two,..'
     *
     * @return array|null
     */
    public function processFilter($filter)
    {
        if ( ! empty($filter) ) {
            if ( ! is_array($filter) ) {
                $filter = explode(',', $filter);
            }

            foreach ( $filter as $key => $val ) {
                $filter[$key] = trim($val);
            }

            return $filter;
        }

        return null;
    }

    public function countAllPosts()
    {
        global $wpdb;

        $sql    = "SELECT COUNT(ID) as cnt
			FROM {$wpdb->posts} as posts
			WHERE 
				post_status = 'publish'
				AND post_type IN ('post', 'page')
				AND NOT EXISTS(
					SELECT post_id, meta_key
						FROM {$wpdb->postmeta} as meta
						WHERE posts.ID = meta.post_id AND meta.meta_key = '_spbc_links_checked'
				);";
        $result = $wpdb->get_results($sql, ARRAY_A);

        $this->posts_total = $result[0]['cnt'] + count($this->default_pages);
    }

    public function getPosts($amount)
    {
        // Getting POSTS range with all approved comments
        global $wpdb;

        $sql   = "
            SELECT
                posts.id as id,
                posts.post_content as post_content,
                CONCAT(
                    posts.post_content,
                    ' ',
                    (
                        SELECT
                            GROUP_CONCAT(`comment_content` SEPARATOR ' ')
                        FROM
                            {$wpdb->comments}
                        WHERE
                                comment_approved = 1
                            AND comment_post_id  = posts.id
                    )
                ) AS content
            FROM
                {$wpdb->posts} as posts
            WHERE
                    post_status = 'publish'
                AND post_type IN ('post', 'page')
                AND NOT EXISTS(
                    SELECT
                        post_id, meta_key
                    FROM
                        {$wpdb->postmeta} as meta
                    WHERE
                            posts.ID = meta.post_id
                        AND meta.meta_key = '_spbc_links_checked'
                )
            LIMIT $amount";
        $posts = $wpdb->get_results($sql, ARRAY_A);

        if ( ! empty($posts) ) {
            foreach ( $posts as $post ) {
                $this->content[]      = array(
                    'post_type'    => 'post_page',
                    'post_id'      => $post['id'],
                    'post_content' => $post['content'] ?: $post['post_content']
                );
                $this->post_checked[] = $post['id'];
            }
        }

        // Getting default pages
        if ( $this->check_default && ! count($this->content) ) {
            foreach ( $this->default_pages as $page ) {
                if ( HTTP::getResponseCode(get_site_url() . $page) === 200 ) {
                    $this->content[] = array(
                        'post_type'    => 'default',
                        'post_id'      => get_site_url() . $page,
                        'post_content' => HTTP::getContentFromURL(get_site_url() . $page),
                    );
                }
            }
        }
    }

    public function getLinks()
    {
        for ( $i = 0; isset($this->content[$i]); $i++ ) {
            $current = $this->content[$i];
            if ( $current['post_type'] === 'post_page' ) {
                // Links in tags
                preg_match_all(
                    "/<a\shref=\"(\S+:\/\/\S+)\".*?>(.*?)<\/a>/",
                    $current['post_content'],
                    $matches_tags
                );
                // Cutting founded
                $current['post_content'] = preg_replace(
                    "/<a\shref=\"(\S+:\/\/\S+)\".*?>(.*?)<\/a>/",
                    '',
                    $current['post_content']
                );
                // Naked links
                preg_match_all(
                    "/([a-zA-Z]{1,5}:\/\/[a-zA-Z0-9_\.\-\~]+\.[a-zA-Z0-9_\.\-\~]{2,4}\/?[a-zA-Z0-9_.\-~!*();:@&=+$,\/?#[%]*)/",
                    $current['post_content'],
                    $matches_naked
                );
                $matches_naked[2] = $matches_naked[1];
                // Merging found
                $matches = array(
                    array_merge($matches_tags[1], $matches_naked[1]),
                    array_merge($matches_tags[2], $matches_naked[2]),
                );
                foreach ( $matches[0] as $key => $match ) {
                    // Get only http or https links (not ftp, smtp, telnet, e.t.c.)
                    if ( parse_url($match, PHP_URL_SCHEME) === 'http' || parse_url($match, PHP_URL_SCHEME) === 'https' ) {
                        // Exclusion for website mirrors
                        if ( ! in_array(parse_url($match, PHP_URL_HOST), $this->hosts, true) ) {
                            $this->links[$match]['domain']    = parse_url($match, PHP_URL_HOST);
                            $this->links[$match]['link_text'] = trim($matches[1][$key]);
                            $this->links[$match]['page_url']  = $this->getPageUrlById($current['post_id']);
                        }
                    }
                }
            }

            if ( $current['post_type'] === 'default' ) {
                $dom = new \DOMDocument();
                @$dom->loadHTML($current['post_content']);
                $xpath = new \DOMXPath($dom);
                $hrefs = $xpath->evaluate("/html/body//a");
                for ( $j = 0; $j < $hrefs->length; $j++ ) {
                    $href = $hrefs->item($j);
                    $url  = $href->getAttribute('href');
                    $url  = filter_var($url, FILTER_SANITIZE_URL);
                    // Validate url
                    if ( ! filter_var($url, FILTER_VALIDATE_URL) === false ) {
                        // Exclusion for website mirrors
                        if ( ! in_array(parse_url($url, PHP_URL_HOST), $this->hosts, true) ) {
                            $this->links[$url]['domain']    = parse_url($url, PHP_URL_HOST);
                            $this->links[$url]['link_text'] = trim($href->nodeValue);
                            $this->links[$url]['page_url']  = $current['post_id'];
                        }
                    }
                }
            }
        }
    }

    public function getAllHostnames()
    {
        global $wpdb;

        $result = $wpdb->get_results(
            "SELECT guid
			FROM " . $wpdb->posts . " 
			WHERE 
				post_status = 'publish' 
				AND (post_type='post' OR post_type = 'page')",
            ARRAY_A
        );

        foreach ( $result as $host ) {
            $filtred_host = parse_url($host['guid'], PHP_URL_HOST);
            if ( ! in_array($filtred_host, $this->hosts, true) ) {
                $this->hosts[] = $filtred_host;
            }
        }
    }

    public function getPageUrlById($id)
    {
        global $wpdb;
        $result = $wpdb->get_results(
            "SELECT guid
			FROM " . $wpdb->posts . " 
			WHERE ID = $id
			LIMIT 1",
            ARRAY_A
        );

        return $result[0]['guid'];
    }

    public function postMarkAsChecked()
    {
        // global $wpdb;

        foreach ( $this->post_checked as $id ) {
            update_post_meta($id, '_spbc_links_checked', 1);
        }

        // $sql = "INSERT INTO {$wpdb->postmeta}
        // (post_id, meta_key, meta_value)
        // VALUES ";

        // foreach($this->post_checked as $id){
        // $sql .= "($id, '_spbc_links_checked', 1),";
        // }
        // $sql = substr($sql, 0, -1);
        // $sql .= ' ON DUPLICATE KEY
        // UPDATE
        // meta_value = 1;';

        // $wpdb->query($sql);
    }

    public static function resetCheckResult()
    {
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->postmeta} WHERE meta_key = '_spbc_links_checked';");

        return $wpdb->query('DELETE FROM ' . SPBC_TBL_SCAN_LINKS . ';');
    }
}
