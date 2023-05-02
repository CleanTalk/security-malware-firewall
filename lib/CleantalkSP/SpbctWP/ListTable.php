<?php

namespace CleantalkSP\SpbctWP;

use CleantalkSP\Variables\Post;

class ListTable
{
    /**
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $args = array(); // Input arguments

    public $id = ''; // Table id
    private $type; // Short description

    // SQL query params
    public $sql = array(
        'add_col'            => array(), // Additional cols to select
        'except_cols'        => array(), // Cols to except from query
        'table'              => '',      // Table name
        'where'              => '',      // Where clause
        'order_by'           => '',      // Order By
        'order_by_direction' => '',      // Desc / Asc
        'group_by'           => '',
        'offset'             => 0,       // Limit from
        'limit'              => 20,      // Limit till
        'get_array'          => false,   // Give an array on output
    );
    public $rows = array(); // SQL Result

    // Pagination params
    public $pagination = array();

    // Callbacks
    public $func_data_prepare = null; // Function to process items before output
    public $func_data_get = null; // Function to receive data
    public $func_data_total = null; // Function to get total items

    // ROWS
    public $items = array(); // Items to output
    public $items_count = 0; // Amount to output
    public $items_total = 0; // Amount total

    // COLS
    public $columns = array();
    public $columns_names;
    public $columns_amount;

    // Misc
    public $sortable = array();     // Sortable columns
    public $order_by = array();     // Current sorting
    public $actions = array();      // Row actions
    public $bulk_actions = array(); // Bulk actions

    // HTML output
    public $html_before = ''; // HTML before table
    public $html_after = ''; // HTML after table
    public $if_empty_items = 'No data given.'; // HTML message

    public function __construct($args = array())
    {
        $this->args = json_encode($args);

        $this->id   = ! empty($args['id']) ? $args['id'] : 'table_' . rand(0, 10000);
        $this->type = ! empty($args['type']) ? $args['type'] : 'unknown';

        $this->items   = ! empty($args['items']) ? $args['items'] : $this->items;
        $this->columns = ! empty($args['columns']) ? $args['columns'] : $this->columns;

        $this->items_count = count((array)$this->items);
        $this->items_total = count((array)$this->items);

        // HTML output
        $this->html_before    = ! empty($args['html_before']) ? $args['html_before'] : $this->html_before;
        $this->html_after     = ! empty($args['html_after']) ? $args['html_after'] : $this->html_after;
        $this->if_empty_items = ! empty($args['if_empty_items']) ? $args['if_empty_items'] : $this->if_empty_items;

        if ( isset($args['pagination']['page']) ) {
            $this->pagination['page'] = $args['pagination']['page'];
        }
        if ( isset($args['pagination']['per_page']) ) {
            $this->pagination['per_page'] = $args['pagination']['per_page'];
        }

        // SQL shit

        if ( ! empty($args['sql']) ) {
            $this->sql['add_col']     = ! empty($args['sql']['add_col']) ? $args['sql']['add_col'] : $this->sql['add_col'];
            $this->sql['except_cols'] = ! empty($args['sql']['except_cols']) ? $args['sql']['except_cols'] : $this->sql['except_cols'];
            $this->sql['table']       = ! empty($args['sql']['table']) ? $args['sql']['table'] : $this->sql['table'];
            $this->sql['where']       = ! empty($args['sql']['where']) ? $args['sql']['where'] : $this->sql['where'];
            $this->sql['group_by']    = ! empty($args['sql']['group_by']) ? $args['sql']['group_by'] : $this->sql['group_by'];
            $this->sql['offset']      = ! empty($args['sql']['offset']) ? $args['sql']['offset'] : $this->sql['offset'];
            $this->sql['limit']       = ! empty($args['sql']['limit']) ? $args['sql']['limit'] : $this->sql['limit'];
            $this->sql['get_array']   = ! empty($args['sql']['get_array']) ? $args['sql']['get_array'] : $this->sql['get_array'];
        }

        $this->sql['offset'] = isset($this->pagination['page']) ? ($this->pagination['page'] - 1) * $this->pagination['per_page'] : $this->sql['offset'];
        $this->sql['limit']  = isset($this->pagination['per_page']) ? $this->pagination['per_page'] : $this->sql['limit'];

        $this->func_data_prepare = ! empty($args['func_data_prepare']) ? $args['func_data_prepare'] : $this->func_data_prepare;
        $this->func_data_get     = ! empty($args['func_data_get']) ? $args['func_data_get'] : $this->func_data_get;
        $this->func_data_total   = ! empty($args['func_data_total']) ? $args['func_data_total'] : $this->func_data_total;

        $this->columns_names  = array_keys($this->columns);
        $this->columns_amount = count($this->columns);

        if ( in_array('cb', $this->columns_names) ) {
            $this->columns_names = array_slice($this->columns_names, 1);
        }
        if ( ! empty($this->sql['add_col']) ) {
            $this->columns_names = array_merge($this->columns_names, $this->sql['add_col']);
        }
        if ( ! empty($this->sql['except_cols']) ) {
            $this->columns_names = array_diff($this->columns_names, $this->sql['except_cols']);
        }

        $this->sortable = ! empty($args['sortable']) ? $args['sortable'] : $this->sortable;
        $this->order_by = ! empty($args['order_by']) ? $args['order_by'] : $this->order_by;

        // END OF SQL shit

        $this->actions      = ! empty($args['actions']) ? $args['actions'] : $this->actions;
        $this->bulk_actions = ! empty($args['bulk_actions']) ? $args['bulk_actions'] : $this->bulk_actions;
    }

    public function getData()
    {
        global $wpdb;

        // Getting total of items
        // by using given function
        if ( $this->func_data_total && function_exists($this->func_data_total) ) {
            $this->items_total = call_user_func_array($this->func_data_total, array());
            // by using direct SQL request
        } else {
            $total             = $wpdb->get_results(
                sprintf(
                    'SELECT COUNT(*) as cnt'
                    . ' FROM %s'
                    . '%s',
                    $this->sql['table'], // TABLE
                    $this->sql['where']  // WHERE
                ),
                OBJECT_K
            );
            $this->items_total = key($total);
        }

        // Getting data
        // by using given function
        if ( $this->func_data_get && function_exists($this->func_data_get) ) {
            $param = array($this->sql['offset'], $this->sql['limit']);
            if ( $this->order_by ) {
                $param[] = current($this->order_by);
            }
            if ( $this->order_by ) {
                $param[] = key($this->order_by);
            }
            $this->rows = call_user_func_array($this->func_data_get, $param);
            // by using direct SQL request
        } else {
            $columns = array();
            foreach ( $this->columns_names as $columns_name ) {
                $columns[] = $this->sql['table'] . '.' . $columns_name;
            }
            $this->rows = $wpdb->get_results(
                sprintf(
                    'SELECT %s'
                    . ' FROM %s'
                    . '%s'
                    . ' ORDER BY %s %s'
                    . ' LIMIT %s%d',
                    implode(', ', $columns),                  // COLUMNS
                    $this->sql['table'],                            // TABLE
                    $this->sql['where'],                            // WHERE
                    key($this->order_by),
                    current($this->order_by), // ORDER BY
                    $this->sql['offset'] . ',',
                    $this->sql['limit']   // LIMIT
                ),
                $this->sql['get_array'] === true ? ARRAY_A : OBJECT
            );
        }

        // Adding actions to each row
        foreach ( $this->rows as &$row ) {
            if ( is_object($row) ) {
                $row->actions = array_flip(array_keys($this->actions));
            }
            if ( is_array($row) ) {
                $row['actions'] = array_flip(array_keys($this->actions));
            }
        }
        unset($row);

        $this->items_count = count((array)$this->rows);

        // Execute given function to prepare data
        if ( $this->func_data_prepare && function_exists($this->func_data_prepare) ) {
            call_user_func_array($this->func_data_prepare, array(&$this));
        } else {
            // Changing $this in function
            $this->preapreDataDefault();
        }
    }

    private function preapreDataDefault()
    {
        if ( $this->items_count ) {
            foreach ( $this->rows as $key => $row ) {
                foreach ( $this->columns as $column_name => $column ) {
                    $this->items[$key][$column_name] = $row->$column_name;
                    if ( isset($column['primary']) ) {
                        $this->items[$key]['uid'] = $row->$column_name;
                    }
                    if ( ! empty($this->actions) ) {
                        $this->items[$key]['actions'] = $this->actions;
                    }
                }
            }
        }
    }

    public function display()
    {
        if ( $this->items_count == 0 ) {
            echo $this->if_empty_items;

            return;
        }

        echo '<div id="' . $this->id . '" type="' . $this->type . '" class="tbl-root">';

        echo $this->html_before;

        $this->displayBulkActionControls();
        $this->displayPaginationControls();

        ?>
        <table class="wp-list-table widefat fixed striped">
            <thead>
            <tr>
                <?php
                $this->displayColumnHeaders(); ?>
            </tr>
            </thead>

            <tbody>
            <?php
            $this->displayRows(); ?>
            </tbody>

            <tfoot>
            <tr>
                <?php
                $this->displayColumnHeaders(); ?>
            </tr>
            </tfoot>

        </table>
        <?php

        echo $this->html_after;

        $this->displayBulkActionControls();
        $this->displayPaginationControls();

        echo '</div>';
    }

    /**
     * Return template for different blocks
     *
     * @return string|boolean
     */
    public function getTemplate()
    {
        if ( $this->items_count == 0 ) {
            return false;
        }

        ob_start();
        echo '<div id="' . $this->id . '" type="' . $this->type . '" class="tbl-root">';

        echo $this->html_before;

        $this->displayBulkActionControls();
        $this->displayPaginationControls();

        ?>
        <table class="wp-list-table widefat fixed striped">
            <thead>
            <tr>
                <?php
                $this->displayColumnHeaders(); ?>
            </tr>
            </thead>

            <tbody>
            <?php
            $this->displayRows(); ?>
            </tbody>

            <tfoot>
            <tr>
                <?php
                $this->displayColumnHeaders(); ?>
            </tr>
            </tfoot>

        </table>
        <?php

        echo $this->html_after;

        $this->displayBulkActionControls();
        $this->displayPaginationControls();

        echo '</div>';

        return ob_get_clean();
    }

    public function displayBulkActionControls()
    {
        if ( ! empty($this->bulk_actions) ) {
            echo '<div class="tbl-bulk_actions--wrapper">';
            echo '<select class="tbl-select">';
            echo "<option value='-1'>Bulk actions</option>";
            foreach ( $this->bulk_actions as $action_key => $action ) {
                echo "<option value='{$action_key}'>{$action['name']}</option>";
            }
            echo '</select>';
            echo '<button type="button" class="tbl-button tbl-button---white_blue tbl-bulk_actions--apply">'
                 . __('Apply to selected')
                 . '<img class="tbl-preloader--small tbl-preloader--in_button" src="' . SPBC_PATH . '/images/preloader2.gif" />'
                 . '</button>';
            echo '<button type="button" class="tbl-button tbl-bulk_actions-all--apply">'
                 . __('Apply to all')
                 . '<img class="tbl-preloader--small tbl-preloader--in_button" src="' . SPBC_PATH . '/images/preloader2.gif" />'
                 . '</button>';
            echo '';
            echo '</div>';
        }
    }

    public function displayPaginationControls()
    {
        if ( ! empty($this->pagination) && $this->items_total > $this->pagination['per_page'] ) {
            $next_page = $this->pagination['page'] + 1 > ceil(
                $this->items_total / $this->pagination['per_page']
            ) ? $this->pagination['page'] : $this->pagination['page'] + 1;
            echo "<div class='tbl-pagination--wrapper'
				prev_page='" . ($this->pagination['page'] - 1 ?: 1) . "'
				next_page='$next_page'
				last_page='" . ceil($this->items_total / $this->pagination['per_page']) . "'
			>";
            echo "<span class='tbl-pagination--total'>{$this->items_total} Entries</span>";
            echo '<button type="button" class="tbl-button tbl-pagination--button tbl-pagination--start"><i class="spbc-icon-to-start"></i></button>';
            echo '<button type="button" class="tbl-button tbl-pagination--button tbl-pagination--prev"><i class="spbc-icon-fast-bw"></i></button>';
            echo "<input type='text' class='tbl-pagination--curr_page' value='{$this->pagination['page']}'/>";
            echo '<span class="tbl-pagination--total"> of ' . ceil($this->items_total / $this->pagination['per_page']) . '</span>';
            echo '<button type="button" class="tbl-button tbl-pagination--button tbl-pagination--go">' . __('Go') . '</button>';
            echo '<button type="button" class="tbl-button tbl-pagination--button tbl-pagination--next"><i class="spbc-icon-fast-fw"></i></button>';
            echo '<button type="button" class="tbl-button tbl-pagination--button tbl-pagination--end"><i class="spbc-icon-to-end"></i></button>';
            echo '<img class="tbl-preloader--small" src="' . SPBC_PATH . '/images/preloader2.gif" />';
            echo '</div>';
        }
    }

    public function displayColumnHeaders()
    {
        foreach ( $this->columns as $column_key => $column ) {
            $tag = ('cb' === $column_key) ? 'td' : 'th';

            $id = $column_key;

            $classes = "manage-column column-$column_key";
            $classes .= isset($column['primary']) ? ' column-primary' : '';
            $classes .= isset($column['class']) ? ' ' . $column['class'] : '';

            // Sorting
            if ( in_array($column_key, $this->sortable) ) {
                $classes .= ' tbl-column-sortable';
                $classes .= isset($this->order_by[$column_key]) ? ' tbl-column-sorted' : '';

                $sort_direction      = isset($this->order_by[$column_key]) && $this->order_by[$column_key] == 'asc' ? 'desc' : 'asc';
                $sort_direction_attr = 'sort_direction="' . $sort_direction . '"';

                $sort_classes = 'tbl-sorting_indicator';
                $sort_classes .= isset($this->order_by[$column_key]) ? ' tbl-sorting_indicator--sorted' : '';
                $sort_classes .= isset($this->order_by[$column_key]) ? ' spbc-icon-sort-alt-' . ($sort_direction == 'desc' ? 'up' : 'down') : ' spbc-icon-sort-alt-down';

                $sortable = "<i class='$sort_classes'></i>";
            } else {
                $sortable            = '';
                $sort_direction_attr = '';
            }

            $hint = isset($column['hint']) ? '<i class="spbc_hint--icon spbc-icon-help-circled"></i><span class="spbc_hint--text">' . $column['hint'] . '</span>' : '';

            // Out
            echo "<$tag id='$id' class='$classes' $sort_direction_attr>{$column['heading']}$sortable$hint</$tag>";
        }
        unset($column_key);
    }

    public function displayRows($return = false)
    {
        $out = '';

        foreach ( $this->items as $item ) {
            $item = (array)$item;

            $out .= '<tr>';

            foreach ( $this->columns as $column_key => $column ) {
                $classes = "$column_key column-$column_key";
                $classes .= isset($column['primary']) ? ' column-primary' : '';
                $classes .= isset($column['class']) ? ' ' . $column['class'] : '';

                if ( 'cb' === $column_key ) {
                    $out .= '<th scope="row" class="check-column">';
                    $out .= $this->displayColumnCb($item['cb']);
                    $out .= '</th>';
                } elseif ( method_exists($this, 'display__column_' . $column['heading']) ) {
                    $out .= call_user_func(
                        array($this, '_column_' . $column['heading']),
                        $item,
                        $classes
                    );
                } else {
                    $out .= "<td class='$classes'>";

                    $out .= isset($item[$column_key]) ? $item[$column_key] : '-';
                    $out .= isset($column['primary'])
                        ? '<button type="button" class="toggle-row"><span class="screen-reader-text">' . __(
                            'Show more details'
                        ) . '</span></button>'
                        : '';
                    if ( isset($column['primary']) && ! empty($this->actions) && ! empty($item['uid']) ) {
                        $out .= $this->displayRowActions($item['uid'], $item);
                    }


                    $out .= '</td>';
                }
            }
            unset($column_key, $column['heading']);

            $out .= '</tr>';
        }
        unset($item);

        if ( $return ) {
            return $out;
        }

        echo $out;
    }

    public function displayColumnCb($id)
    {
        return '<input type="checkbox" name="item[]" class="cb-select" id="cb-select-' . $id . '" value="' . $id . '" />';
    }

    public function displayRowActions($uid, $item)
    {
        $home_url = get_option('home') . '/';
        $out      = "<div class='row-actions' uid='{$uid}' cols_amount='{$this->columns_amount}'>";

        foreach ( $this->actions as $action_key => $action ) {
            if ( ! isset($item['actions'][$action_key]) ) {
                continue;
            }

            if ( isset($action['type']) && $action['type'] == 'link' ) {
                $href   = ! empty($action['local']) && isset($action['href']) && ! empty($action['href']) ? $home_url . $action['href'] : @$action['href'];
                $href   .= ! empty($action['uid']) ? $uid : '';
                $href   .= ! empty($action['edit_post_link']) ? preg_match(
                    '/=(\d+)$/',
                    $item['page_url'],
                    $matches
                ) ? "post.php?post=$matches[1]&action=edit" : '' : '';
                $target = ! empty($action['target']) ? $action['target'] : '_self';
                $out    .= "<a href='$href' target='$target'>{$action['name']}</a> | ";
            } else {
                $classes = "tbl-row_action tbl-row_action--{$action_key}" . (! isset($action['handler']) ? ' tbl-row_action--ajax' : '');
                $handler = isset($action['handler']) ? " onclick='{$action['handler']}'" : " row-action='{$action_key}'";
                $out     .= "<span class='$classes' $handler>{$action['name']}</span> | ";
            }
        }
        $out = trim($out, '|');
        $out = isset($classes) ? substr($out, 0, -3) : $out;
        $out .= '</div>';
        $out .= '<img class="tbl-preloader--tiny" src="' . SPBC_PATH . '/images/preloader2.gif" />';

        return $out;
    }

    public static function ajaxBulkActionHandler()
    {
        check_ajax_referer('spbc_secret_nonce', 'security');

        $ids = spbc_scanner_get_files_by_category(Post::get('status', null, 'word'));

        switch ( Post::get('add_action', null, 'word') ) {
            case 'approve':
                $out = spbc_scanner_file_approve__bulk($ids);
                break;
            case 'disapprove':
                $out = spbc_scanner_file_disapprove__bulk($ids);
                break;
            case 'send':
                $out = spbc_scanner_file_send_for_analysis__bulk($ids);
                break;
            case 'check_analysis_status':
                $out = spbc_scanner_pscan_check_analysis_status(true, $ids);
                break;
            default:
                wp_send_json(array('error' => 'UNKNOWN ACTION'));
        }

        if ( isset($out['error'], $out['error_detail']) ) {
            $out['error_comment'] = '';
            foreach ( $out['error_detail'] as $error_detail ) {
                $out['error_comment'] .= 'File path: ' . $error_detail['file_path'] . ' Error: ' . $error_detail['error'] . '<br>';
            }
        }

        wp_send_json($out);
    }

    public static function ajaxRowActionHandler()
    {
        check_ajax_referer('spbc_secret_nonce', 'security');

        switch ( Post::get('add_action', null, 'word') ) {
            case 'approve':
                self::ajaxRowActionHandlerApprove();
                break;
            case 'disapprove':
                self::ajaxRowActionHandlerDisapprove();
                break;
            case 'delete':
                self::ajaxRowActionHandlerDelete();
                break;
            case 'replace':
                self::ajaxRowActionHandlerReplace();
                break;
            case 'send':
                self::ajaxRowActionHandlerSend();
                break;
            case 'quarantine':
                self::ajaxRowActionHandlerQuarantine();
                break;
            case 'restore':
                self::ajaxRowActionHandlerQuarantineRestore();
                break;
            case 'download':
                self::ajaxRowActionHandlerDownload();
                break;
            case 'check_analysis_status':
                self::ajaxRowActionHandlerCheckAnalysisStatus();
                break;
            case 'copy_file_info':
                self::ajaxRowActionHandlerCopyFileInfo();
                break;
            default:
                wp_send_json(array('temp_html' => '<div class="spbc-popup-msg popup--red">UNKNOWN ACTION</div>'));
        }
    }

    public static function ajaxRowActionHandlerApprove()
    {
        $out = spbc_scanner_file_approve(true, Post::get('id', null, 'word'));

        if ( empty($out['error']) ) {
            $out = array(
                'html'              => '<div class="spbc-popup-msg popup--green">'
                                       . __('File has been approved.', 'security-malware-firewall')
                                       . '</div>',
                'success'           => true,
                'color'             => 'black',
                'background'        => 'rgba(110, 240, 110, 0.7)',
                'original_response' => $out,
            );
        }

        wp_send_json($out);
    }

    public static function ajaxRowActionHandlerDisapprove()
    {
        $out = spbc_scanner_file_disapprove(true, Post::get('id', null, 'word'));

        if ( empty($out['error']) ) {
            $out = array(
                'html'       => '<div class="spbc-popup-msg popup--red">'
                                . __('File has been disapproved.', 'security-malware-firewall')
                                . '</div>',
                'success'    => true,
                'color'      => 'black',
                'background' => 'rgba(240, 110, 110, 0.7)',
            );
        }

        wp_send_json($out);
    }

    public static function ajaxRowActionHandlerDelete()
    {
        $out = spbc_scanner_file_delete(true, Post::get('id', null, 'word'));

        if ( empty($out['error']) ) {
            $out = array(
                'html'       => '<div class="spbc-popup-msg popup--red">'
                                . __('File has been deleted.', 'security-malware-firewall')
                                . '</div>',
                'success'    => true,
                'color'      => 'black',
                'background' => 'rgba(240, 110, 110, 0.7)',
            );
        }

        wp_send_json($out);
    }

    public static function ajaxRowActionHandlerReplace()
    {
        $out = spbc_scanner_file_replace(true, Post::get('id', null, 'word'));

        if ( empty($out['error']) ) {
            $out = array(
                'html'       => '<div class="spbc-popup-msg popup--green">'
                                . __('File has been replaced.', 'security-malware-firewall')
                                . '</div>',
                'success'    => true,
                'color'      => 'black',
                'background' => 'rgba(240, 110, 110, 0.7)',
            );
        }

        wp_send_json($out);
    }

    public static function ajaxRowActionHandlerSend()
    {
        $file_fast_hash = Post::get('id', null, 'word');
        $out = spbc_scanner_file_send(true, $file_fast_hash);

        if ( empty($out['error']) ) {
            $args  = spbc_list_table__get_args_by_type('analysis_log');
            $table = new ListTable($args);
            $table->getData();
            $file_info_from_scan_results_table = $table->getTemplate();

            $out = array(
                'html'  => '<div class="spbc-popup-msg popup--green">'
                                . __('Thank you! We will check the file(s).', 'security-malware-firewall')
                                . '</div>',
                'success'    => true,
                'color'      => 'black',
                'background' => 'rgba(110, 110, 240, 0.7)',
            );

            if ($file_info_from_scan_results_table) {
                $out['updated_template'] = $file_info_from_scan_results_table;
                $out['updated_template_type'] = 'analysis_log';
            }
        }

        wp_send_json($out);
    }

    public static function ajaxRowActionHandlerQuarantine()
    {
        $out = spbc_scanner_file_quarantine(true, Post::get('id', null, 'word'));

        if ( empty($out['error']) ) {
            $out = array(
                'html'       => '<div class="spbc-popup-msg popup--red">'
                                . __('File has been put into a corner.', 'security-malware-firewall')
                                . '</div>',
                'success'    => true,
                'color'      => 'black',
                'background' => 'rgba(110, 110, 240, 0.7)',
            );
        }

        wp_send_json($out);
    }

    public static function ajaxRowActionHandlerQuarantineRestore()
    {
        $out = spbc_scanner_file_quarantine__restore(true, Post::get('id', null, 'word'));

        if ( empty($out['error']) ) {
            $out = array(
                'html'       => '<div class="spbc-popup-msg popup--green">'
                                . __('File has been restored.', 'security-malware-firewall')
                                . '</div>',
                'success'    => true,
                'color'      => 'black',
                'background' => 'rgba(110, 110, 240, 0.7)',
            );
        }

        wp_send_json($out);
    }

    private static function ajaxRowActionHandlerDownload()
    {
        //@ToDo NOT IMPLEMENTED YET
    }

    public static function ajaxRowActionHandlerCheckAnalysisStatus()
    {
        $out = spbc_scanner_pscan_check_analysis_status(true, Post::get('id', null, 'word'));

        if ( empty($out['error']) ) {
            $out = array(
                'html'  => '<div class="spbc-popup-msg popup--green">'
                                . __(
                                    'Status checked and update successfully. Please, refresh the page to see the result.',
                                    'security-malware-firewall'
                                )
                                . '</div>',
                'success'    => true,
                'color'      => 'black',
                'background' => 'rgba(110, 110, 240, 0.7)',
            );
        }

        wp_send_json($out);
    }

    public static function ajaxPaginationHandler()
    {
        check_ajax_referer('spbc_secret_nonce', 'security');

        $type                       = Post::get('type', 'word');
        $args                       = spbc_list_table__get_args_by_type($type);
        $args['pagination']['page'] = Post::get('page', 'int', null);
        $table                      = new ListTable($args);
        $table->getData();
        $table->display();

        die();
    }

    public static function ajaxSortHandler()
    {
        check_ajax_referer('spbc_secret_nonce', 'security');

        $type             = Post::get('type', 'word');
        $order_by         = Post::get('order_by', null, 'word');
        $order            = Post::get('order', null, 'word');
        $args             = spbc_list_table__get_args_by_type($type);
        $args['order_by'] = array((string)$order_by => $order);
        $table            = new ListTable($args);
        $table->getData();
        $table->display();

        die();
    }

    public static function ajaxSwitchTable()
    {
        check_ajax_referer('spbc_secret_nonce', 'security');

        $type  = Post::get('type', 'word');
        $args  = spbc_list_table__get_args_by_type($type);
        $table = new ListTable($args);
        $table->getData();
        $table->display();

        die();
    }

    /**
     * @param $arr
     *
     * @return mixed
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function stripslashesArray($arr)
    {
        foreach ( $arr as $_key => &$value ) {
            if ( is_string($value) ) {
                $value = stripslashes($value);
            } elseif ( is_array($value) ) {
                $value = self::stripslashesArray($value);
            }
        }
        unset($value);

        return $arr;
    }

    /**
     * Output JSON with pscan_file_id got by file_id(fast_hash)
     * @return void
     *
     */
    public static function ajaxRowActionHandlerCopyFileInfo()
    {
        $file_id = Post::get('id', null, 'word');
        if ( !empty($file_id) ) {
            $file_info = spbc_scanner_get_file_by_id($file_id);
            $file_info = array(
                $file_id => array(
                    'path'              => !empty($file_info['path']) ? urlencode($file_info['path']) : null,
                    'full_hash'         => !empty($file_info['full_hash']) ? $file_info['full_hash'] : null,
                    'real_full_hash'    => !empty($file_info['real_full_hash']) ? $file_info['real_full_hash'] : null,
                    'pscan_file_id'     => !empty($file_info['pscan_file_id']) ? $file_info['pscan_file_id'] : null,
                    'pscan_status' => !empty($file_info['pscan_status']) ? $file_info['pscan_status'] : null,
                    'last_sent'         => !empty($file_info['last_sent']) ? $file_info['last_sent'] : null,
                )
            );
            $file_info = json_encode($file_info);

            if ( $file_info !== false ) {
                $file_info = array ('file_info' => $file_info);
                wp_send_json_success($file_info);
            }
        }
        wp_send_json_error(array('error' => 'Can not get file info.'));
    }
}
