<?php

namespace CleantalkSP\SpbctWP;

use CleantalkSP\Variables\Post;

class ListTable
{
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
	public $func_data_get     = null; // Function to receive data
	public $func_data_total   = null; // Function to get total items
	
	// ROWS
	public $items = array(); // Items to output
	public $items_count = 0; // Amount to output
	public $items_total = 0; // Amount total
	
	// COLS
	public $columns = array();
	
	// Misc
	public $sortable = array();     // Sortable columns
	public $order_by = array();     // Current sorting
	public $actions = array();      // Row actions
	public $bulk_actions = array(); // Bulk actions
	
	// HTML output
	public $html_before    = ''; // HTML before table
	public $html_after     = ''; // HTML after table
	public $if_empty_items = 'No data given.'; // HTML message
    
    function __construct($args = array()){
		
		$this->args = json_encode($args);
    
        $this->id   = ! empty( $args['id'] )   ? $args['id']   : 'table_' . rand( 0, 10000 );
        $this->type = ! empty( $args['type'] ) ? $args['type'] : 'unknown';
		
		$this->items   = !empty($args['items'])   ? $args['items']   : $this->items;
		$this->columns = !empty($args['columns']) ? $args['columns'] : $this->columns;
		
		$this->items_count = count((array)$this->items);
		$this->items_total = count((array)$this->items);
		
		// HTML output
		$this->html_before = !empty($args['html_before']) ? $args['html_before'] : $this->html_before;
		$this->html_after  = !empty($args['html_after'])  ? $args['html_after']  : $this->html_after;
		$this->if_empty_items = !empty($args['if_empty_items']) ? $args['if_empty_items'] : $this->if_empty_items;
		
		if(isset($args['pagination']['page']))    $this->pagination['page']     = $args['pagination']['page'];
		if(isset($args['pagination']['per_page']))$this->pagination['per_page'] = $args['pagination']['per_page'];
		
		// SQL shit
		
			if(!empty($args['sql'])){
				$this->sql['add_col']     = !empty($args['sql']['add_col'])     ? $args['sql']['add_col']     : $this->sql['add_col'];
				$this->sql['except_cols'] = !empty($args['sql']['except_cols']) ? $args['sql']['except_cols'] : $this->sql['except_cols'];
				$this->sql['table']       = !empty($args['sql']['table'])       ? $args['sql']['table']       : $this->sql['table'];
				$this->sql['where']       = !empty($args['sql']['where'])       ? $args['sql']['where']       : $this->sql['where'];
				$this->sql['group_by']    = !empty($args['sql']['group_by'])    ? $args['sql']['group_by']    : $this->sql['group_by'];
				$this->sql['offset']      = !empty($args['sql']['offset'])      ? $args['sql']['offset']      : $this->sql['offset'];
				$this->sql['limit']       = !empty($args['sql']['limit'])       ? $args['sql']['limit']       : $this->sql['limit'];
				$this->sql['get_array']   = !empty($args['sql']['get_array'])   ? $args['sql']['get_array']   : $this->sql['get_array'];
			}
			
			$this->sql['offset'] = isset($this->pagination['page']) ? ($this->pagination['page']-1)*$this->pagination['per_page'] : $this->sql['offset'];
			$this->sql['limit']  = isset($this->pagination['per_page']) ? $this->pagination['per_page'] : $this->sql['limit'];
			
			$this->func_data_prepare = !empty($args['func_data_prepare']) ? $args['func_data_prepare'] : $this->func_data_prepare;
			$this->func_data_get     = !empty($args['func_data_get'])     ? $args['func_data_get']     : $this->func_data_get;
			$this->func_data_total   = !empty($args['func_data_total'])   ? $args['func_data_total']   : $this->func_data_total;
			
			$this->columns_names  = array_keys($this->columns);
			$this->columns_amount = count($this->columns);
			
			if(in_array('cb', $this->columns_names)) $this->columns_names = array_slice($this->columns_names, 1);
			if(!empty($this->sql['add_col']))        $this->columns_names = array_merge($this->columns_names, $this->sql['add_col']);
			if(!empty($this->sql['except_cols']))     $this->columns_names = array_diff( $this->columns_names, $this->sql['except_cols']);
			
			$this->sortable = !empty($args['sortable']) ? $args['sortable'] : $this->sortable;
			$this->order_by = !empty($args['order_by']) ? $args['order_by'] : $this->order_by;
			
		// END OF SQL shit
		
		$this->actions      = !empty($args['actions'])      ? $args['actions']      : $this->actions;
		$this->bulk_actions = !empty($args['bulk_actions']) ? $args['bulk_actions'] : $this->bulk_actions;
		
	}
	
	public function get_data(){
		
		global $wpdb;
		
		// Getting total of items
		// by using given function
		if($this->func_data_total && function_exists($this->func_data_total)){
			$this->items_total = call_user_func_array($this->func_data_total, array());			
		// by using direct SQL request
		}else{
			$total = $wpdb->get_results(
				sprintf(
					'SELECT COUNT(*) as cnt'
						.' FROM %s'
						.'%s',
					$this->sql['table'], // TABLE
					$this->sql['where']  // WHERE
				),
				OBJECT_K
			);
			$this->items_total = key($total);			
		}
		
		// Getting data
		// by using given function
		if($this->func_data_get && function_exists($this->func_data_get)){
			$param = array($this->sql['offset'], $this->sql['limit']);
			if($this->order_by) $param[] = current($this->order_by);
			if($this->order_by) $param[] = key($this->order_by);
			$this->rows = call_user_func_array($this->func_data_get, $param);
		// by using direct SQL request
		}else{
		    $columns = array();
		    foreach ( $this->columns_names as $columns_name ) {
			    $columns[] = $this->sql['table'] . '.' . $columns_name;
            }
			$this->rows = $wpdb->get_results(
				sprintf(
					'SELECT %s'
						.' FROM %s'
						.'%s'
						.' ORDER BY %s %s'
						.' LIMIT %s%d',
					implode(', ', $columns),                  // COLUMNS
					$this->sql['table'],                            // TABLE
					$this->sql['where'],                            // WHERE
					key($this->order_by), current($this->order_by), // ORDER BY
					$this->sql['offset'].',', $this->sql['limit']   // LIMIT	
				),
				$this->sql['get_array'] === true ? ARRAY_A : OBJECT
			);
		}
		
		// Adding actions to each row 
		foreach($this->rows as &$row){
			if(is_object($row)) $row->actions   = array_flip(array_keys($this->actions));
			if(is_array($row))  $row['actions'] = array_flip(array_keys($this->actions));
		} unset($row);
		
		$this->items_count = count((array)$this->rows);
		
		// Execute given function to prepare data
		if($this->func_data_prepare && function_exists($this->func_data_prepare))
			call_user_func_array($this->func_data_prepare, array(&$this)); // Changing $this in function
		else{
			$this->preapre_data__default();
		}
		
	}
	
	private function preapre_data__default(){
		if($this->items_count){
			foreach($this->rows as $key => $row){
				foreach($this->columns as $column_name => $column){
					$this->items[$key][$column_name] = $row->$column_name;
					if(isset($column['primary']))
						$this->items[$key]['uid'] = $row->$column_name;
					if(!empty($this->actions))
						$this->items[$key]['actions'] = $this->actions;
				}
			}
		}
	}
	
	public function display()
	{
		if($this->items_count == 0){
			echo $this->if_empty_items;
			return;
		}
		
		echo '<form method="post" id="'.$this->id.'" type="' . $this->type. '" class="tbl-root">';
			
			echo $this->html_before;
			
			echo "<script>/*<![CDATA[*/var args_{$this->id} = {$this->args};/*]]>*/</script>";
			
			$this->display__bulk_action_controls();
			$this->display__pagination_controls();
			
			?>
				<table class="wp-list-table widefat fixed striped">
					<thead>
					<tr>
						<?php $this->display__column_headers(); ?>
					</tr>
					</thead>

					<tbody>
						<?php $this->display__rows(); ?>
					</tbody>

					<tfoot>
					<tr>
						<?php $this->display__column_headers(); ?>
					</tr>
					</tfoot>

				</table>
			<?php
		
		echo $this->html_after;
		
		$this->display__bulk_action_controls();
		$this->display__pagination_controls();
		
		echo '</form>';
		
	}
	
	public function display__bulk_action_controls()
	{
		if(!empty($this->bulk_actions)){
			echo '<div class="tbl-bulk_actions--wrapper">';
				echo '<select class="tbl-select">';
                echo "<option value='-1'>Bulk actions</option>";
				foreach($this->bulk_actions as $action_key => $action){
					echo "<option value='{$action_key}'>{$action['name']}</option>";
				}
				echo '</select>';
				echo '<button type="button" class="tbl-button tbl-button---white_blue tbl-bulk_actions--apply">'
                     .__('Apply to selected')
                     .'<img class="tbl-preloader--small tbl-preloader--in_button" src="' . SPBC_PATH . '/images/preloader2.gif" />'
                    .'</button>';
				echo '<button type="button" class="tbl-button tbl-bulk_actions-all--apply">'
                     .__('Apply to all')
                     .'<img class="tbl-preloader--small tbl-preloader--in_button" src="' . SPBC_PATH . '/images/preloader2.gif" />'
                     .'</button>';
				echo '';
			echo '</div>';
		}
	}
	
	public function display__pagination_controls()
	{
		if(!empty($this->pagination) && $this->items_total > $this->pagination['per_page']){
			$next_page = $this->pagination['page']+1>ceil($this->items_total / $this->pagination['per_page']) ? $this->pagination['page']: $this->pagination['page']+1;
			echo "<div class='tbl-pagination--wrapper'
				prev_page='".($this->pagination['page']-1?$this->pagination['page']-1:1)."'
				next_page='$next_page'
				last_page='".ceil($this->items_total / $this->pagination['per_page'])."'
			>";
				echo "<span class='tbl-pagination--total'>{$this->items_total} Entries</span>";
				echo '<button type="button" class="tbl-button tbl-pagination--button tbl-pagination--start"><i class="spbc-icon-to-start"></i></button>';
				echo '<button type="button" class="tbl-button tbl-pagination--button tbl-pagination--prev"><i class="spbc-icon-fast-bw"></i></button>';
				echo "<input type='text' class='tbl-pagination--curr_page' value='{$this->pagination['page']}'/>";
				echo '<span class="tbl-pagination--total"> of '.ceil($this->items_total / $this->pagination['per_page']).'</span>';
				echo '<button type="button" class="tbl-button tbl-pagination--button tbl-pagination--go">'.__('Go').'</button>';
				echo '<button type="button" class="tbl-button tbl-pagination--button tbl-pagination--next"><i class="spbc-icon-fast-fw"></i></button>';
				echo '<button type="button" class="tbl-button tbl-pagination--button tbl-pagination--end"><i class="spbc-icon-to-end"></i></button>';
				echo '<img class="tbl-preloader--small" src="' . SPBC_PATH . '/images/preloader2.gif" />';
			echo '</div>';
		}
	}
	
	public function display__column_headers(){
		
		foreach($this->columns as $column_key => $column){
			
			$tag = ( 'cb' === $column_key ) ? 'td' : 'th';
			
			$id = $column_key;
			
			$classes  = "manage-column column-$column_key";
			$classes .= isset($column['primary']) ? ' column-primary' : '';
			$classes .= isset($column['class'])   ? ' '.$column['class'] : '';
			
			// Sorting
			if(in_array($column_key, $this->sortable)){
				
				$classes .= ' tbl-column-sortable';
				$classes .= isset($this->order_by[$column_key]) ? ' tbl-column-sorted' : '';
				
				$sort_direction = isset($this->order_by[$column_key]) && $this->order_by[$column_key] == 'asc' ? 'desc' :  'asc';
				$sort_direction_attr = 'sort_direction="'.$sort_direction.'"';
				
				$sort_classes = 'tbl-sorting_indicator';
				$sort_classes .=  isset($this->order_by[$column_key]) ? ' tbl-sorting_indicator--sorted' : '';
				$sort_classes .=  isset($this->order_by[$column_key]) ? ' spbc-icon-sort-alt-'.($sort_direction == 'desc' ? 'up' : 'down') : ' spbc-icon-sort-alt-down';
				
				$sortable = "<i class='$sort_classes'></i>";
				
			}else{
				$sortable = '';
				$sort_direction_attr = '';
			}
			
			$hint = isset($column['hint']) ? '<i class="spbc_hint--icon spbc-icon-help-circled"></i><span class="spbc_hint--text">'.$column['hint'].'</span>' : '';
			
			// Out
			echo "<$tag id='$id' class='$classes' $sort_direction_attr>{$column['heading']}$sortable$hint</$tag>";
			
		} unset($column_key, $column_name);
		
	}
	
	public function display__rows($return = false)
	{
		$out = '';
		
		foreach($this->items as $item){
			
			$item = (array)$item;
			
			$out .= '<tr>';
			
			foreach($this->columns as $column_key => $column){
								
				$classes  = "$column_key column-$column_key";
				$classes .= isset($column['primary']) ? ' column-primary'    : '';
				$classes .= isset($column['class'])   ? ' '.$column['class'] : '';
				
				if ( 'cb' === $column_key ) {
					$out .= '<th scope="row" class="check-column">';
					$out .= $this->display__column_cb($item['cb']);
					$out .= '</th>';
				}elseif ( method_exists( $this, 'display__column_' . $column['heading'] ) ) {
					$out .= call_user_func(
						array( $this, '_column_' . $column['heading'] ),
						$item,
						$classes
					);
				}else{
					$out .= "<td class='$classes'>";
					
						$out .= isset($item[$column_key]) ? $item[$column_key] : 'Unknown';
						$out .= isset($column['primary'])
							? '<button type="button" class="toggle-row"><span class="screen-reader-text">'.__( 'Show more details' ).'</span></button>' 
							: '';
						if(isset($column['primary']) && !empty($this->actions) && !empty($item['uid']))
							$out .= $this->display__row_actions($item['uid'], $item);

						
					$out .= '</td>';
				}
				
				
			} unset($column_key, $column['heading']);
			
			$out .= '</tr>';
			
		} unset($item);
		
		if($return) return $out; else echo $out; 
	}
	
	function display__column_cb($id)
	{
		return  '<input type="checkbox" name="item[]" class="cb-select" id="cb-select-'. $id .'" value="'. $id .'" />';
	}
	
	public function display__row_actions($uid, $item)
	{
		$home_url = get_option('home').'/';
		$out = "<div class='row-actions' uid='{$uid}' cols_amount='{$this->columns_amount}'>";
		
			foreach($this->actions as $action_key => $action){
			 
				if(!isset($item['actions'][$action_key])) continue;
				
				if(isset($action['type']) && $action['type'] == 'link'){
					$href    = !empty($action['local']) && isset($action['href']) && !empty($action['href'])   ? $home_url.$action['href'] : @$action['href'];
					$href   .= !empty($action['uid'])    ? $uid                      : '';
					$href   .= !empty($action['edit_post_link']) ? preg_match('/=(\d+)$/', $item['page_url'], $matches) ? "post.php?post=$matches[1]&action=edit" : '' : '';
					$target  = !empty($action['target']) ? $action['target']         : '_self';
					$out    .= "<a href='$href' target='$target'>{$action['name']}</a> | ";
				}else{
					$classes = "tbl-row_action tbl-row_action--{$action_key}" . (!isset($action['handler']) ? ' tbl-row_action--ajax' : '');
					$handler = isset($action['handler']) ? " onclick='{$action['handler']}'" : " row-action='{$action_key}'";
					$out .= "<span class='$classes' $handler>{$action['name']}</span> | ";
				}
			}
			$out = isset($classes) ? substr($out, 0, -3) : $out;
		$out .= '</div>';
		$out .= '<img class="tbl-preloader--tiny" src="' . SPBC_PATH . '/images/preloader2.gif" />';
		return $out;
	}
	
	public static function ajax__bulk_action_handler(){
	 
		check_ajax_referer('spbc_secret_nonce', 'security');
		
        switch(Post::get('add_action')){
            case 'approve':    self::ajax__bulk_action_handler___approve(); break;
            case 'disapprove': self::ajax__bulk_action_handler___disapprove(); break;
            default: die(json_encode(array('error' => 'UNKNOWN ACTION')));  break;
        }
		
    }
    
    public static function ajax__bulk_action_handler___approve()
    {
        $ids = spbc_scanner_get_files_by_status( Post::get( 'status' ) );
        $result = spbc_scanner_file_approve__bulk( $ids );
        
        if(empty($result['error'])){
            $out = array(
                'success' => true,
                'original_response' => $result,
            );
        }else
            $out = $result;
        
        die( json_encode( $out ) );
    }
    
    public static function ajax__bulk_action_handler___disapprove()
    {
        $ids = spbc_scanner_get_files_by_status( Post::get( 'status' ) );
        $result = spbc_scanner_file_disapprove__bulk( $ids );
        
        if(empty($result['error'])){
            $out = array(
                'success' => true,
                'original_response' => $result,
            );
        }else
            $out = $result;
        
        die( json_encode( $out ) );
    }
    
	public static function ajax__row_action_handler(){
		
		check_ajax_referer('spbc_secret_nonce', 'security');
		
		// Executing given function
		if( Post::get('function') ){
			
			if( Post::get('class') && class_exists(Post::get('class')) && method_exists(Post::get('class'), Post::get('function')))
				$function_to_call = Post::get('class').'::'.Post::get('function');
			
			if(function_exists(Post::get('function')))
				$function_to_call = Post::get('function');
			
			if(!empty($function_to_call))
				call_user_func($function_to_call);
		
		// Executing predefined table action
		}else{
			$colspan = Post::get('cols') ? "colspan='" . Post::get('cols') . "'" : '';
			switch(Post::get('add_action')){
				case 'approve':    self::ajax__row_action_handler___approve();                       break;
				case 'disapprove': self::ajax__row_action_handler___disapprove();                    break;
				case 'delete':     self::ajax__row_action_handler___delete();                        break;
				case 'replace':    self::ajax__row_action_handler___replace();                       break;
				case 'send':       self::ajax__row_action_handler___send();                          break;
				case 'quarantine': self::ajax__row_action_handler___quarantine();                    break;
				case 'restore':    self::ajax__row_action_handler___quarantine_restore();            break;
				case 'download':   self::ajax__row_action_handler___download();                      break;
				default: die(json_encode(array('temp_html' => "<td $colspan>UNKNOWN ACTION</td>"))); break;
			}
		}
	}
	
	public static function ajax__row_action_handler___approve()
	{
		$result = spbc_scanner_file_approve(true, Post::get('id'));
		if(empty($result['error'])){
			$colspan = Post::get('cols') ? "colspan='" . Post::get('cols') . "'" : '';
			$out = array(
				'html' => "<td $colspan>File approved</td>",
				'success' => true,
				'color' => 'black',
				'background' => 'rgba(110, 240, 110, 0.7)',
                'original_response' => $result,
			);
		}else
			$out = $result;
		die(json_encode($out));
	}
	
	public static function ajax__row_action_handler___disapprove()
	{
		$result = spbc_scanner_file_disapprove(true, Post::get('id'));
		if(empty($result['error'])){
			$colspan = Post::get('cols') ? "colspan='" . Post::get('cols') . "'" : '';
			$out = array(
				'html' => "<td $colspan>File disapproved</td>",
				'success' => true,
				'color' => 'black',
				'background' => 'rgba(240, 110, 110, 0.7)',
			);
		}else
			$out = $result;
		die(json_encode($out));
	}
	
	public static function ajax__row_action_handler___delete()
	{
		$result = spbc_scanner_file_delete(true, Post::get('id'));
		if(empty($result['error'])){
			$colspan = Post::get('cols') ? "colspan='" . Post::get('cols') . "'" : '';
			$out = array(
				'html' => "<td $colspan>File deleted</td>",
				'success' => true,
				'color' => 'black',
				'background' => 'rgba(240, 110, 110, 0.7)',
			);
		}else
			$out = $result;
		die(json_encode($out));
	}
	
	public static function ajax__row_action_handler___replace()
	{
		$result = spbc_scanner_file_replace(true, Post::get('id'));
		if(empty($result['error'])){
			$colspan = Post::get('cols') ? "colspan='" . Post::get('cols') . "'" : '';
			$out = array(
				'html' => "<td $colspan>File replaced.</td>",
				'success' => true,
				'color' => 'black',
				'background' => 'rgba(240, 110, 110, 0.7)',
			);
		}else
			$out = $result;
		die(json_encode($out));
	}
	
	public static function ajax__row_action_handler___send()
	{
		$result = spbc_scanner_file_send(true, Post::get('id'));
		if(empty($result['error'])){
			$colspan = Post::get('cols') ? "colspan='" . Post::get('cols') . "'" : '';
			$out = array(
				'temp_html' => "<td $colspan>" . __('Thank you! We will check the file(s).', 'security-malware-firewall') . '</td>',
				'success' => true,
				'color' => 'black',
				'background' => 'rgba(110, 110, 240, 0.7)',
			);
		}else
			$out = $result;
		die(json_encode($out));
	}
	
	public static function ajax__row_action_handler___quarantine()
	{
		$result = spbc_scanner_file_quarantine(true, Post::get('id'));
		if(empty($result['error'])){
			$colspan = Post::get('cols') ? "colspan='" . Post::get('cols') . "'" : '';
			$out = array(
				'html' => "<td $colspan>File been put into a corner.</td>",
				'temp_html' => "<td $colspan>File has been moved to quarantine. You can restore it in quarantine table.</td>",
				'success' => true,
				'color' => 'black',
				'background' => 'rgba(110, 110, 240, 0.7)',
			);
		}else
			$out = $result;
		die(json_encode($out));
	}
	
	public static function ajax__row_action_handler___quarantine_restore()
	{
		$result = spbc_scanner_file_quarantine__restore(true, Post::get('id'));
		if(empty($result['error'])){
			$colspan = Post::get('cols') ? "colspan='" . Post::get('cols') . "'" : '';
			$out = array(
				'html' => "<td $colspan>File been restored.</td>",
				'temp_html' => "<td $colspan>File has been restored.</td>",
				'success' => true,
				'color' => 'black',
				'background' => 'rgba(110, 110, 240, 0.7)',
			);
		}else
			$out = $result;
		die(json_encode($out));
	}
	
	public static function ajax__pagination_handler()
	{
		check_ajax_referer('spbc_secret_nonce', 'security');
		$page = intval(Post::get('page'));
		$args = self::stripslashes__array(Post::get('args'));
		$args['pagination']['page'] = $page;
		$table = new ListTable($args);
		$table->get_data();
		$table->display();
		die();
	}
	
	public static function ajax__sort_handler()
	{
		check_ajax_referer('spbc_secret_nonce', 'security');
		$order_by = substr(Post::get('order_by'), 0, 15);
		$order = Post::get('order') == 'desc' ? 'desc' : 'asc';
		$args = self::stripslashes__array(Post::get('args'));
		$args['order_by'] = array($order_by => $order);
		$table = new ListTable($args);
		$table->get_data();
		$table->display();
		die();
	}
	
	public static function ajax__switch_table()
	{
		check_ajax_referer('spbc_secret_nonce', 'security');
		switch(Post::get('table')){
			case 'domains':
				$args = array(	
					'id' => 'spbc_tbl__scanner__outbound_links',
					'actions' => array(
						'edit_post' => array(
							'name'   => 'Edit',
							'type'   => 'link',
							'local'  => true,
							'edit_post_link' => true,
							'target' => '_blank',
						),
						'show_links' => array(
							'name' => 'Show links',
							'handler' => 'spbc_scanner__switch_table(this, "links");'
						),
					),
					'order_by'  => array('spam_active' => 'desc'),
					'func_data_total'   => 'spbc_scanner_links_count_found__domains',
					'func_data_get'     => 'spbc_scanner_links_get_scanned__domains',
					'func_data_prepare' => 'spbc_field_scanner__prepare_data__domains',
					'if_empty_items' => '<p class="spbc_hint">'.__('No links are found', 'security-malware-firewall').'</p>',
					'columns' => array(
						'num'         => array('heading' => __('Number', 'security-malware-firewall'), 'class' => ' tbl-width--50px'),
						'domain'      => array('heading' => __('Domain', 'security-malware-firewall'), 'primary' => true,),
						'spam_active' => array(
							'heading' => __('Spam-active', 'security-malware-firewall'),
							'hint' => __('Does link spotted in spam?', 'security-malware-firewall'),),
						'link_count'  => array(
							'heading' => __('Links of domain', 'security-malware-firewall'),
							'hint' => __('Number of found links to the domain on site.', 'security-malware-firewall'),),  
					),
					'sortable' => array('spam_active', 'domain', 'link_count'),
				);
				break;
			case 'links':
				$args = array(	
					'id' => 'spbc_tbl__scanner__outbound_links',
					'sql' => array(
						'table'     => SPBC_TBL_SCAN_LINKS,
						'get_array' => true,
						'where' => ' WHERE domain = "'.Post::get('domain').'"',
						'get_array'  => false,
					),
					'order_by'  => array('spam_active' => 'asc'),
					'html_before' => 
						 sprintf(__('Links for <b>%s</b> domain.', 'security-malware-firewall'), Post::get('domain')).' '
						.sprintf(__('%sSee all domains%s', 'security-malware-firewall'), '<a href="#" onclick="spbc_scanner__switch_table(this, \'domains\');">','</a>')
						.'<br /><br />',
					'func_data_prepare' => 'spbc_field_scanner__prepare_data__links',
					'if_empty_items' => '<p class="spbc_hint">'.__('No links are found', 'security-malware-firewall').'</p>',
					'columns' => array(
						'link_id'     => array('heading' => __('Number', 'security-malware-firewall'), 'class' => ' tbl-width--50px'),
						'link'        => array('heading' => __('Link', 'security-malware-firewall'), 'primary' => true,),
						'page_url'    => array('heading' => __('Post Page', 'security-malware-firewall'),),
						'link_text'   => array('heading' => __('Link Text', 'security-malware-firewall'),),
						'spam_active' => array(
							'heading' => __('Spam-active', 'security-malware-firewall'),
							'hint' => __('Does link spotted in spam?', 'security-malware-firewall'),
						),
					),
					'sortable' => array('link', 'page_url', 'spam_active'),
				);
				break;
		}
		$table = new ListTable($args);
		$table->get_data();
		$table->display();
		die();
	}
	
	public static function stripslashes__array($arr)
	{
		foreach($arr as $key => &$value){
			if(is_string($value))
				$value = stripslashes($value);
			elseif(is_array($value))
				$value = self::stripslashes__array($value);
			else
				continue;
		} unset($key, $value);
		return $arr;
	}
}
