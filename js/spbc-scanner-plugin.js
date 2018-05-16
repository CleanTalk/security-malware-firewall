(function($){
	
	// Wrappers
	$.spbc = {
		scanner: {
			
			// Controller
			control: function(result, data, start) { return spbcObj.spbcScannerPlugin('control', result, data, start) },
			
			// Common
			data:  function(param, data) { return spbcObj.spbcScannerPlugin('data', param, data)  },
			ajax:  function(data)        { return spbcObj.spbcScannerPlugin('ajax', data)         },
			start: function()            { return spbcObj.spbcScannerPlugin('start')              },
			end:   function()            { return spbcObj.spbcScannerPlugin('end')                },
			pause: function(result, data){ return spbcObj.spbcScannerPlugin('pause', result, data)},
			resume:function()            { return spbcObj.spbcScannerPlugin('resume')             },
			
			// Debug
			clear:           function() { return spbcObj.spbcScannerPlugin('clear')          },
			clear_callback:  function() { return spbcObj.spbcScannerPlugin('clear_callback') },
			
			// Actions
			getHashes:     function()             { return spbcObj.spbcScannerPlugin('getHashes')                   },
			clearTable:    function()             { return spbcObj.spbcScannerPlugin('clearTable')                 },
			count:         function(path)         { return spbcObj.spbcScannerPlugin('count',         path)         },
			scan:          function(path)         { return spbcObj.spbcScannerPlugin('scan',          path)         },
			countModified: function(path, status) { return spbcObj.spbcScannerPlugin('countModified', path, status) },
			scanModified:  function(path, status) { return spbcObj.spbcScannerPlugin('scanModified',  path, status) },
			countLinks:    function()             { return spbcObj.spbcScannerPlugin('countLinks')                  },
			scanLinks:     function()             { return spbcObj.spbcScannerPlugin('scanLinks')                   },
			sendResults:   function()             { return spbcObj.spbcScannerPlugin('sendResults')                 },
			listResults:   function()             { return spbcObj.spbcScannerPlugin('listResults')                 },
			
			// Callbacks
			count_callback:         function(result, data) { return spbcObj.spbcScannerPlugin('count_callback',         result, data) },
			scan_callback:          function(result, data) { return spbcObj.spbcScannerPlugin('scan_callback',          result, data) },
			countModified_callback: function(result, data) { return spbcObj.spbcScannerPlugin('countModified_callback', result, data) },
			scanModified_callback:  function(result, data) { return spbcObj.spbcScannerPlugin('scanModified_callback',  result, data) },
			countLinks_callback:    function(result, data) { return spbcObj.spbcScannerPlugin('countLinks_callback',    result, data) },
			scanLinks_callback:     function(result, data) { return spbcObj.spbcScannerPlugin('scanLinks_callback',     result, data) },
			sendResults_callback:   function(result, data) { return spbcObj.spbcScannerPlugin('sendResults_callback',   result, data) },
			listResults_callback:   function(result, data) { return spbcObj.spbcScannerPlugin('listResults_callback',   result, data) },
			
		},
	};
	
	$.fn.spbcScannerPlugin = function(param){
		
		var scanner = jQuery.spbc.scanner;
		
		// Methods
		var methods = {
			init: function(settings) {
				console.log('init');
				this.data(settings);
				window.spbcObj = this;
			},
			start: function(opt){
				opt.progressbar.show(500)
					.progressbar('option', 'value', 0);
				opt.progress_overall.show(500);
				opt.button.html(spbcScaner.button_scan_pause);
				opt.spinner.css({display: 'inline'});
			},
			end: function(opt){
				opt.progressbar.hide(500)
					.progressbar('option', 'value', 100);
				opt.progress_overall.hide(500);
				opt.button.html(spbcScaner.button_scan_perform);
				opt.spinner.css({display: 'none'});
				this.removeData('status');
				this.data('total_links', 0)
					.data('plug', false)
					.data('total_scanned', 0);
			},
			resume: function(opt){
				console.log('RESUME');
				opt.button.html(spbcScaner.button_scan_pause);
				opt.spinner.css({display: 'inline'});
				opt.paused = false;
			},			
			pause: function(result, data, opt){
				console.log('PAUSE');
				opt.button.html(spbcScaner.button_scan_resume);
				opt.spinner.css({display: 'none'});
				opt.result = result;
				opt.data = data;
				opt.paused = true;
			},
			data: function(param, data){
				if(typeof data === 'undefined'){
					if(param === 'all')
						return this.data();
					return this.data(param);
				}
				this.data(param, data);
			},
			clear: function(){
				console.log('CLEAR');
				scanner.start();
				this.data('scan_status', 'clear')
					.data('callback', scanner.clear_callback);
				var data = { action : 'spbc_scanner_clear' };
				scanner.ajax(data);
			},
			clear_callback: function(){
				console.log('CLEARED');
				scanner.end();
			},
			
			// AJAX request
			ajax: function(data, opt){
				// Default prarams
				var notJson = this.data('notJson') || false;
				
				// Changing text and precent
				if(opt.prev_action != data.action && typeof opt.progressbar !== 'undefined'){
					opt.progress_overall.children('span')
						.removeClass('spbc_bold')
						.filter('.spbc_overall_scan_status_'+opt.status)
							.addClass('spbc_bold');
					opt.progressbar.progressbar('option', 'value', 0);
					opt.progressbar_text.text(spbcScaner['progressbar_'+opt.status] + ' - 0%');
				}
				this.data('prev_action', data.action);
				
				// Default params
				data.security = spbcSettings.ajax_nonce; // Adding security code
				jQuery.ajax({
					type: "POST",
					url: spbcSettings.ajaxurl,
					data: data,
					success: function(result){
						if(!notJson) result = JSON.parse(result);
						if(result.error){
							console.log(result); console.log(data);	console.log(opt);
							alert('Error happens: ' + (result.error_string || 'Unkown'));
							setTimeout(function(){ scanner.end(); }, 1000);
						}else{
							console.log(result); console.log(data);	console.log(opt);
							if(result.scanned)
								opt.button.data('precent_completed', opt.precent_completed + result.scanned / opt.scan_precent);
							if(typeof opt.progressbar !== 'undefined'){
								opt.progressbar.progressbar('option', 'value', Math.floor(opt.precent_completed));
								opt.progressbar_text.text(spbcScaner['progressbar_'+opt.status] + ' - ' + Math.floor(opt.precent_completed) + '%');
							}
							if(typeof opt.callback !== 'undefined'){
								setTimeout(function(){
									opt.callback(result, data);
								}, 1000);
							}
						}
					},
					error: function(jqXHR, textStatus, errorThrown){
						scanner.end();
						console.log('SPBC_AJAX_ERROR');
						console.log(jqXHR);
						console.log(textStatus);
						console.log(errorThrown);
						alert(errorThrown);
					},
					timeout: opt.timeout,
				});
			},
			
			// CONTROL
			
			control: function(result, data, action, opt){
				
				this.data('callback', scanner.control)
					.data('precent_completed', 100);
					
				if(typeof action !== 'undefined' && action){
					if(opt.status == null){
						scanner.start();
						scanner.getHashes();
						return;
					}else{
						if(opt.paused == true){
							scanner.resume();
							result = opt.result;
							data = opt.data;
						}else{
							scanner.pause(result, data);
							return;
						}
					}
				}
				if(opt.paused == true) return;
				
				setTimeout(function(){
					switch(opt.status){
						
						// WP Core
						case 'get_hashes':
							scanner.clearTable();
							break;
						case 'clear_table':
							scanner.count( spbcScaner.wp_root_dir );
							break;
						case 'count':
							scanner.scan( spbcScaner.wp_root_dir );
							break;
						case 'scan':
							scanner.countModified( spbcScaner.wp_root_dir, 'UNKNOWN,COMPROMISED' );
							break;
						case 'count_modified':
							if(result.files_total > 30){
								if(!confirm(spbcScaner.scan_modified_confiramation)){
									alert(spbcScaner.warning_about_cancel);
									scanner.sendResults();
									return;
								}
							}
							scanner.scanModified( spbcScaner.wp_root_dir, 'UNKNOWN,COMPROMISED' ); 
							break;
						case 'scan_modified':
							if( +spbcScaner.check_links )    {                                scanner.countLinks();                     return; } // Scan links
							if( +spbcScaner.check_heuristic ){ opt.button.data('plug', true); scanner.count(spbcScaner.wp_content_dir); return; } // Scan plugins
							scanner.sendResults(); 
							break;
						
						// Links
						case 'count_links':
							scanner.scanLinks();
							break;
						case 'scan_links':
							if( +spbcScaner.check_heuristic ){ opt.button.data('plug', true); scanner.count(spbcScaner.wp_content_dir); return; } // Scan plugins
							scanner.sendResults(); 
							break;
						
						// Plugins and themes
						case 'count_plug':
							scanner.scan(spbcScaner.wp_content_dir);
							break;
						case 'scan_plug':                 
							scanner.countModified(spbcScaner.wp_content_dir, 'UNKNOWN');
							break;
						case 'count_modified_plug': 
							scanner.scanModified(spbcScaner.wp_content_dir, 'UNKNOWN');
							break;
						case 'scan_modified_plug':
							scanner.sendResults();
							break;
						
						// List results
						// case 'list_results':
							// scanner.sendResults();
							// break;
						
						// Send results
						case 'send_results':
							scanner.end();
							opt.button.data('status', null);
							location.href=location.origin+location.pathname+location.search+"&spbc_tab=scanner";
							break;
						
						default:
							
							break;
					}
				}, 300);
			},
			
			// ACTIONS
			getHashes: function(opt){
				console.log('GET_HASHES');
				this.data('status', 'get_hashes');
				scanner.ajax({ action: 'spbc_scanner_get_remote_hashes'	});
			},
			clearTable: function(){
				console.log('CLEAR_TABLE');
				this.data('status', 'clear_table');
				scanner.ajax({action : 'spbc_scanner_clear_table'});
			},			
			count: function(path, opt){
				console.log('COUNT_FILES'+ (opt.plug ? '_plug' : ''));
				this.data('status', 'count' + (opt.plug ? '_plug' : ''))
					.data('callback', scanner.count_callback);
				scanner.ajax({
					action : 'spbc_scanner_count_files',
					path: path,
				});
			},
			count_callback: function(result, data, opt){
				console.log('FILES COUNTED');
				this.data('total_scanned', this.data('total_scanned') + +result.files_total)
					.data('scan_precent', +result.files_total / 98);
				scanner.control();
			},
			scan: function(path, opt){
				console.log('SCAN FILES'+ (opt.plug ? '_plug' : ''));
				data = {
					action : 'spbc_scanner_scan',
					offset : 0,
					amount : 700,
					path: path,
				};
				this.data('status', 'scan' + (opt.plug ? '_plug' : ''))
					.data('precent_completed', 0)
					.data('callback', scanner.scan_callback);
				scanner.ajax(data);
			},
			scan_callback: function(result, data, opt){
				console.log('SCANNING FILES');
				if(result.scanned >= data.amount){
					data.offset += data.amount;
					scanner.ajax(data);
					return;
				}
				console.log('SCAN COMPLETED');
				opt.progressbar.progressbar('option', 'value', 100);
				opt.progressbar_text.text(spbcScaner['progressbar_'+opt.status] + ' - 100%');
				scanner.control();
			},
			countModified: function(path, status, opt){
				console.log('COUNT MODIFIED FILES' + (opt.plug ? '_plug' : ''));
				this.data('status', 'count_modified' + (opt.plug ? '_plug' : ''))
					.data('callback', scanner.countModified_callback);
				data = {
					action : 'spbc_scanner_count_modified_files',
					status : status,
					path: path,
				};
				scanner.ajax(data);
			},
			countModified_callback: function(result, data, opt){
				console.log('MODIFIED FILES COUNTED');
				this.data('scan_precent', +result.files_total / 98);
				scanner.control(result, data);
			},
			scanModified: function(path, status, opt){
				console.log('SCAN MODIFIED FILES' + (opt.plug ? '_plug' : ''));
				this.data('status', 'scan_modified' + (opt.plug ? '_plug' : ''))
					.data('precent_completed', 0)
					.data('callback', scanner.scanModified_callback)
					.data('timeout',  60000);
				data = {
					action : 'spbc_scanner_scan_modified',
					amount : 5,
					status : status,
					path: path,
				};
				scanner.ajax(data);
			},
			scanModified_callback: function(result, data, opt){
				console.log('MODIFIED FILES SCANNING');
				if(result.scanned >= data.amount){
					scanner.ajax(data);
					return;
				}
				console.log('MODIFIED FILES END');
				opt.progressbar.progressbar('option', 'value', 100);
				opt.progressbar_text.text(spbcScaner['progressbar_'+opt.status] + ' - 100%');
				scanner.control();
			},
			countLinks: function(opt){
				console.log('COUNT LINKS');
				this.data('status', 'count_links')
					.data('callback', scanner.countLinks_callback);
				data ={
					action: 'spbc_scanner_count_links',
				};
				scanner.ajax(data);
			},
			countLinks_callback: function(result, data, opt){
				console.log('SCAN LINKS');
				this.data('scan_precent', +result.posts_total / 98);
				scanner.control();
			},
			scanLinks: function(opt){
				console.log('SCAN LINKS');
				this.data('status', 'scan_links')
					.data('precent_completed', 0)
					.data('callback', scanner.scanLinks_callback)
					.data('timeout', 30000);
				data ={
					action: 'spbc_scanner_scan_links',
					amount: 10,
				};
				scanner.ajax(data);
			},
			scanLinks_callback: function(result, data, opt){
				console.log('LINKS SCANNING');
				if ( +result.scanned){
					this.data('total_links', +opt.total_links + +result.links_found);
					scanner.ajax(data);
					return;
				}
				console.log('LINKS SCANNED');
				opt.progressbar.progressbar('option', 'value', 100);
				opt.progressbar_text.text(spbcScaner['progressbar_'+opt.status] + ' - 100%');
				scanner.control();
			},
			listResults: function(opt){
				console.log('LIST RESULTS');
				this.data('status', 'list_results')
					.data('callback', scanner.listResults_callback);
				var data = {
					action: 'spbc_scanner_list_results',
				};
				scanner.ajax(data);
			},
			listResults_callback: function(result, data, opt){
				console.log('RESULTS LISTED');
	
				var i = 0,
					item = undefined,
					actions = '';
					
				for(type in result.data){
					var wrapper = opt.wrapper[i];
						hint = wrapper.previousElementSibling,
						pagination = jQuery(wrapper.nextElementSibling),
						header = jQuery(wrapper.parentElement.previousElementSibling);
					// Rows
					jQuery(wrapper).find('.spbc_scan_result_row').remove();
					for(key in result.data[type].list){
						item = result.data[type].list[key];
						// Different button set for different file types
						if(type == 'unknown'){
							actions = spbcScaner.actions_unknown;
							if( +item.size == 0 || +item.size > 1048570 || (+item.mtime < +item.last_sent && item.last_sent !== null)){
								actions = actions.replace('file_send"', 'file_send" disabled');
							}
						}else{
							actions = spbcScaner.actions_modified;
							if( !item.real_full_hash ){
								actions = actions.replace('compare"', 'compare" disabled');
							}
						}
						if (type == 'outbound links')
							jQuery(wrapper).find('tbody').append(spbcScaner.row_template_links.printf(item.url, item.url_text, item.page, item.page_text, item.link_text));
						else
							jQuery(wrapper).find('tbody').append(spbcScaner.row_template.printf(type, item.fast_hash, item.path, item.size_str, item.perms, item.mtime_str, actions));
					}
					// Table visibility and Text
					if(result.data[type].amount > 0){
						wrapper.style.display = 'block';
						hint.innerHTML = spbcScaner.result_text_bad_template.printf(result.data[type].amount)
						pagination.find('li.pagination').remove();
						var pages = Math.ceil(+result.data[type].amount / +spbcScaner.on_page),
							curr_page = data.page || 1;
						for(var page = 1; page <= pages; page++){
							pagination.find('ul.pagination').append(spbcScaner.page_selector_template.printf(type, page, (page == curr_page ? ' class=\'current_page\'' : ''), page))
						}
						if(pages < 2)
							pagination.hide();
						else
							pagination.show();
						spbc_setHandlers(true);
					}else{
						wrapper.style.display = 'none';
						hint.innerHTML = spbcScaner.result_text_good_template;
						pagination.hide();
					}
					header.find('.spbc_bad_type_count').text(result.data[type].amount);
					i++;
				}
				spbcStartShowHide();
				scanner.control();
			},
			sendResults: function(){
				console.log('SEND RESULTS');
				this.data('status', 'send_results')
					.data('callback', scanner.sendResults_callback);
				var data = {
					action: 'spbc_scanner_send_results',
					total_scanned: this.data('total_scanned'),
				};
				if( +spbcScaner.check_links )
					data.total_links = this.data('total_links');
				scanner.ajax(data);
			},
			sendResults_callback: function(result, data, opt){
				console.log('RESULTS_SENT');
				if( +spbcScaner.check_links ){
					opt.button.parent().next().html(spbcScaner.last_scan_was_just_now_links.printf(data.total_scanned, data.total_links));
				}else{
					opt.button.parent().next().html(spbcScaner.last_scan_was_just_now.printf(data.total_scanned)); 
				}	
					
				jQuery('#spbc_scanner_status_icon').attr('src', spbcSettings.img_path + '/yes.png');
				scanner.control();
			},
			
			// FILE BUTTONS
			
		};
		
		// Method call. Passing current settings to each function as the last element.
		if(typeof methods[param]==='function'){
			var args = Array.prototype.slice.call(arguments, 1);
			if(param !== 'data')
				args.push(this.data());
			// console.log(param); console.log(args);
			return methods[param].apply(this, args);
		}
		
		// Init
		if(typeof param === 'object'){
			var settings = $.extend({
				
				status: null,
				pused_status: null,
				
				total_links: 0,
				total_scanned: 0,
				
				button: null,
				spinner: null,
				
				progress_overall: null,
				progressbar: null,
				progressbar_text: null,
				
				callback: null,
				timeout: 60000,
			}, param);
			return methods.init.apply(this, [settings]);
		}
		
		// Error
		$.error( 'Метод с именем "' +  param + '" не существует для jQuery.spbcScannerPlugin' );		
	};
	
})(jQuery);
