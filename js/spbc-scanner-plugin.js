'use strict';

class spbcMalwareScanner{

	first_start = true;

	root  = '';
	settings = [];
	states = [
		'get_cms_hashes',
		'get_modules_hashes',
		'clean_results',
		'file_system_analysis',
		'get_approved_hashes',
		'signature_analysis',
		'heuristic_analysis',
		'auto_cure_backup',
		'auto_cure',
		'outbound_links',
		'frontend_analysis',
		'important_files_listing',
		'send_results',
	];
	state = null;
	offset = 0;
	amount = 0;
	total_scanned = 0;
	scan_percent = 0;
	percent_completed = 0;

	paused = false;

	button = null;
	spinner = null;

	progress_overall = null;
	progressbar = null;
	progressbar_text = null;

	timeout = 60000;

	state_timer = 0;

	constructor ( properties ) {

		console.log('init');

		// Crunch for cure backups
		if( typeof properties['settings']['auto_cure'] !== 'undefined' ){
			properties['settings']['scanner__auto_cure_backup'] = '1';
		}

		for( let key in properties ){
			if( typeof this[key] !== 'undefined' ){
				this[key] = properties[key];
			}
		}

	};

	actionControl(){

		if(this.state === null){
			this.start();

		}else if(this.paused){
			this.resume();
			this.controller();

		}else{
			this.pause();
		}
	};

	start(){

		this.state_timer = Math.round(new Date().getTime() /1000);

		this.state = this.getNextState( null );

		this.setPercents( 0 );
		this.scan_percent = 0;
		this.offset = 0;
		this.progress_overall.children('span')
			.removeClass('spbc_bold')
			.filter('.spbc_overall_scan_status_' + this.state)
			.addClass('spbc_bold');

		this.progressbar.show(500);
		this.progress_overall.show(500);
		this.button.html(spbcScaner.button_scan_pause);
		this.spinner.css({display: 'inline'});

		setTimeout(() => {
			this.controller();
		}, 1000);

	};

	pause( result, data, opt ){
		console.log('PAUSE');
		this.button.html(spbcScaner.button_scan_resume);
		this.spinner.css({display: 'none'});
		this.paused = true;
	};

	resume( opt ){
		console.log('RESUME');
		this.button.html(spbcScaner.button_scan_pause);
		this.spinner.css({display: 'inline'});
		this.paused = false;
	};

	end( reload ){

		this.progressbar.hide(500);
		this.progress_overall.hide(500);
		this.button.html(spbcScaner.button_scan_perform);
		this.spinner.css({display: 'none'});
		this.state = null;
		this.total_links = 0;
		this.plug = false;
		this.total_scanned = 0;

		if(reload){
			document.location = document.location;
		}else{
			spbc_sendAJAXRequest(
				{action: 'spbc_scanner_tab__reload_accordion'},
				{
					notJson: true,
					callback: function(result, data, params, obj){
						jQuery(obj).accordion('destroy')
							.html(result)
							.accordion({
								header: 'h3',
								heightStyle: 'content',
								collapsible: true,
								active: false,
							});
						spbc_tbl__bulk_actions__listen();
						spbc_tbl__row_actions__listen();
						spbc_tbl__pagination__listen();
						spbc_tbl__sort__listen();
						spbcStartShowHide();
					},
				},
				jQuery('#spbc_scan_accordion')
			);
		}

	};

	controller( result ) {

		console.log(this.state);

		// The current stage is over. Switching to the new one
		if( typeof result !== 'undefined' && result.end ){

			this.state = this.getNextState( this.state );

			// End condition
			if (typeof this.state === 'undefined'){
				this.end();
				return;
			}

			// Set percent to 0
			this.setPercents( 0 );
			this.scan_percent = 0;
			this.offset = 0;

			// Changing visualizing of the current stage
			this.progress_overall.children('span')
				.removeClass('spbc_bold')
				.filter('.spbc_overall_scan_status_' + this.state)
				.addClass('spbc_bold');
		}

		// Break execution if paused
		if( this.paused === true )
			return;

		// // AJAX params
		let data = {
			action: 'spbc_scanner_controller_front',
			method: this.state,
			offset: this.offset,
		};

		var params = {
			type:        'GET',
			success:     this.success,
			callback:    this.successCallback,
			error:       this.error,
			errorOutput: this.errorOutput,
			complete:    null,
			context:     this,
			timeout:     120000
		};

		switch (this.state) {
			case 'get_modules_hashes':   this.amount = 2;        break;
			case 'clear_table':          this.amount = 10000;    break;
			case 'file_system_analysis': this.amount = 700;      break;
			case 'auto_cure':            this.amount = 5;        break;
	        case 'outbound_links':       this.amount = 10;       break;
	        case 'frontend_analysis':    this.amount = 2;        break;
			case 'signature_analysis':   this.amount = 10; data.status = 'UNKNOWN,MODIFIED,OK,INFECTED'; break;
			case 'heuristic_analysis':   this.amount = 4;  data.status = 'UNKNOWN,MODIFIED,OK,INFECTED'; break;
		}

		data.amount = this.amount;

		spbc_sendAJAXRequest(
			data,
			params,
			jQuery('#spbc_scan_accordion')
		);

	};

	getNextState( state ) {

		state = state === null ? this.states[0] : this.states[ this.states.indexOf( state ) + 1 ];

		if (typeof this.settings[ 'scanner__' + state ] !== 'undefined' && +this.settings[ 'scanner__' + state ] === 0)
			state = this.getNextState( state );

		return state;
	};

	setPercents( percents ){
		this.percent_completed = Math.floor( percents * 100 ) / 100;
		this.progressbar.progressbar( 'option', 'value', this.percent_completed );
		this.progressbar_text.text( spbcScaner[ 'progressbar_' + this.state ] + ' - ' + this.percent_completed + '%' );
	};

	success( response ){

		if( !! response.error ){

			this.error(
				{status: 200, responseText: response.error},
				response.error,
				response.msg
			);

		}else{
			if( this.successCallback )
				this.successCallback( response, this.data, this.obj );
		}

	};

	// Processing response from backend
	successCallback( result ){

		console.log( result );

		if( typeof result.total !== 'undefined' )
			this.scan_percent = 100 / result.total;

		if( typeof result.processed_items !== 'undefined'){

			if( this.state === 'heuristic_analysis' && typeof result.total !== 0 )
				this.logRaw('<h3 class="spbc_log-block_header">Heuristic Analysis</h3>');
			if( this.state === 'signature_analysis' && typeof result.total !== 0 )
				this.logRaw('<h3 class="spbc_log-block_header">Signature Analysis</h3>');

			this.logFileEntry( result.processed_items );
		}
		
		// Add link on shuffle salt if cured
		if (result.cured !== 'undefined' && Number(result.cured) > 0) {
			this.showLinkForShuffleSalts(result.message);
		}

		if( result.end !== true && result.end !== 1 ){
			this.setPercents( this.percent_completed + result.processed * this.scan_percent );
			this.offset = this.offset + result.processed;
			this.controller( result );
		}else{
			console.log( this.state + " stage took " + ( Math.round(new Date().getTime() /1000) - this.state_timer ) + " seconds to complete" );
			this.state_timer = Math.round(new Date().getTime()/1000);
			this.setPercents( 100 );
			this.scan_percent = 0;
			this.offset = 0;
			setTimeout(() => {
				this.controller( result );
			}, 300);
		}
	};

	error( xhr, status, error ){

		let errorOutput = this.errorOutput;

		console.log( '%c APBCT_AJAX_ERROR', 'color: red;' );
		console.log( status );
		console.log( error );
		console.log( xhr );

		if( xhr.status === 200 ){
			if( status === 'parsererror' ){
				errorOutput( 'Unexpected response from server. See console for details.', this.state );
				console.log( '%c ' + xhr.responseText, 'color: pink;' );
			}else{
				let error_string = status;
				if( typeof error !== 'undefined' )
					error_string += ' Additional info: ' + error;
				errorOutput( error_string, this.state );
			}
		}else if(xhr.status === 500){
			errorOutput( 'Internal server error.', this.state);
		}else
			errorOutput('Unexpected response code: ' + xhr.status + '. Error: ' + status, this.state);

		if( this.progressbar )
			this.progressbar.fadeOut('slow');

		this.end();
	};

	errorOutput( error_msg, stage ){
		spbcModal.open().putError( error_msg + '<br>Stage: ' + stage);
	};

	logRaw(message_to_log ){
		jQuery('.spbc_log-wrapper').removeClass('spbc---hidden')
			.prepend( message_to_log );
	};

	logFileEntry(items){
		var ct_date = new Date(),
			shortMonthName = new Intl.DateTimeFormat("en-US", { month: "short" }).format,
			time_string = shortMonthName(ct_date) + ' ' + ct_date.getDate() + ' ' + ct_date.getFullYear() + ' ' + ct_date.getHours() + ':' + ct_date.getMinutes() + ':' + ct_date.getSeconds();
		for ( var key in items ){
			this.logRaw( '<p class="spbc_log-line">' + time_string + ' - ' + items[ key ].path + '<b>: ' + items[ key ].status + '</b></p>' );
		}
	};

	showLinkForShuffleSalts(message) {
		jQuery('#spbc_notice_about_shuffle_link').remove();
		jQuery(jQuery('.spbc_tab--active .spbc_wrapper_field p')[1])
			.after(
				'<div style="text-align: center;" id="spbc_notice_about_shuffle_link">' +
				'<a href="#" ' +
				'onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], {target: \'action-shuffle-salts-wrapper\', action: \'highlight\', times: 3})">' +
				message +
				'</a>' +
				'</div>'
			);
	}

};