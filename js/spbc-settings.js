// Switching tabs
function spbc_switchTab(tab, highlight, highlight_times){
	var tab_name = tab.classList[1].replace('spbc_tab_nav-', '')
	jQuery('.spbc_tab_nav').removeClass('spbc_tab_nav--active');
	jQuery('.spbc_tab').removeClass('spbc_tab--active');
	jQuery(tab).addClass('spbc_tab_nav--active');
	jQuery('.spbc_tab-'+tab_name).addClass('spbc_tab--active');
	if(!jQuery(tab).data('loaded')){
		var data = {
			action: 'spbc_tab__'+tab_name,
			tab_name: tab_name,
		};
		var params = {
			callback: spbc_draw_settings_callback,
			notJson: true,
			highlight: highlight || null,
			highlight_times: highlight_times || null,
		};
		spbc_sendAJAXRequest( data, params, tab );
	}else if(highlight){
		spbcHighlightElement(highlight, highlight_times);
	}
}

function spbc_draw_settings_callback(result, data, params, obj){
	jQuery(obj).data('loaded', true);
	var tab = jQuery('.spbc_tab-'+data.tab_name);
	tab.html(result);
	if(params.highlight)
		spbcHighlightElement(params.highlight, params.highlight_times);
	jQuery(tab).on('click', '.spbc_hint-send_'+data.tab_name, function(){
			jQuery('.spbc_hint-send_'+data.tab_name).hide();
		spbc_sendAJAXRequest(
			{action: 'spbc_send_'+data.tab_name, tab_name: data.tab_name},
			{callback: spbc_send_logs_callback}
		);
	});
}

function spbc_send_logs_callback(result, data, params, obj){
	jQuery('.spbc_tab_nav-'+data.tab_name).data('loaded', false);
	spbc_switchTab(document.getElementsByClassName('spbc_tab_nav-'+data.tab_name)[0]);
}
// Settings dependences
function spbcSettingsDependencies(spbcSettingSwitchId){
	var spbcSettingToSwitch = document.getElementById(spbcSettingSwitchId);
	if(spbcSettingToSwitch.getAttribute('disabled') === null)
		spbcSettingToSwitch.setAttribute('disabled', 'disabled');
	else
		spbcSettingToSwitch.removeAttribute('disabled');
}

// Shows/hides full text
function spbcStartShowHide(){
	jQuery('.spbcShortText').on('mouseover', function(){ jQuery(this).hide(); jQuery(this).next().show(); });
	jQuery('.spbcFullText').on('mouseout',   function(){ jQuery(this).hide(); jQuery(this).prev().show(); });
}

jQuery(document).ready(function(){
	
	// Auto update banner close handler 
	jQuery('.spbc_update_notice').on('click', 'button', function(){
		spbc_admin_set_cookie('spbc_update_banner_closed', 1, 86400 * 30)
	});
	
	//* TAB_CONROL
	
		jQuery('.spbc_tab_nav-summary').data('loaded', true); // Summary tab loaded by default
		jQuery('.spbc_tabs_nav_wrapper').on('click', '.spbc_tab_nav', function(event){
			spbc_switchTab(event.currentTarget);
		});
		
		// Get spbc_highlight form query
		var spbc_highlight_id = location.search.match(/spbc_highlight=(\S*?)(&|$)/);
		spbc_highlight_id = spbc_highlight_id ? spbc_highlight_id[1] : null;
		
		// Get open tab form query
		var spbc_tab = location.search.match(/spbc_tab=(\S*?)(&|$)/);
		spbc_tab = spbc_tab ? document.getElementsByClassName('spbc_tab_nav-'+(spbc_tab ? spbc_tab[1] : ''))[0] : null;
		
		// Switch to tab
		if(spbc_tab){
			spbc_switchTab(spbc_tab, spbc_highlight_id, 3);
		// }else if( true ){ // dev
			// spbc_tab = document.getElementsByClassName('spbc_tab_nav-scanner')[0]; 
		}else if( +spbcSettings.debug ){
			spbc_tab = document.getElementsByClassName('spbc_tab_nav-debug')[0]; // Switch to Debug to tab if debug is iset
		}else if( +spbcSettings.key_is_ok ){
			spbc_tab = document.getElementsByClassName('spbc_tab_nav-summary')[0];
		}else{
			spbc_tab = document.getElementsByClassName('spbc_tab_nav-settings_general')[0];
			spbc_highlight_id = 'spbc_key';
		}
		
		if(spbc_tab) spbc_switchTab(spbc_tab, spbc_highlight_id, 3);
		
		
		
		
	//*/ TAB_CONROL END
});