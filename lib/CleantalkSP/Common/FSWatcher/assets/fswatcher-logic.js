// if no changes detected after comparison
let noFSWChangesDetected = true;
// first selector elem
const firstFSWSelector = document.getElementById('fswatcher__first_date');
// second selector elem
const secondFSWSelector = document.getElementById('fswatcher__second_date');
// FSW table body
const fsWatcherTableBody = document.getElementById('spbc-table-fs_watcher-comparison');
// available types of events
const availableFSWDataSetNames = ['added','changed','deleted'];

if( document.readyState !== 'loading' ) {
    FSWOnload();
} else {
    document.addEventListener('DOMContentLoaded', FSWOnload);
}


function FSWOnload() {
    document.querySelector('#fswatcher__first_date').selectedIndex = 0;
    let secondDate = document.querySelector('#fswatcher__second_date');
    secondDate.selectedIndex = secondDate.options.length - 1;
    FSWCompare(new Event({}));
}

/**
 * Main handler function. Run this on the button click.
 * @param {Event} e click event.
 */
function FSWCompare(e) {
    e.preventDefault();

    if (e.currentTarget !== null) {
        document.querySelector('#fsw_preloader_compare').style.display = 'inline';
    }

    if ( typeof document.getElementById('fswatcher__first_date') === 'undefined'
        || typeof document.getElementById('fswatcher__second_date') === 'undefined' ) {
        return false;
    }

    let first_date = document.getElementById('fswatcher__first_date').value;
    let second_date = document.getElementById('fswatcher__second_date').value;

    if (typeof fswatcherToken !== 'undefined' && first_date && second_date) {
        let data = [
            'fswatcher_token=' + fswatcherToken,
            'fswatcher_compare=1',
            'fswatcher__first_date=' + first_date,
            'fswatcher__second_date=' + second_date,
        ];
        let callback = function (response) {
            FSWHandleXHRResponse(response);
            toggleFSWSelectorsInfo(true);
            document.querySelector('#fsw_preloader_compare').style.display = 'none';
        }
        FSWrequest(data, callback);
    }

    return false;
}

/**
 * Handle File System Watcher XHR Response
 * @param {string} response
 */
function FSWHandleXHRResponse(response) {
    let responseDataObj = {};
    noFSWChangesDetected = true;
    if (typeof response === 'object') {
        responseDataObj = response;
    } else if (typeof response === 'string') {
        responseDataObj = FSWDecodeJSON(response)
        if (responseDataObj.hasOwnProperty('error')) {
            alert(fswatcherTranslations['fs_err_parse_json']);
            console.log('File System watcher JSON parse error: ' + responseDataObj.error)
            return;
        }
    }

    const validate_result = validateFSWResponse(responseDataObj)
    if (true === validate_result) {
        renderFSWatcherTableContent(responseDataObj)
        if (noFSWChangesDetected) {
            renderFSWTableRow( '', 'no_changes', '')
        }
    } else {
        alert(validate_result + ' ' + fswatcherTranslations['fs_err_valid_result'] + ' support@cleantalk.org');
        console.log('File System watcher response validating error: ' + validate_result)
    }
    resetFSWSelectors();
}

function FSWCreate(e) {
    e.preventDefault();

    if (e.currentTarget !== null) {
        document.querySelector('#fsw_preloader_create').style.display = 'inline';
    }

    if (typeof fswatcherToken !== 'undefined') {
        const button = e.target;
        button.disabled = true;
        let data = [
            'fswatcher_token=' + fswatcherToken,
            'fswatcher_create_snapshot=1'
        ];
        let callback = function(response) {
                FSWHandleXHRResponseCreate(response, button);
                document.querySelector('#fsw_preloader_create').style.display = 'none';
        };
        FSWrequest(data, callback);
    }
}

function FSWHandleXHRResponseCreate(response, button) {
    let responseDataObj = {};
    if (typeof response === 'string') {
        responseDataObj = FSWDecodeJSON(response);
        button.disabled = false;
    }

}

/**
 * Try to decode JSON string from site response.
 * @param {string} response
 */
function FSWDecodeJSON(response) {
    try {
        return JSON.parse(response)
    } catch (e) {
        return {'error': e};
    }
}

/**
 * Run rendering comparison table in dependence of response object
 * @param {{}} responseDataObj
 */
function renderFSWatcherTableContent(responseDataObj) {
    fsWatcherTableBody.innerHTML = '';
    for (const dataSetName of availableFSWDataSetNames) {
        if (handleFSWDataObject(responseDataObj, dataSetName))
        {
            noFSWChangesDetected = false;
        }
    }
}

function validateFSWResponse(responseDataObj) {
    if (
        !responseDataObj ||
        typeof responseDataObj !== 'object'
    ) {
        return fswatcherTranslations['fs_err_resp_obj']
    }

    if (typeof responseDataObj.error !== 'undefined') {
        return responseDataObj.error
    }

    for (const dataSetName of availableFSWDataSetNames) {
        if (
            !responseDataObj.hasOwnProperty(dataSetName)
        ) {
            return fswatcherTranslations['fs_err_property']
        }
    }

    return true;
}

/**
 * @param {object} responseDataObj
 * @param {string|number} event_type
 */
function handleFSWDataObject(responseDataObj, event_type) {
    const events_array = responseDataObj[event_type]
    if (events_array.length > 0) {
        for (let i = 0; i < events_array.length; i++) {
            const row = convertFSWEventToRow(events_array[i], event_type);
            renderFSWTableRow(row.path, row.event_type, row.date)
        }
    } else {
        return false;
    }
    return true;
}

/**
 * Convert a row of site response to the formatted data.
 * @param {object} event contains the date and the file path
 * @param {string} event_type contains event type
 */
function convertFSWEventToRow(event, event_type) {
    let row = {
        'path': 'unknown',
        'event_type': event_type.toUpperCase(),
        'date': 'unknown'
    }

    if (event.length === 2) {
        if (typeof event[0] === 'string') {
            row.path = event[0];
            if (row.event_type !== 'DELETED') {
                row.path += '<br><span data-path="' + row.path + '" onclick="FSWViewFile(this);" style="cursor: pointer; color: blue;">View</span>';
            }
        }
        if (typeof event[1] === 'string') {
            let d = new Date(Number(event[1]) * 1000);
            shortMonthName = new Intl.DateTimeFormat("en-US", { month: "short" }).format;
            let minutes = String(d.getMinutes()).padStart(2, '0');
            let seconds = String(d.getSeconds()).padStart(2, '0');
            row.date = shortMonthName(d) + ' ' + d.getDate() + ' ' + d.getFullYear() + ' ' + d.getHours() + ':' + minutes + ':' + seconds
        }
    }

    return row;
}

/**
 * Show file view.
 * @param {Node} el.
 */
function FSWViewFile(el) {
    let wp_wrap = jQuery('#wpwrap')
	let dialog_window = jQuery('#spbc_dialog')

	dialog_window.dialog({
		modal:true,
		title: fswatcherTranslations['fs_modal'] + ' ' + el.dataset.path,
		position: { my: "center top", at: "center top+100px" , of: window },
		width: +(wp_wrap.width() / 100 * 90),
		show: { effect: "blind", duration: 500 },
		draggable: false,
		resizable: false,
		closeText: "X",
		classes: {"ui-dialog": 'spbc---top'},
		open: function(event, ui) {
			event.target.style.overflow = 'auto';
			jQuery('#spbc_dialog').height((document.documentElement.clientHeight) / 100 * 25);
		},
		beforeClose: function(event, ui) {
			document.body.style.overflow = 'auto';
			jQuery('#spbc_dialog').empty();
		},
	});

	dialog_window.append('<img id="spbc_file_view_preloader" alt="Wait for downloading" ' +
		'class="spbc_preloader" ' +
		'src="../../wp-content/plugins/security-malware-firewall/images/preloader2.gif" ' +
		'style="' +
		'display: block; ' +
		'position: absolute; ' +
		'">');

	let spinner = jQuery('#spbc_file_view_preloader');
	let size_multiplier = (wp_wrap.width() * 0.0004);

	spinner.height(128 * size_multiplier);
	spinner.width(128 * size_multiplier);
	spinner.css({left: dialog_window.width()/2 - (128 * size_multiplier / 2)});
	spinner.css({top: dialog_window.height()/2 - (128 * size_multiplier / 2)});

    if (typeof fswatcherToken !== 'undefined') {
        const firstSelectorId = jQuery('#fswatcher__first_date').val()
        const secondSelectorId = jQuery('#fswatcher__second_date').val()
        let data = [
            'fswatcher_token=' + fswatcherToken,
            'fswatcher_view_file=1',
            'fswatcher_file_path=' + el.dataset.path,
            'fswatcher__first_date=' + firstSelectorId,
            'fswatcher__second_date=' + secondSelectorId,
        ];
        let callback = function(response) {
            let content = '';
            if (typeof response.error !== 'undefined') {
                content = response.error
            } else if (typeof response.data !== 'undefined') {
                content = response.data;
            } else {
                content = 'Unknown error on reading file. Data is empty.'
            }
            content = content.split('\n');
            let dialog_window = jQuery('#spbc_dialog');
            dialog_window.empty();
            jQuery('#spbc_file_view_preloader').css({display:'none'})
            let row_template = '<div class="spbc_view_file_row_wrapper"><span class="spbc_view_file_row_num">%s</span><p class="spbc_view_file_row">%s</p><br /></div>';
            for (let row in content) {
                dialog_window.append(row_template.printf(+row + 1, content[row]));
            }

            let content_height = Object.keys(content).length * 19 < 76 ? 76 : Object.keys(content).length * 19,
                visible_height = (document.documentElement.clientHeight) / 100 * 75,
                overflow       = content_height < visible_height ? 'hidden' : 'scroll',
                height         = overflow === 'scroll' ? visible_height : content_height;

            dialog_window.css({
                height: height,
                overflow: overflow
            });
        };
        FSWrequest(data, callback);
    }

    return false;
}


/**
 * Render the row of FSW table.
 * @param {string} path the file path
 * @param {string} event_type the event type
 * @param {string} date the date of event
 */
function renderFSWTableRow(path, event_type, date) {

    if (event_type === 'no_changes') {
        let tr = document.createElement('tr');
        let td = document.createElement('td');
        td.setAttribute('name', 'fswatcher-event-no-changes');
        td.setAttribute('colspan', '3');
        td.innerText = fswatcherTranslations['fs_no_changes'];
        tr.appendChild(td);
        fsWatcherTableBody.appendChild(tr);
        return;
    }

    let tr = document.createElement('tr');

    let td_path = document.createElement('td');
    td_path.setAttribute('name', 'fswatcher-event-path');
    td_path.setAttribute('data-before', 'Path');
    td_path.innerHTML = path;
    tr.appendChild(td_path);

    let td_type = document.createElement('td');
    td_type.setAttribute('name', 'fswatcher-event-type');
    td_type.setAttribute('data-before', 'Event');
    td_type.innerText = event_type;
    tr.appendChild(td_type);

    let td_date = document.createElement('td');
    td_date.setAttribute('name', 'fswatcher-event-date');
    td_date.setAttribute('data-before', 'Changed on date');
    td_date.innerText = date;
    tr.appendChild(td_date);

    fsWatcherTableBody.appendChild(tr);
}

/**
 * Filter options for the first selector and disable it to keep it from changes.
 */
function filterFSWSecondSelector() {
    toggleFSWSelectorsInfo(false);
}

/**
 * Filter options for the second selector and disable it to keep it from changes.
 */
function filterFSWFirstSelector() {
    toggleFSWSelectorsInfo(false);
}

/**
 * Reset selectors to its initial statements.
 */
function resetFSWSelectors() {
    for (let i = 0; i < firstFSWSelector.options.length; i++) {
        firstFSWSelector.options[i].style.display = 'inherit';
    }
    for (let i = 0; i < secondFSWSelector.options.length; i++) {
        secondFSWSelector.options[i].style.display = 'inherit';
    }
    secondFSWSelector.removeAttribute('disabled');
    firstFSWSelector.removeAttribute('disabled');
}

/**
 * Toggle info string.
 * @param {boolean} enable Set logs names if true, disable content if false.
 */
function toggleFSWSelectorsInfo(enable) {
    let infoTag = document.getElementById('spbc--fs-watcher-table-handling-selects-info')
    if (
        enable
        && typeof firstFSWSelector.options[firstFSWSelector.selectedIndex] !== 'undefined'
        && typeof secondFSWSelector.options[secondFSWSelector.selectedIndex] !== 'undefined'
    )
    {
        const changesCountOnTRS = document.querySelectorAll('#spbc-table-fs_watcher-comparison > tr').length;
        const hasNoChangesTD = document.getElementsByName('fswatcher-event-no-changes').length;
        const changesCount = hasNoChangesTD > 0 ? 0 : changesCountOnTRS;

        infoTag.style.display = 'inherit';
        infoTag.innerHTML= fswatcherTranslations['fs_comparing'] +
            ' <b>' + firstFSWSelector.options[firstFSWSelector.selectedIndex].text + '</b> ' +
            fswatcherTranslations['fs_with'] +
            ' <b>' + secondFSWSelector.options[secondFSWSelector.selectedIndex].text + '</b> ' +
            fswatcherTranslations['fs_total'] +
            ' <b>' + changesCount + '</b>'
    } else {
        infoTag.innerText = '';
        infoTag.style.display = 'none';
    }
}

/**
 * Wrapper for xhr
 * @param {Array} data
 * @param {Function} callback
 */
function FSWrequest(data, callback) {
    let xhr = new XMLHttpRequest();
    xhr.open("POST", fswatcherWebsiteUrl + '/');
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send(data.join('&'));
    xhr.onreadystatechange = function() {
        if( xhr.readyState == XMLHttpRequest.DONE && xhr.status == 200 ) {
            let response = FSWDecodeJSON(xhr.response);
            callback(response);
        }
    };
}

// listeners
document.getElementById('fswatcher__compare').addEventListener('click', FSWCompare);
document.getElementById('fswatcher__create_snapshot').addEventListener('click', FSWCreate);
firstFSWSelector.addEventListener('change', filterFSWSecondSelector);
secondFSWSelector.addEventListener('change', filterFSWFirstSelector);


