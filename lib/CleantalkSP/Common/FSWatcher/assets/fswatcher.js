document.addEventListener('DOMContentLoaded', function() {
    if (typeof fswatcherToken !== 'undefined' && fswatcherWebsiteUrl !== 'undefined') {
        let xhr = new XMLHttpRequest();
        xhr.open("POST", fswatcherWebsiteUrl + '/');
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.send('fswatcher_token=' + fswatcherToken);
    }
});
