<?php
$message_style = <<<EOT
<meta charset="utf-8"> <!-- utf-8 works for most cases -->
<meta name="viewport" content="width=device-width"> <!-- Forcing initial-scale shouldn't be necessary -->
<meta http-equiv="X-UA-Compatible" content="IE=edge"> <!-- Use the latest (edge) version of IE rendering engine -->
<title></title> <!-- The title tag shows in email notifications, like Android 4.4. -->

<!-- Web Font / @font-face : BEGIN -->
<!-- NOTE: If web fonts are not required, lines 9 - 26 can be safely removed. -->

<!-- Desktop Outlook chokes on web font references and defaults to Times New Roman, so we force a safe fallback font. -->
<!--[if mso]>
    <style>
        * {
            font-family: sans-serif !important;
        }
    </style>
<![endif]-->

<!-- All other clients get the webfont reference; some will render the font and others will silently fail to the fallbacks. More on that here: http://stylecampaign.com/blog/2015/02/webfont-support-in-email/ -->
<!--[if !mso]><!-->
    <!-- insert web font reference, eg: <link href='https://fonts.googleapis.com/css?family=Roboto:400,700' rel='stylesheet' type='text/css'> -->
<!--<![endif]-->

<!-- Web Font / @font-face : END -->

<!-- CSS Reset -->
<style>
    /* What it does: Remove spaces around the email design added by some email clients. */
    /* Beware: It can remove the padding / margin and add a background color to the compose a reply window. */
    html,
    body {
        margin: 0 auto !important;
        padding: 0 !important;
        height: 100% !important;
        width: 100% !important;
    }
    
    /* What it does: Stops email clients resizing small text. */
    * {
        -ms-text-size-adjust: 100%;
        -webkit-text-size-adjust: 100%;
    }
    
    /* What is does: Centers email on Android 4.4 */
    div[style*="margin: 16px 0"] {
        margin:0 !important;
    }
    
    /* What it does: Stops Outlook from adding extra spacing to tables. */
    table,
    td {
        mso-table-lspace: 0pt !important;
        mso-table-rspace: 0pt !important;
    }
            
    /* What it does: Fixes webkit padding issue. Fix for Yahoo mail table alignment bug. Applies table-layout to the first 2 tables then removes for anything nested deeper. */
    table {
        border-spacing: 0 !important;
        border-collapse: collapse !important;
        table-layout: fixed !important;
        margin: 0 auto !important;
    }
    table table table {
        table-layout: auto; 
    }
    
    td {
        border: 1px solid #ccc;
    }

    /* What it does: Uses a better rendering method when resizing images in IE. */
    img {
        -ms-interpolation-mode:bicubic;
    }
    
    /* What it does: A work-around for iOS meddling in triggered links. */
    .mobile-link--footer a,
    a[x-apple-data-detectors] {
        color:inherit !important;
        text-decoration: underline !important;
    }
  
</style>
EOT;

$message_tpl = "
<html>
<head>
%s
</head>
<body>
<div>
<h1>%s</h1>
</div>
<div>
<p style='color: #666;'>%s</p>
</div>
<div>
<h3>".__('Brute force attacks to hack passwords or failed logins', 'security-malware-firewall')."</h3>
%s
</div>
<div>
<h3>".__('Brute force attacks to find accounts', 'security-malware-firewall')."</h3>
%s
</div>
<div>
<h3>".__('Successfull logins', 'security-malware-firewall')."</h3>
%s
</div>
<br />
<div style='color: #666;'>
    ".__('The report is provided by', 'security-malware-firewall')." <a href='https://wordpress.org/plugins/security-malware-firewall/'>%s</a>.
    ".sprintf(
    	__('This report has been automatically sent by CleanTalk Security Plugin. Please, enter your access key in %sthe plugin settings.%s', 'security-malware-firewall'),
	    '<a href="' . get_home_url() . '/wp-admin/options-general.php?page=spbc&spbc_tab=settings_general">',
	    '</a>'
	).
"</div>
</body>
</html>
";

$event_part_tpl = <<<EOT
<tr valign="top">
    <td style="border: 1px solid #ccc;">
        %s
    </td>
    <td style="border: 1px solid #ccc;">
        %s
    </td>
</tr>
EOT;

$auth_failed_part = '
<table width="100%%" border="1" padding="1">
<thead>
    <tr style="border: 1px solid #ccc;">
        <th style="border: 1px solid #ccc;">
           '.__('User', 'security-malware-firewall').' 
        </th>
        <th style="border: 1px solid #ccc;">
            IP, # of attempts, Country
        </th>
    </tr>
</thead>
<tbody>
%s
</tbody>
</table>';

$logins_part_tpl = '
<table width="100%%" border="1" padding="1">
<thead>
    <tr style="border: 1px solid #ccc;">
        <th style="border: 1px solid #ccc;">
            '.__('User', 'security-malware-firewall').'
        </th>
        <th style="border: 1px solid #ccc;">
            '.__('Date and time, IP, Country', 'security-malware-firewall').' 
        </th>
    </tr>
</thead>
<tbody>
%s
</tbody>
</table>';

$spbc_tpl = array(
    'logins_part_tpl' => $logins_part_tpl,
    'auth_failed_part' => $auth_failed_part,
    'event_part_tpl' => $event_part_tpl,
    'message_tpl' => $message_tpl,
    'message_style' => $message_style,
);
