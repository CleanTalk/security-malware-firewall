=== Security & Malware scan by CleanTalk ===
Contributors: shagimuratov, Aleksandrrazor, sartemd174, security24
Requires at least: 3.0
Stable tag: 2.9
Tested up to: 4.9
Tags: security, Limit Login Attempts, malware, wordpress security, brute force 
License: GPLv2 

Security, FireWall, Malware scan by CleanTalk, protects from Brute force hacks, online security. Limit Login Attempts. Security plugin.

== Description ==

= Security features =
* **Stops brute force attacks to hack passwords**
* **Stops brute force attacks to find WordPress accounts**
* **Limit Login Attempts**
* **Security Protection for WordPress login form**
* **Security Protection for WordPress backend**
* **Security FireWall to filter access to your site by IP, Networks or Countries**
* **Security daily report to email**
* **Security audit log**
* **Real-time traffic monitor**
* **Security Malware scanner with AntiVirus functions**
* **Checking Outbound Links**

CleanTalk is a Cloud security service that protects your website from online threats and provides you great security instruments to control your website security. We provide detailed security stats for all of our security features to have a full control of security. All security logs are stored in the cloud for 45 days.

Security FireWall by CleanTalk is a free plugin which works with the premium Cloud security service cleantalk.org. This security plugin as a service https://en.wikipedia.org/wiki/Software_as_a_service.

Malware always becomes a headache for site owners. If you don’t regularly check for malware, it will be able to work insensibly a lot of time and damage your reputation. If you prevent malware attacks before they happen, you will be able to save your resources.

What is malware and why does it matter to your business? Malware is malicious code that performs actions for hackers. If your site has been infected with malware it will be able a problem for customer trust and their personal details.

First, you need to scan your site to confirm the malware exists. The next step you should fix all files with malware.

= Limit Login Attempts =  
Limit Login Attempts - is a part of brute-force protection and security firewall. Each time, when login/pass was wrong, plugin set the first timeout for 5 attempts within 3 sec, for next attempts timeout will be set to 10 sec. 

Security Firewall has a limit for requests to your website (by default 1000 requests per hour, so you can change it) and if any IP exceed this threshold it will be added to security firewall for next 24 hours. It allows you to break some of the DDoS attacks. 

= Brute Force Protection =

It adds a few seconds delay for any failed attempt to login to WordPress admin area. WordPress Security & Firewall by CleanTalk makes access to your website more secure. Service will check your security log once per hour and if some IP’s have 10 and more attempts to log in per hour, then these IP’s will be banned for next 24 hours.

*Security Audit Log* keeps track of actions in the WP Dashboard to let you know what is happening on your blog.
With the Security Audit Log is very easy to see user activity in order to understand what changes have done and who made them.
Security Audit Log shows who logged in and when and how much time they spent on each page.

= Security Traffic Control =
CleanTalk security Traffic Control will track every single visitor no matter if they are using JavaScript or not and provides many valuable traffic parameters. 

Another option in Security Traffic Control - "Block user after requests amounts more than" - blocks access to the site for any IP that has exceeded the number of HTTP requests per hour. The number of requests can be set in the settings, the default is 1000. If this number of requests will be exceeded, this IP will be added to the FireWall Black List for 24 hours. This is an effective measure against DoS attacks and reduces a load on your web server.

= Security Firewall =
To enhance the security of your site, you can use the CleanTalk FireWall, which will allow you to block access by HTTP/HTTPS to your website for individual IP addresses, IP networks and block access to users from specific countries. Use personal BlackList to block IP addresses with a suspicious activity to enhance the WordPress security.

BlackIPs Database — is the database of the most active IP addresses where massive spam and brute force attacks come from. When IP starts attacking a few websites they are immediately added to the blacklist. IPs that stop attacking are being removed over time and that time is relatively short — usually about 2 weeks.

Security FireWall may significantly reduce the risk of hacking and reduces the load on your web server.

= Security Malware Scanner =
Scans WordPress files for hacker files or code for hacker code.

Security Malware Scanner runs manually in the settings. All of the results will send in your CleanTalk Dashboard with the details and you will be able to investigate them and see if that was a legitimate change or some bad code was injected.

If any files have changed in your WordPress system you will be able to delete them or restore the original WP files.

CleanTalk Antivirus protects your website from viruses and deletes infected code from files. Antivirus scans not only WP core, it will check all of the files on your WordPress. Heuristics antivirus scan allows finding malware/viruses code by bad php constructions. 

= Checking Outbound Links =
Outbound links have an effect on your SEO and when search crawls your web pages all of the outbound links may be an important thing for page ranking.

This option allows you to let know the number of outgoing links from your website and websites on which they linking to. All websites will be checked by our Database and will show results if they were used as links in spam messages. it allows you to check your website and find hidden links or spam links.

You should always remember if you have links to other websites which have a bad reputation, it will be able to have an effect your on visitor's trust and your SEO. 

= Malware Heuristic Check =
This option allows you to check files of plugins and themes with heuristic analysis. Probably it will find more than you expect.

The core files are files that go with WordPress distributive. Any other PHP files laying in WordPress directory (except /wp-content/) are unknown and should be properly scanned. Even if we found something in these files they will also show up in the Unknown category to let you know that they are third-party files.

Every file in /wp-content/* will be checked with a heuristic. And the check can find many interesting. If you see there many finds, don't panic, it shows you only possible weak spots.

Malware Heuristic analyses the code by simplifying it and looks for suspicious functions and constructs which are usually used by hackers. For example eval construct http://php.net/manual/en/function.eval.php and much other suspicious stuff.

= Malware scanner to find SQL Injections =

What is SQL injection?

This is an attack on the database, which will allow performing some action that was not planned by the script creator.

SQL injection is one of the most accessible ways to hack a site. With using it, hackers "read" the contents of any tables, delete, modify or add information to the database, overwrite the contents of local files and give commands to execute arbitrary commands. In other words, they completely intercept the management of the attacked site.
The essence of such injections is the introduction of arbitrary SQL code into data (transmitted via GET, POST requests or Cookie values). If the site is vulnerable and performs such injections, then in fact there is an opportunity to create from the database (most often it's MySQL) anything.

The CleanTalk Malware Scanner allows you to find code that allows performing SQL injection. It is this problem that the scanner solves.

== Frequently Asked Questions ==

= Why are they attacking me? =
Hackers want to get access to your website and use it to get backlinks from your site to improve their site’s PageRank or redirect your visitors to malicious sites or use your website to send spam and viruses or other attacks.These attacks can damage your reputation with readers and commentators if you fail to tackle it. It is not uncommon for some WordPress websites to receive hundreds or even thousands of attacks every week. However, by using the Security CleanTalk plugin, all attacks will be stopped on your WordPress website.

= How to install the plugin? =
Installing the plugin is very simple and does not require much time or special knowledge.

**Manual installation** 

1. Download latest version on your computer's hard drive,

<a
href="https://downloads.wordpress.org/plugin/security-malware-firewall.zip">https://downloads.wordpress.org/plugin/security-malware-firewall.zip</a>

1. Go to your WordPress Dashboard->Plugins->Add New->Upload CleanTalk zip file.

1. Click Install Now and Activate.

1. After activated, go to plugin settings. Then you will need to create an API key, this is done automatically for you. Just click on "Get access key automatically"

Installation completed successfully.

**Installation from wordpress.org directory**

1. Navigate to Plugins Menu option in your WordPress administration panel and click the button "Add New".

1. Type CleanTalk in the Search box, and click Search plugins.

1. When the results are displayed, click Install Now.

1. Select Install Now.

1. Then choose to Activate the plugin.

1. After activated, go to plugin settings. Then you will need to create an API key, this is done automatically for you. Just click on "Get access key automatically"

Installation completed successfully.

= How to test the security service? = 
Please use the wrong username or password to log-in to your WP admin panel to see how the Security Plugin works. Then you may log-in with your correct account name and see the logs for the last actions in the settings or our plugin. Also, Audit Log will display the last visited URL's of the current user.

= Is the plugin compatible with WordPress MultiUser (WPMU or WordPress network)? = 
Yes, the plugin is compatible with WordPress MultiUser. 

= How to control security activities on your website? =
Go to your CleanTalk account->Log. Use filters to sort data for analyses.

Security logs provide you to receive and keep information for 45 days. You have the following possibilities:
1. Time period for all records you want to see.

2. Website for which you want to see security records. Leave the field empty to see security records for all websites.

3. Choose an event you want to see:
 * Authorization Login — all successful logins to your website.
 * Authorization Logout — all closed sessions.
 * Authorization Invalid username — login attempts with not existing username.
 * Authorization Auth failed — wrong password login attempts.
 * Audit View — records of actions and events of users in your website backend.

4. Searching records by IP address.

5. Searching records by country.
 
There are date and time of events for each record, username who performed an action and his IP (country) address. How to use Security Log https://cleantalk.org/help/Security-Log
 
= Is it possible to set custom email for notification? =
Yes, it is possible. Go to your CleanTalk account->Change email https://cleantalk.org/my/change-email

= Why do you need an access key? =
Access Key allows you to keep statistics up to 45 days in the cloud and different additional settings and has more possibilities to sort the data and analyses. Our plugin evolves to Cloud Technology and all its logs are transferred to Cloud. Cloud Service takes data processing and data storage and allows to reduce your webserver load.

= How to use Security Log = 

  * First go to your Security Dashboard. Choose "Site Security" in the "Services" menu.
  * Then go to your Security Log.

You have the following possibilities:

  * Time period for all records you want to see.
  * Website for which you want to see security records. Leave the field empty to see security records for all websites.

Choose an event you want to see:

  * Authorization Login — all successful logins to your website.
  * Authorization Logout — all closed sessions.
  * Authorization Invalid username — login attempts with not existing username.
  * Authorization Auth failed — wrong password login attempts.

Audit View — records of actions and events of users in your website backend.

  * Searching records by IP address.
  * Searching records by username.
  * Searching records by country.

List of records. Each record has the following columns:

  * Date — when the event happened.
  * User Log — who performed actions.
  * Event — what did he do.
  * Status — was he Passed or Banned.
  * IP — his IP address.
  * Country — what country that IP belongs to.
  * Details — some details if they are available.

Please, read more 
https://cleantalk.org/help/Security-Log

If you wish to block some countries from visiting your website, please, use this instruction: https://cleantalk.org/help/Security-Firewall

= How to use Security Firewall =
First go to your Security Dashboard. Choose "Site Security" in the "Services" menu. Then press the line "Black&White Lists" under the name of your website.

You can add records of different types to your black list or white list:

  * IP-Addresses (For example 10.150.20.250, 10.10.10.10)
  * Subnets (For example 10.150.20.250/24, 10.10.10.10/8)
  * Countries. Click the line "Add a country" to blacklist or whitelist all IP-addresses of the chosen countries.

The records can be added one by one or all at once using separators: comma, semicolon, space, tab or new line. After filling the field press the button "Whitelist" or "Blacklist". All added records will be displayed in your list below. Please note, all changes will be applied in 5-10 minutes.

Please, read full instruction here
https://cleantalk.org/help/Security-Firewall

= How to test Security Firewall? =

1. Open another browser or enter the incognito mode.
2. Type address YOUR_WEBSITE/?security_test_ip=ANY_IP_FROM_BLACK_LIST
2.1 Address 10.10.10.10 is local address and it's in blacklist constantly. So address YOUR_WEBSITE/?security_test_ip=10.10.10.10 will works everytime.
3. Make sure that you saw page with the blocking message.
4. FireWall works properly, if it is not, see item 4 of the list.

= How does malware scanner work? =
Malware scanner will check and compare with the original WP files and show you what files were changed, deleted or added. Malware scanner could be used to find an added code in WP files. On your Malware Security Log page, you will see the list of all scans that were performed for your website. The CleanTalk Cloud saves the list of the found files for you to know where to look them for.

= How to start malware scanner? =
At the moment malware scanner may be started one time per day and manually. 
To start malware scanner go to the WordPress Admin Page —> Settings —> Security by CleanTalk —> "Malware Scanner" tab —> Perform Scan.
Give the Malware Scanner some time to check all necessary files on your website.

= Is it free or paid? =
The plugin is free. But the plugin uses CleanTalk cloud security service. You have to register an account and then you will receive a free trial to test. When the trial (on CleanTalk account) is finished, you can renew the subscription for 1 year or deactivate the Security by CleanTalk plugin.
If you haven’t got access key, the plugin will work and you will have logs only on the plugin settings page for last 20 requests.

= What happens after the end of the trial period? =
The plugin will fully perform its functions after the end of the trial period and will protect your website from brute force attacks and will keep Action Log in your WP Dashboard, but the number of entries in the log will be limited to the last 20 entries/24 hours. Also, you will receive a short daily security report to your email. 

Premium version allows to storage all logs for 45 days in the CleanTalk Dashboard for further analysis.

= Email Notifications when administrators are logged in =

Do you want to receive a notice each time a user with administrator rights is logged into the WP Dashboard?

We added this option to our security plugin. Now you can receive notifications if you want to know about an unauthorized entrance to your WP Dashboard.

Notification will be sent only when a user was able to authorize entering login and password. If you are logged into the admin panel from the saved session, then the alert won’t be sent.

You can enable the option “Receive notifications for admin authorizations in your CleanTalk Dashboard. Choose “Site Security” in the “Services” menu, then click “Settings”.

= Can CleanTalk Security protect from DDoS? =

Security FireWall can mitigate HTTP/HTTPS DDoS attacks. When an intruder makes GET requests to attack your website, Security FireWall blocks all requests from bad IP addresses. If your website under DDoS attack you will be able to add IPs to your personal BlackList to block all Post and GET requests.

= Brute Force security for Wordpress =

Brute force attack is an exhaustive password search to get full access to an Administrator account. Passwords are not the hard part for hackers taking into account the quantity of sent password variants per second and the big amount of IP-addresses.

Brute force attack is one of the most security issues as an intruder gets full access to your website and can change your code. Consequences of these break-ins might be grievous, your website could be added to the [botnet] and it could participate in attacks to other websites, it could be used to keep hidden links or automatic redirection to a suspicious website. Consequences for your website reputation might be very grievous.

== Screenshots ==

1. **Security report**. The report includes list of Brute force attacks or failed logins and list of successful logins. The plugin sends the reports daily. 
2. **Security Log**. The log includes list of Brute force attacks or failed logins and list of successful logins for up to 45 days. To do the log is not accessible for hackers the plugin keeps the log on CleanTalk servers. 
3. **General settings tab**. Here you can control all of the plugin's functions. 
4. **Brute-force attacks log tab**. The log includes list of attacks for past 24 hours and shows only last 20 records. To see the full report please check the Daily security report in your Inbox. 
5. **Traffic control tab**. Appears only if Traffic control is enabled. Shows all visitors of the website with details (IP, User-Agent, URL, etc.).
6. **Malware scanner tab**. Here  you can scan all Wordpress files for malicious and suspicious code.

== Changelog ==
= 2.10 May 16 2018 =
 * New: Links scanner checks links for spam activity.
 * New: Resigned settings tabs.
 * Fix: Scanner memory usage significantly decreased.
 * Fix: Update system.
 * Minor fixes.

= 2.9 April 24 2018 =
 * Mod: SQL-injection search.
 * Fix: IP detection. PHP Warning.
 * Fix: Empty username in security log.
 * Fix: Possible SSL error.

= 2.8.3 April 6 2018 =
 * Fix: IP detection and PHP Warnings.

= 2.8.2 April 6 2018 =
 * Fix: Bad IP addresses in security log.

= 2.8.1 April 5 2018 =
 * Fix: For servers without Apache.
 * Fix: Links scanner. Scanning always will be performed completely.

= 2.8 April 4 2018 =
 * Fix: Spelling and layout.
 * Fix: False allow_url_fopen error.
 * Modification: IPv6 Support.
 * Modification: Trusted networks support.
 * Modification: Links scanner accelerated.
 * Minor error fixes.

= 2.7 March 22 2018 =
 * Fix: Few PHP Notices.
 * Fix: Spelling and layout.
 * Fix: Decreased amount of false positives in Malware Scanner. Security scanner improved.
 * Fix: WPMS - errors messages in settings on secondary website.
 * Minor error fixes.
 
 = 2.6.2 March 12 2018 =
 * Fix: Cron loop.

= 2.6.1 March 8 2018 =
 * Fix: PHP Notices.

= 2.6 March 7 2018 =
 * New: Autoupdate functionality.
 * New: Advanced error reporting system.
 * Scanner: Scanning with allow_url_fopen disabled.
 * Scanner: Precision improved.
 * Scanner: Complete scanning in background mode.
 * FireWall: Improved IP detection.
 * Improvings: Security and reliability.
 * Minor fixes.

= 2.5 February 19 2018 =
 * New: Heuristic scan.
 * New: Plugins and themes scan.
 * Scanning quality improved.
 * Layout fixes and improvements.
 * Minor fixes.

= 2.4 February 6 2018 =
 * Minor fixes.
 * Outbound links scanner.
 * Security scanner improvements.

= 2.3 January 16 2018 =
 * Fix: Spelling.
 * Fix: Decreased CPU load for some cases.
 * Fix: Security scanner status.
 * Interface: Showing more info on Traffic Control tab, added links to control IP-addresses.

= 2.2.1 December 26 2017 =
 * Fix: Security FireWall IP detection improved.

= 2.2 December 20 2017 =
 * Improvements: Security scanner.
 * Fix: Issue with periodically scan.
 * Minor error fixes.

= 2.1 December 13 2017 =
 * Errors detection improved.
 * Security functions improved.
 * Cron updated.
 * Minor error fixes.

= 2.0.1 December 5 2017 =
 * Minor error fixes.
 * Layout fixes.
 * Improved security scanner logic.

= 2.0 December 4 2017 =
 * Added Malware Scanner.
 * Error fixes.
 * Improved update logic.

= 1.29.1 November 27 2017 =
 * Error fix.

= 1.29 November 23 2017 =
 * Security improvements.
 * Error fixes.

= 1.28 November 8 2017 =
 * Security firewall fixes.

= 1.27 November 3 2017 =
 * Improved security logs displaying.
 * Fixed issue with DB errors.
 * Many other small fixes and improvements.

= 1.26 October 16 2017 =
 * Fixed issue with high CPU load.
 * Some small fixes for WPMS.
 * Security functionality improved.

= 1.25 October 2 2017 =
 * Recognizing real IP when using Cloudflare CDN.
 * Admin notices and displaying fixes for WPMS.
 * Minor fixes.

= 1.24 September 20 2017 =
 * Fix for Security Firewall under Worpdress Multisite with inherited access key.
 * Traffic Control log is now been updated automatically.
 * Minor fixes.

= 1.23 September 15 2017 =
 * Security Firewall updated.
 * Fixed an issue with FireWall whitelist.
 * Fixes for WPMS.

= 1.22 August 31 2017 =
 * Major fix for Wordpress Miltisite functionality.
 * Improved security functionality.
 * Minor fixes.

= 1.21.1 August 24 2017 =
 * Last actions to view 20.

= 1.21 August 24 2017 =
 * Added "Set cookies" setting.
 * Added Traffic Control feature.
 * Optimization.
 * Fixes for the cron jobs.

= 1.20.2 July 7 2017 =
 * Fix the daily report sending function.

= 1.20.1 July 5 2017 =
 * Minor fixes.

= 1.20 July 3 2017 =
 * Fixes for cron system.
 * Some small fixes.
 * Stability and security were improved.

= 1.19 June 15 2017 =
 * Added the secured tasks running system (cron) instead of using wp_cron.

= 1.18 June 7 2017 =
 * Security settings have been redesigned.

= 1.17 May 24 2017 =
 * Improved security functions.
 * Sending protected URL and other info to the cloud.

= 1.16 May 16 2017 =
 * Small security fixes.
 * Blocking page cache issues fix.

= 1.15 April 24 2017 =
 * Small security fixes.
 * Translation fix.

= 1.14 April 13 2017 =
 * Major fix for Security FireWall.
 * Translation fix.
 * Changes for settings screen  (Support button added).
 * Improved performance.
 
 
= 1.13 April 5 2017 =
 * Fix for 'Let them know about security protection' option.
 * Minor fixes to improve security logic.
 * Added 'Complete deactivation' option.

= 1.12 March 30 2017 =
 * Major fix for security firewall.
 * Small fixes for settings page.
 * Fixed WPDB Warnings for new users.
 * 'Complete deactivation' option was added.
 
= 1.11.1 March 24 2017 =
 * Fixed issue with database prefix.
 * Small fixes to improve security logic.

= 1.11 March 23 2017 =
 * Security has been improved. Added email notifications to account owner about superuser login to WordPress backend. 
 * Brute force protection logic has been updated. 

= 1.10.1 March 17 2017 =
 * Fixed issue with exit() statement. 

= 1.10 March 17 2017 =
 * Improved anti brute force protection. An anti brute force notice has been added on sign in form.
 * Fixed logic to process remote calls.
 * Small fixes to improve security logic.

= 1.9.6 March 14 2017 =
 * Fixed anti brute force logic to avoid issue with emails scanning. 
 * Small fixes to improve security logic.

= 1.9.5 March 7 2017 =
 * Database fix (support DB prefix with digits).
 * Fix for admin notices.
 * Small fixes to improve security logic.

= 1.9.4 March 2 2017 =
 * Small fixes (WPMS settings logic, FireWall).
 * Added option for notification on login page.
 * Small fixes to improve security logic.

= 1.9.3 February 28 2017 =
 * Packets SQL requests for FireWall updates.
 * Small fixes (User token gaining)
 * Notification changes

= 1.9.2 February 16 2017 = 
 * Bug fixes.
 * Automatic FireWall update time increased to 1 day.
 
= 1.9.1 February 8 2017 = 
 * Minor bug fixes.

= 1.9 January 26 2017 = 
 * Added new feature Security FireWall.
 * Common optimization.
 * Minor bug fixes.

= 1.8.2 January 16 2017 = 
 * Cron hooks fix

= 1.8.1 December 29 2016 = 
 * Translation fix
 
= 1.8 December 23 2016 = 
 * Fixes for settings page.
 * Showing last logs sending time in settings.

= 1.7.2 December 19 2016 = 
 * Fixed issue with logging for brute-force attacks. 

= 1.7.1 December 13 2016 = 
 * Fix for translation system.
 * Added Russian language support.
 * Minor fixes.

= 1.7 December 12 2016 = 
 * Added support for WPMS.
 * Personal log possibility for each website.
 * Translation system attached.
 * Varnish extension compatibility.

= 1.6.1 November 29 2016 = 
 * Fixed error for some PHP versions.

= 1.6 November 29 2016 = 
 * Cloud service API key.
 * Cloud service dashboard.
 * Logs are stored in Cloud.
 * Protection status.
 * Code optimization.

= 1.5.2 November 16 2016 = 
 * Fixed conflict with CleanTalk Anti-spam plugin.

= 1.5.1 November 14 2016 = 
 * Fixed and improve log.
 * Fixed database error.
 * Changed update logic.

= 1.5 November 13 2016 = 
 * Logging viewed admin's page.
 * Counting viewed time.
 
= 1.4.3 November 2 2016 = 
 * Fixed issue with Security report. On some hostings the report couldn't be send by WP Cron because of PHP Fatal error with spbc_report_country_part().  

= 1.4.2 October 20 2016 = 
 * Improved the Security log. The new version includes brute force attacks to find WordPress accounts.
 * Applied changes to localize the plugin via Translating WordPress.org.
 * Minor backend fixes.

= 1.3.1 September 29 2016 = 
 * Fixed issue with PHP 5.2 and Security reports.
 * Fixed issue with WordPress notice after plugin activation.

= 1.3 September 20 2016 = 
 * Added a log of last 20 events (login, logout, auth failed and etc.) in WordPress backend to the plugin settings.
 * Added WP cron call for every auth_failed event. This fix has been made to avoid issue with missed Daily security reports on low visited web sites.

= 1.2.3 September 14 2016 = 
 * Added a country name in the Daily report for each IP address in the list of Brute-Force attacks.
 * Minor changes with WP Cron integration. 

= 1.2.1 September 5 2016 = 
 * Fixed issue with Daily security report. Previous version (1.2) didn't send the report.

= 1.2 September 2 2016 = 
 * Added Daily security report. The report includes list of Brute-force attacks or failed logins and list of successful logins. 

= 1.1.1 August 29 2016 = 
 * Removed some statement to debug the plugin. 

= 1.1 August 29 2016 = 
 * Added 10 seconds delay for a failed attempt if more then 5 failed attempts have been made for past 1 hour. 

= 1.0.1 August 24 2016 = 
 * Minor fix.  

= 1.0 August 19 2016 =
 * First release with anti brute force hacks protection.

== Upgrade Notice ==
= 2.10 May 16 2018 =
 * New: Links scanner checks links for spam activity.
 * New: Resigned settings tabs.
 * Fix: Scanner memory usage significantly decreased.
 * Fix: Update system.
 * Minor fixes.

= 2.9 April 24 2018 =
 * Mod: SQL-injection search.
 * Fix: IP detection. PHP Warning.
 * Fix: Empty username in security log.
 * Fix: Possible SSL error.

= 2.8.3 April 6 2018 =
 * Fix: IP detection and PHP Warnings.

= 2.8.2 April 6 2018 =
 * Fix: Bad IP addresses in security log.

= 2.8.1 April 5 2018 =
 * Fix: For servers without Apache.
 * Fix: Links scanner. Scanning always will be performed completely.

= 2.8 April 4 2018 =
 * Fix: Spelling and layout.
 * Fix: False allow_url_fopen error.
 * Modification: IPv6 Support.
 * Modification: Trusted networks support.
 * Modification: Links scanner accelerated.
 * Minor error fixes.

= 2.7 March 22 2018 =
 * Fix: Few PHP Notices.
 * Fix: Spelling and layout.
 * Fix: Decreased amount of false positives in Malware Scanner. Security scanner improved.
 * Fix: WPMS - errors messages in settings on secondary website.
 * Minor error fixes.

= 2.6.2 March 12 2018 =
 * Fix: Cron loop.

= 2.6.1 March 8 2018 =
 * Fix: PHP Notices.

= 2.6 March 7 2018 =
 * New: Autoupdate functionality.
 * New: Advanced error reporting system.
 * Scanner: Scanning with allow_url_fopen disabled.
 * Scanner: Precision improved.
 * Scanner: Complete scanning in background mode.
 * FireWall: Improved IP detection.
 * Improvings: Security and reliability.
 * Minor fixes.

= 2.5 February 19 2018 =
 * New: Heuristic scan.
 * New: Plugins and themes scan.
 * Scanning quality improved.
 * Layout fixes and improvements.
 * Minor fixes.

= 2.4 February 6 2018 =
 * Minor fixes.
 * Outbound links scanner.
 * Security scanner improvements.

= 2.3 January 16 2018 =
 * Fix: Spelling.
 * Fix: Decreased CPU load for some cases.
 * Fix: Security scanner status.
 * Interface: Showing more info on Traffic Control tab, added links to control IP-addresses.

= 2.2.1 December 26 2017 =
 * Fix: Security FireWall IP detection improved.

= 2.2 December 20 2017 =
 * Improvements: Security scanner.
 * Fix: Issue with periodically scan.
 * Minor error fixes.

= 2.1 December 13 2017 =
 * Errors detection improved.
 * Security functions improved.
 * Cron updated.
 * Minor error fixes.

= 2.0.1 December 5 2017 =
 * Minor error fixes.
 * Layout fixes.
 * Improved security scanner logic.

= 2.0 December 4 2017 =
 * Added Malware Scanner.
 * Error fixes.
 * Improved update logic.

= 1.29.1 November 27 2017 =
 * Error fix.

= 1.29 November 23 2017 =
 * Security improvements.
 * Error fixes.

= 1.28 November 8 2017 =
 * Security firewall fixes.

= 1.27 November 3 2017 =
 * Improved security logs displaying.
 * Fixed issue with DB errors.
 * Many other small fixes and improvements.

= 1.26 October 16 2017 =
 * Fixed issue with high CPU load.
 * Some small fixes for WPMS.
 * Security functionality improved.

= 1.25 October 2 2017 =
 * Recognizing real IP when using Cloudflare CDN.
 * Admin notices and displaying fixes for WPMS.
 * Minor fixes.

= 1.24 September 20 2017 =
 * Fix for Security Firewall under Worpdress Multisite with inherited access key.
 * Traffic Control log is now been updated automatically.
 * Minor fixes.

= 1.23 September 15 2017 =
 * Security Firewall updated.
 * Fixed an issue with FireWall whitelist.
 * Fixes for WPMS.

= 1.22 August 31 2017 =
 * Major fix for Wordpress Miltisite functionality.
 * Improved security functionality.
 * Minor fixes.

= 1.21.1 August 24 2017 =
 * Last actions to view 20.

= 1.21 August 24 2017 =
 * Added "Set cookies" setting.
 * Added Traffic Control feature.
 * Optimization.
 * Fixes for the cron jobs.

= 1.20.2 July 7 2017 =
 * Fix the daily report sending function.

= 1.20.1 July 5 2017 =
 * Minor fixes.

= 1.20 July 3 2017 =
 * Fixes for cron system.
 * Some small fixes.
 * Stability and security were improved.

= 1.19 June 15 2017 =
 * Added the secured tasks running system (cron) instead of using wp_cron.

= 1.18 June 7 2017 =
 * Security settings have been redesigned.

= 1.17 May 24 2017 =
 * Improved security functions.
 * Sending protected URL and other info to the cloud.

= 1.16 May 16 2017 =
 * Small security fixes.
 * Blocking page cache issues fix.
 
= 1.15 April 24 2017 =
 * Small security fixes.
 * Translation fix.
 
= 1.14 April 13 2017 =
 * Major fix for Security FireWall.
 * Translation fix.
 * Changes for settings screen  (Support button added).
 * Improved performance.

= 1.13 April 5 2017 =
 * Fix for 'Let them know about protection' option.
 * Minor fixes.
 * Added 'Complete deactivation' option.

= 1.12 March 30 2017 =
 * Major fix for security firewall.
 * Small fixes for settings page.
 * Fixed WPDB Warnings for new users.
 * 'Complete deactivation' option was added.

= 1.11.1 March 24 2017 =
 * Fixed issue with database prefix.
 * Smal fixes.

= 1.11 March 23 2017 =
 * Security has been improved. Added email notifications to account owner about superuser login to WordPress backend. 
 * Brute force protection logic has been updated. 

= 1.10.1 March 17 2017 =
 * Fixed issue with exit() statement.
 
= 1.10 March 17 2017 =
 * Improved anti brute force protection. An anti brute force notice has been added on sign in form.
 * Fixed logic to process remote calls.

= 1.9.6 March 14 2017 =
 * Fixed anti brute force logic to avoid issue with emails scanning.
 
= 1.9.5 March 7 2017 =
 * Database fix (support DB prefix with digits).
 * Fix for admin notices.

= 1.9.4 March 2 2017 =
 * Small fixes (WPMS settings logic, FireWall).
 * Added option for notification on login page.

= 1.9.3 February 28 2017 =
 * Packets SQL requests for FireWall updates.
 * Small fixes (User token gaining)
 * Notification changes

= 1.9.2 February 16 2017 = 
 * Bug fixes.
 * Automatic FireWall update time increased to 1 day.

= 1.9.1 February 8 2017 = 
 * Minor bug fixes.

= 1.9 January 26 2017 = 
 * Added new feature Security FireWall.
 * Common optimization.
 * Minor bug fixes.

= 1.8.2 January 16 2017 = 
 * Cron hooks fix

= 1.8.1 December 29 2016 = 
 * Translation fix

= 1.8 December 23 2016 = 
 * Fixes for settings page.
 * Showing last logs sending time in settings.

= 1.7.2 December 19 2016 = 
 * Fixed issue with logging for brute-force attacks. 

= 1.7.1 December 13 2016 = 
 * Fix for translation system.
 * Added Russian language support.
 * Minor fixes.

= 1.7 December 12 2016 = 
 * Added support for WPMS.
 * Personal log possibility for each website.
 * Translation system attached.
 * Varnish extension compatibility.

= 1.6.1 November 29 2016 = 
 * Fixed error for some PHP versions.

= 1.6 November 29 2016 = 
 * Cloud service API key.
 * Cloud service dashboard.
 * Logs are stored in Cloud.
 * Protection status.
 * Code optimization.

= 1.5.2 November 16 2016 = 
 * Fixed conflict with CleanTalk Anti-spam plugin.
 
= 1.5.1 November 14 2016 = 
 * Fixed and improve log.
 * Fixed database error.
 * Changed update logic.

= 1.5 November 13 2016 = 
 * Logging viewed admin's page.
 * Counting viewed time.

= 1.4.3 November 2 2016 = 
 * Fixed issue with Security report. On some hostings the report couldn't be send by WP Cron because of PHP Fatal error with spbc_report_country_part().  

= 1.4.2 October 20 2016 = 
 * Improved the Security log. The new version includes brute force attacks to find WordPress accounts.
 * Applied changes to localize the plugin via Translating WordPress.org.
 * Minor backend fixes.

= 1.3.1 September 29 2016 = 
 * Fixed issue with PHP 5.2 and Security reports.
 * Fixed issue with WordPress notice after plugin activation.

= 1.3 September 20 2016 = 
 * Added a log of last 20 events (login, logout, auth failed and etc.) in WordPress backend to the plugin settings.
 * Added WP cron call for every auth_failed event. This fix has been made to avoid issue with missed Daily security reports on low visited web sites.

= 1.2.1 September 5 2016 = 
 * Fixed issue with Daily security report. Previous version didn't send the report. 

