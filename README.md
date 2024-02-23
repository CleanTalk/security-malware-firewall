# Security & Malware scan by CleanTalk

![example workflow](https://github.com/CleanTalk/security-malware-firewall/actions/workflows/tests.yml/badge.svg)

**License: GPLv2**

Security, FireWall, Malware scan by CleanTalk, protects from Brute force hacks, online security. Limit Login Attempts. Security plugin.

##Description

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

## Requirements

* PHP 5.6 or higher
* Wordpress 3.0 or higher
* CleanTalk account https://cleantalk.org/register?product_name=security

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
