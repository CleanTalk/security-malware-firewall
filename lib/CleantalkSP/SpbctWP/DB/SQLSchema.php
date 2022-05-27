<?php


namespace CleantalkSP\SpbctWP\DB;


class SQLSchema extends \CleantalkSP\Common\DB\SQLSchema {
    
    /**
     * @var string[]
     */
    protected static $field_standard = array('field' => '', 'type' => '', 'null' => '', 'default' => '', 'extra' => '');
    
    /**
     * Set of SQL-schemas for tables in array
     * Set for all websites. Should installed with a main database prefix
     *
     * @var array
     */
    protected static $schemas__common = array(

        'firewall_data' => array(
            'columns' => array(
                array('field' => 'id',           'type' => 'char(32)',     'null' => 'no',),
                array('field' => 'network1',     'type' => 'int unsigned', 'null' => 'no',  'default' => '0',),
                array('field' => 'network2',     'type' => 'int unsigned', 'null' => 'no',  'default' => '0',),
                array('field' => 'network3',     'type' => 'int unsigned', 'null' => 'no',  'default' => '0',),
                array('field' => 'network4',     'type' => 'int unsigned', 'null' => 'no',  'default' => '0',),
                array('field' => 'mask1',        'type' => 'int unsigned', 'null' => 'no',  'default' => '0',),
                array('field' => 'mask2',        'type' => 'int unsigned', 'null' => 'no',  'default' => '0',),
                array('field' => 'mask3',        'type' => 'int unsigned', 'null' => 'no',  'default' => '0',),
                array('field' => 'mask4',        'type' => 'int unsigned', 'null' => 'no',  'default' => '0',),
                array('field' => 'country_code', 'type' => 'char(2)',      'null' => 'yes', 'default' => 'NULL',),
                array('field' => 'status',       'type' => 'tinyint',      'null' => 'yes',),
            ),
            'indexes'    => array(
                array('type' => 'PRIMARY', 'name' => 'KEY',     'body' => '(`id`)'),
                array('type' => 'INDEX',   'name' => 'network', 'body' => '(`network1`, `network2`, `network3`, `network4`, `mask1`, `mask2`, `mask3`, `mask4`)'),
            ),
        ),

        'scan_results' => array(
            'columns' => array(
                array('field'=>'path',           'type' => 'varchar(1024)', 'null' => 'no',),
                array('field'=>'size',           'type' => 'int',           'null' => 'no', 'default' => '0',),
                array('field'=>'perms',          'type' => 'int',           'null' => 'no', 'default' => '0',),
                array('field'=>'mtime',          'type' => 'int',           'null' => 'no', 'default' => '0',),
                array('field'=>'detected_at',    'type' => 'int',           'null' => 'yes', 'default' => 'NULL'),
                array('field'=>'source_type',    'type' => 'enum("CORE", "PLUGIN", "THEME")', 'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'source',         'type' => 'varchar(300)',  'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'source_status',  'type' => 'set("UP_TO_DATE","OUTDATED","NOT_IN_DIRECTORY","UNKNOWN")', 'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'version',        'type' => 'varchar(20)',   'null' => 'yes', 'default' => 'NULL',),
				array('field'=>'checked',        'type' => 'enum("NO", "YES", "YES_SIGNATURE", "YES_HEURISTIC")', 'null' => 'no', 'default' => '"NO"',),
                array('field'=>'checked_heuristic',   'type' => 'int', 'null' => 'no', 'default' => '0',),
                array('field'=>'checked_signatures',  'type' => 'int', 'null' => 'no', 'default' => '0',),
                array('field'=>'status',         'type' => 'enum("UNKNOWN","OK","APROVED","APPROVED_BY_CT","MODIFIED","INFECTED","QUARANTINED")', 'null' => 'no', 'default' => '"UNKNOWN"',),
                array('field'=>'severity',       'type' => 'enum("CRITICAL", "DANGER", "SUSPICIOUS", "NONE")', 'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'weak_spots',     'type' => 'varchar(2048)', 'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'difference',     'type' => 'varchar(1024)', 'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'last_sent',      'type' => 'int',           'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'fast_hash',      'type' => 'varchar(32)',   'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'full_hash',      'type' => 'varchar(32)',   'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'real_full_hash', 'type' => 'varchar(32)',   'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'previous_state', 'type' => 'varchar(1024)', 'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'q_path',         'type' => 'varchar(1024)', 'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'q_time',         'type' => 'int',           'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'analysis_status',  'type' => 'ENUM("NEW","SAFE","DANGEROUS")', 'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'analysis_comment', 'type' => 'VARCHAR(1024)',                  'null' => 'yes', 'default' => 'NULL',),
            ),
            'indexes'      => array(
                array('type' => 'UNIQUE',  'name' => 'KEY', 'body' => '(`fast_hash`)'),
            ),
        ),

        'scan_links_logs' => array(
            'columns' => array(
                array('field'=>'link_id',     'type' => 'int',           'null' => 'no', 'extra' => 'AUTO_INCREMENT'),
                array('field'=>'scan_id',     'type' => 'int',           'null' => 'no',),
                array('field'=>'domain',      'type' => 'tinytext',      'null' => 'no',),
                array('field'=>'link',        'type' => 'varchar(2048)', 'null' => 'no',),
                array('field'=>'link_text',   'type' => 'varchar(2048)', 'null' => 'no',),
                array('field'=>'page_url',    'type' => 'varchar(2048)', 'null' => 'no',),
                array('field'=>'spam_active', 'type' => 'tinyint',       'null' => 'yes',),
            ),
            'indexes' => array(
                array('type' => 'PRIMARY', 'name' => 'KEY',         'body' => '(`link_id`)'),
                array('type' => 'INDEX',   'name' => 'spam_active', 'body' => '(`spam_active`)'),
                array('type' => 'INDEX',   'name' => 'scan_id',     'body' => '(`scan_id`)'),
                array('type' => 'INDEX',   'name' => 'domain',      'body' => '(`domain`(40))'),
            ),
        ),

        'scan_frontend' => array(
            'columns' => array(
                array('field'=>'page_id',        'type' => 'varchar(1024)', 'null' => 'no',),
                array('field'=>'url',            'type' => 'varchar(1024)', 'null' => 'no',),
                array('field'=>'dbd_found',      'type' => 'tinyint',       'null' => 'yes',),
                array('field'=>'redirect_found', 'type' => 'tinyint',       'null' => 'yes',),
                array('field'=>'signature',      'type' => 'tinyint',       'null' => 'yes',),
                array('field'=>'bad_code',       'type' => 'tinyint',       'null' => 'yes',),
                array('field'=>'csrf',           'type' => 'tinyint',       'null' => 'yes',),
                array('field'=>'weak_spots',     'type' => 'varchar(2048)', 'null' => 'yes',),
            ),
            'indexes' => array(),
        ),

        'scan_signatures' => array(
            'columns' => array(
                array('field'=>'id',          'type' => 'int unsigned', 'null' => 'no', 'extra' => 'AUTO_INCREMENT'),
                array('field'=>'name',        'type' => 'varchar(128)', 'null' => 'no',),
                array('field'=>'body',        'type' => 'varchar(512)', 'null' => 'no',),
                array('field'=>'type',        'type' => 'enum("FILE","CODE_PHP","CODE_HTML","CODE_JS","WAF_RULE")', 'null' => 'no',),
                array('field'=>'attack_type', 'type' => 'set("SQL_INJECTION","XSS","MALWARE","EXPLOIT","SUSPICIOUS")', 'null' => 'no',),
                array('field'=>'waf_action',  'type' => 'enum("DENY","LOG","ALLOW")', 'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'submitted',   'type' => 'datetime', 'null' => 'no',),
                array('field'=>'cci',         'type' => 'text',     'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'waf_headers', 'type' => 'varchar(1024)', 'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'waf_url',     'type' => 'varchar(512)',  'null' => 'yes', 'default' => 'NULL',),
            ),
            'indexes'   => array(
                array('type' => 'PRIMARY', 'name' => 'KEY', 'body' => '(`id`)'),
                array('type' => 'UNIQUE',  'name' => 'KEY', 'body' => '(`name`)'),
            ),
        ),

        'backuped_files' => array(
            'columns' => array(
                array('field'=>'id',        'type' => 'int unsigned', 'null' => 'no', 'extra' => 'AUTO_INCREMENT'),
                array('field'=>'backup_id', 'type' => 'int unsigned', 'null' => 'no',),
                array('field'=>'real_path', 'type' => 'varchar(512)', 'null' => 'no',),
                array('field'=>'back_path', 'type' => 'varchar(512)', 'null' => 'no',),
            ),
            'indexes'   => array(
                array('type' => 'PRIMARY', 'name' => 'KEY', 'body' => '(`id`)'),
            ),
        ),

        'backups' => array(
            'columns' => array(
                array('field'=>'backup_id', 'type' => 'int unsigned',                                                    'null' => 'no', 'extra' => 'AUTO_INCREMENT'),
                array('field'=>'type',      'type' => 'enum("FILE","ALL","SIGNATURES")',                                     'null' => 'no', 'default' => '"FILE"',),
                array('field'=>'datetime',  'type' => 'datetime',                                                            'null' => 'no',),
                array('field'=>'status',    'type' => 'enum("PROCESSING", "BACKUPED", "ROLLBACK", "ROLLBACKED", "STOPPED")', 'null' => 'no', 'default' => '"PROCESSING"',),
            ),
            'indexes'   => array(
                array('type' => 'PRIMARY', 'name' => 'KEY', 'body' => '(`backup_id`)'),
            ),
        ),
    );
    
    /**
     * Set of SQL-schemas for tables in array
     * Set for a blog only. Should installed with a blog database prefix
     *
     * @var array
     */
    protected static $schemas__blog = array(
        
        'sessions' => array(
            'columns' => array(
                array('field'=>'id',          'type' => 'varchar(64)', 'null' => 'no',),
                array('field'=>'name',        'type' => 'varchar(40)', 'null' => 'no',),
                array('field'=>'value',       'type' => 'text',        'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'last_update', 'type' => 'datetime',    'null' => 'yes', 'default' => 'NULL',),
            ),
            'indexes'   => array(
                array('type' => 'PRIMARY', 'name' => 'KEY', 'body' => '(`name`(40), `id`(64))'),
            )
        ),
        
        'monitoring_users' => array(
            'columns' => array(
                array('field'=>'user_id',       'type' => 'int',           'null' => 'no',),
                array('field'=>'user_login',    'type' => 'varchar(60)',   'null' => 'no',),
                array('field'=>'last_activity', 'type' => 'int',           'null' => 'no',),
                array('field'=>'page',          'type' => 'varchar(500)',  'null' => 'yes',),
                array('field'=>'ip',            'type' => 'varchar(50)',   'default' => 'NULL',),
                array('field'=>'role',          'type' => 'varchar(64)',   'default' => 'NULL',),
                array('field'=>'user_agent',    'type' => 'varchar(1024)', 'default' => 'NULL',),
            ),
            'indexes'   => array(
                array('type' => 'PRIMARY', 'name' => 'KEY',       'body' => '(`user_id`)'),
                array('type' => 'KEY',     'name' => 'timestamp', 'body' => '(`last_activity`)'),
            ),
        ),
        
        'auth_logs' => array(
            'columns' => array(
                array('field'=>'id',            'type' => 'int',           'null' => 'no', 'extra' => 'AUTO_INCREMENT'),
                array('field'=>'datetime',      'type' => 'datetime',      'null' => 'no',),
                array('field'=>'timestamp_gmt', 'type' => 'int',           'null' => 'no',),
                array('field'=>'user_login',    'type' => 'varchar(60)',   'null' => 'no',),
                array('field'=>'event',         'type' => 'varchar(32)',   'null' => 'no',),
                array('field'=>'page',          'type' => 'varchar(500)',  'null' => 'yes',),
                array('field'=>'page_time',     'type' => 'varchar(10)',   'null' => 'yes',),
                array('field'=>'blog_id',       'type' => 'int',           'null' => 'no',),
                array('field'=>'auth_ip',       'type' => 'varchar(50)',   'default' => 'NULL',),
                array('field'=>'role',          'type' => 'varchar(64)',   'default' => 'NULL',),
                array('field'=>'user_agent',    'type' => 'varchar(1024)', 'default' => 'NULL',),
                array('field'=>'browser_sign',  'type' => 'varchar(32)',   'default' => 'NULL',),
            ),
            'indexes'       => array(
                array('type' => 'PRIMARY', 'name' => 'KEY',      'body' => '(`id`)'),
                array('type' => 'KEY',     'name' => 'datetime', 'body' => '(`datetime`,`event`)'),
            ),
        ),
        
        'firewall__personal_ips' => array(
            'columns' => array(
                array('field'=>'id',       'type' => 'int',          'null' => 'no', 'extra' => 'AUTO_INCREMENT'),
                array('field'=>'network1', 'type' => 'int unsigned', 'null' => 'no', 'default' => '0',),
                array('field'=>'network2', 'type' => 'int unsigned', 'null' => 'no', 'default' => '0',),
                array('field'=>'network3', 'type' => 'int unsigned', 'null' => 'no', 'default' => '0',),
                array('field'=>'network4', 'type' => 'int unsigned', 'null' => 'no', 'default' => '0',),
                array('field'=>'mask1',    'type' => 'int unsigned', 'null' => 'no', 'default' => '0',),
                array('field'=>'mask2',    'type' => 'int unsigned', 'null' => 'no', 'default' => '0',),
                array('field'=>'mask3',    'type' => 'int unsigned', 'null' => 'no', 'default' => '0',),
                array('field'=>'mask4',    'type' => 'int unsigned', 'null' => 'no', 'default' => '0',),
                array('field'=>'status',   'type' => 'tinyint',      'null' => 'no', 'default' => '0',),
            ),
            'indexes' => array(
                array('type' => 'PRIMARY', 'name' => 'KEY',     'body' => '(`id`)'),
                array('type' => 'INDEX',   'name' => 'network', 'body' => '(`network1`, `network2`, `network3`, `network4`, `mask1`, `mask2`, `mask3`, `mask4`)'),
            ),
        ),
        
        'firewall__personal_countries' => array(
            'columns' => array(
                array('field'=>'id',           'type' => 'int',     'null' => 'no', 'extra' => 'AUTO_INCREMENT'),
                array('field'=>'country_code', 'type' => 'char(2)', 'null' => 'no',),
                array('field'=>'status',       'type' => 'tinyint', 'null' => 'no',),
            ),
            'indexes'    => array(
                array('type' => 'PRIMARY', 'name' => 'KEY', 'body' => '(`id`)'),
            ),
        ),
        
        'firewall_logs' => array(
            'columns' => array(
                array('field' => 'entry_id', 'type' => 'varchar(40)', 'null' => 'no',),
                array('field' => 'ip_entry', 'type' => 'varchar(50)', 'null' => 'yes',),
                array('field'   => 'status',
                      'type'    => 'enum("PASS","PASS_BY_TRUSTED_NETWORK","PASS_BY_WHITELIST","DENY","DENY_BY_NETWORK","DENY_BY_DOS","DENY_BY_WAF_XSS","DENY_BY_WAF_SQL","DENY_BY_WAF_FILE","DENY_BY_WAF_EXPLOIT","DENY_BY_SEC_FW","DENY_BY_SPAM_FW","DENY_BY_BFP")',
                      'null'    => 'yes',
                      'default' => 'NULL',
                      'extra'   => '',
                ),
                array('field' => 'signature_id',    'type' => 'int',              'null' => 'yes',),
                array('field' => 'pattern',         'type' => 'varchar(1024)',    'null' => 'yes',),
                array('field' => 'triggered_for',   'type' => 'varchar(100)',     'null' => 'yes',),
                array('field' => 'requests',        'type' => 'int',              'null' => 'yes',),
                array('field' => 'page_url',        'type' => 'varchar(1024)',    'null' => 'yes',),
                array('field' => 'request_method',  'type' => 'varchar(5)',       'null' => 'yes',),
                array('field' => 'x_forwarded_for', 'type' => 'varchar(15)',      'null' => 'yes',),
                array('field' => 'http_user_agent', 'type' => 'varchar(300)',     'null' => 'yes',),
                array('field' => 'network',         'type' => 'int unsigned',     'null' => 'yes', 'default' => 'NULL',),
                array('field' => 'mask',            'type' => 'int unsigned',     'null' => 'yes', 'default' => 'NULL',),
                array('field' => 'country_code',    'type' => 'char(2)',          'null' => 'yes', 'default' => 'NULL',),
                array('field' => 'is_personal',     'type' => 'tinyint unsigned', 'null' => 'yes', 'default' => 'NULL',),
                array('field' => 'entry_timestamp', 'type' => 'int',              'null' => 'no',),
            ),
            'indexes' => array(
                array('type' => 'PRIMARY', 'name' => 'KEY', 'body' => '(`entry_id`)'),
            ),
        ),

        'traffic_control_logs' => array(
            'columns' => array(
                array('field'=>'id',             'type' => 'varchar(32)', 'null' => 'no',),
                array('field'=>'log_type',       'type' => 'tinyint',     'null' => 'yes', 'default' => 'NULL',),
                array('field'=>'ip',             'type' => 'varchar(40)', 'null' => 'no',),
                array('field'=>'entries',        'type' => 'int', 'default' => '0'),
                array('field'=>'interval_start', 'type' => 'int', 'null' => 'no',),
            ),
            'indexes'      => array(
                array('type' => 'PRIMARY', 'name' => 'KEY',       'body' => '(`id`)'),
                array('type' => 'INDEX',   'name' => 'bfp_index', 'body' => '(`interval_start`, `log_type`)'),
            ),
        ),
        
        'bfp_blocked' => array(
            'columns' => array(
                array('field'=>'id',                     'type' => 'varchar(32)', 'null' => 'no',),
                array('field'=>'ip',                     'type' => 'varchar(15)', 'null' => 'no',),
                array('field'=>'start_time_of_blocking', 'type' => 'int',         'null' => 'no',),
            ),
            'indexes' => array(
                array('type' => 'PRIMARY', 'name' => 'KEY', 'body' => '(`id`)'),
            ),
        ),
    );
}