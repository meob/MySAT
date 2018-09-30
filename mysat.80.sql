-- Program:	MySAT.80.sql
-- 		MySQL 8.0 Security Assessement Tool
--
-- Version:     1.0.3
-- Author:      XeniaLAB srl
-- Date:        01-OCT-2018
-- Usage:	mysql --user=root -pXXX --skip-column-names -f < mysat.80.sql > MySAT.htm
--
-- Note:
-- 1.0.0:       1-MAY-2018 meo@bogliolo.name
--                First version based on MySAT 1.0.1 for MySQL 5.7
-- 1.0.1        25-MAY-2018
--                MySQL 8.0 versions
-- 1.0.2:       01-OCT-2018 meo@bogliolo.name
--                Roles, password history, password plugin, redo/undo encryption
-- 1.0.3:       01-OCT-2018 meo@bogliolo.name
--                CVE list, Last MySQL version update


use information_schema;
select '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" />';
select '<link rel="stylesheet" href="mysat.css" />';
select '<title>MySAT Report</title></head><body>';
select '<h1>MySQL Security Assessment Tool</h1>';
select '<p style="font-size:24px;font-weight: bold;text-align: center;">Highly Confidential';

select '<P><A NAME="top"></A>' ;
select '<p>Table of contents:' ;
select '<table class="none"><tr>' ;
select '<td><b><A HREF="#check">Security Checks</A></b>' ;
select '<td>&nbsp;' ; 
select '<td><b><A HREF="#conf">Configuration &amp; Status</A></b>' ;

select '<tr><td><ul><li><A HREF="#ac"><b>Database Access Control</b></A><ul>' ;
select '<li><A HREF="#ac1">Separation of Roles</A>' ; 
select '<li><A HREF="#ac2">Application credentials</A>' ; 
select '<li><A HREF="#ac3">Developer access</A>' ; 
select '<li><A HREF="#ac7">Lifecycle management</A>' ; 
select '</ul><li><A HREF="#lg"><b>Monitoring and Audit</b></A><ul>' ;
select '<li><A HREF="#lg1">SQL controls</A>' ; 
select '<li><A HREF="#lg2">Logging</A>' ; 
select '<li><A HREF="#lg5">Auditing</A>' ; 
select '</ul>' ;

select '<td><p><ul><li><A HREF="#dp"><b>Data Protection</b></A><ul>' ;
select '<li><A HREF="#dp1">Application encryption</A>' ; 
select '<li><A HREF="#dp2">Tablespace encryption</A>' ; 
select '<li><A HREF="#dp4">Network encryption</A>' ; 
select '<li><A HREF="#dp7">Data Masking </A>' ; 
select '</ul><li><A HREF="#sc"><b>Secure configuration</b></A><ul>' ;
select '<li><A HREF="#sc1">Version Check</A></li>' ; 
select '<li><A HREF="#sc2">Database Hardening</A></li>' ; 
select '<li><A HREF="#sc3">Patching</A></li>' ;
select '</ul>' ;

select '<td><p><ul><li><A HREF="#conf"><b>Database</b></A><ul>' ;
select '<li><A HREF="#status">Summary</A></li>' ;
select '<li><A HREF="#usr">Users</A>' ;
select '<li><A HREF="#obj">Schema/Object Matrix</A></li>' ;
select '<li><A HREF="#tbs">Space Usage</A></li>' ;
select '<li><A HREF="#big">Biggest Objects</A></li>' ;
select '<li><A HREF="#prc">Threads</A></li>' ;
select '<li><A HREF="#sga">Tuning Parameters</A> </li>' ;
select '<li><A HREF="#stat">Performance Statistics</A></li>' ;
select '<li><A HREF="#hostc">Connections</A></li>' ;
select '</ul>' ;

select '<tr><td><A HREF="#xgdpr"><b>GDPR Cross Reference</b><td><A HREF="#xcis"><b>CIS Benchmarks Cross Reference</b></A>' ;
select '<td> <A HREF="#xcve"><b>CVE Details</b></A>' ;
select '</table><p><br><hr>' ;
 
select '<P>Statistics generated on: ', now();
select ' by: ', user(), 'as: ',current_user();
 
select 'using: <I><b>mysat.80.sql</b> v.1.0.3 (2018-10-01)';
select '<br>Software by ';
select '<A HREF="https://www.xenialab.com/english/">XeniaLAB</A></I><p><HR>';

select '<P><A NAME="check"></A><h2>Security Checks</h2>';
select '<table><tr><td><a name="ac"></a><h4>Database Access Control</h4><td><td><td width="50%">' ;
select '<tr><td><a name="ac1"></a><b>Separation of Roles</b>' ;

select '<tr><td><a name="ac1e"></a>CRUD users' ;
select if(count(*)>=1, '<td class="eval">Evaluate<td><td>', '<td class="med">Fail<td>No CRUD users<td>')
  from mysql.db
 where insert_priv='Y'
   and concat(user,'@',host) not in (
	select concat(user,'@',host)
	  from mysql.db
	 where create_priv='Y');
select distinct concat(user,'@',host)
  from mysql.db
 where insert_priv='Y'
   and concat(user,'@',host) not in (
	select concat(user,'@',host)
	  from mysql.db
	 where create_priv='Y')
 order by 1;
select '<tr><td><a name="ac1f"></a>Roles' ;
select if(count(*)>=1, '<td class="pass">Pass<td><td>', '<td class="low">Fail<td>No Active roles<td>')
  FROM mysql.user LEFT JOIN mysql.role_edges ON from_user=user
 WHERE account_locked='Y'
   AND password_expired='Y'
   AND authentication_string=''
   AND from_user is not null;
select DISTINCT User
  FROM mysql.user LEFT JOIN mysql.role_edges ON from_user=user
 WHERE account_locked='Y'
   AND password_expired='Y'
   AND authentication_string=''
   AND from_user is not null;

select '<tr><td><a name="ac2"></a><b>Application user credential protection</b>' ;
select '<tr><td><a name="ac2a"></a>Connection strings' ;
select '<td class="ext">External<td>Check protection and obfuscation';
select '<tr><td><a name="ac3"></a><b>Application user credential usage</b>' ;
select '<tr><td><a name="ac3a"></a>Threads connections as' ;
select if(count(*)=0, '<td class="pass">Pass<td>', '<td class="eval">Evaluate<td>Access found<td>')
  from processlist where host not like 'localhost%' and host <>'';
select distinct concat(user,'@', SUBSTRING_INDEX(host,':',1))
  from processlist where host not like 'localhost%' and host <>'';
-- AC4 	DBAs do not have personal accounts and use technical accounts 
-- AC5 	Technical accounts defined with a human algorithm and never changed 
-- AC6 	End users have direct access to the DB bypassing the application
select '<tr><td><a name="ac7"></a><b>Lifecycle management</b>' ;
select '<tr><td><a name="ac7a"></a>Password expire' ;
select if(count(*)>=1, '<td class="pass">Pass<td><td>', '<td class="eval">Evaluate<td>No users with password expire')
  from mysql.user where password_lifetime is not null;
select user
  from mysql.user where password_lifetime is not null;
select '<tr><td><a name="ac8"><b>OS privilege escalation</b>' ;
select '<tr><td><a name="ac8a"></a>Anonymous user' ; 
select if(count(*)=0, '<td class="pass">Pass', '<td class="high">Fail<td>OS users do not use password')
  from mysql.user
 where user='';

select '<tr><tr><td><a name="lg"></a><h4>Monitoring and Audit</h4>' ;
select '<tr><td><a name="lg1"></a><b>SQL controls</b>' ;
select '<tr><td><a name="lg1a"></a>Suspect SQL' ;
select if(count(*)=0, '<td class="pass">Pass', '<td class="eval">Evaluate<td>Some suspect statements<td>')
  from performance_schema.events_statements_summary_by_digest
 where DIGEST_TEXT like '% OR %? = ?%' OR DIGEST_TEXT like '%mysql.user%';
select '<br><i>', schema_name, '</i><code>', concat(substr(DIGEST_TEXT,1,80),'...'), '</code>'
  from performance_schema.events_statements_summary_by_digest
 where DIGEST_TEXT like '% OR %? = ?%' OR DIGEST_TEXT like '%mysql.user%'
 limit 10;
select '<tr><td><a name="lg1b"></a>Strict SQL mode' ;
select if(locate('STRICT',@@global.sql_mode)>0, '<td class="pass">Pass', '<td class="med">Fail<td>Not enabled');

select '<tr><td><a name="lg2"></a><b>Logging</b>' ;
select '<tr><td><a name="lg2a"></a>Slow log' ;
select if(variable_value<>'OFF', '<td class="pass">Pass', '<td class="med">Fail<td>Slow query log disabled')
  from performance_schema.global_variables
 where variable_name='slow_query_log';
select '<tr><td><a name="lg2b"></a>Slow log timeout' ;
select if(variable_value<=10, '<td class="pass">Pass', '<td class="low">Fail<td>Slow query timeout too long')
  from performance_schema.global_variables
 where variable_name='long_query_time';
select '<tr><td><a name="lg2c"></a>Error Log' ;
select if(variable_value<>'', '<td class="pass">Pass<td>', '<td class="high">Fail<td>')
  from performance_schema.global_variables
 where variable_name='log_error';
select variable_value
  from performance_schema.global_variables
 where variable_name='log_error';
select '<tr><td><a name="lg2d"></a>Binlog Path' ;
select if(@@global.log_bin_basename like '/var/%' OR @@global.log_bin_basename='/', '<td class="med">Fail<td>', '<td class="pass">Pass<td>'), @@global.log_bin_basename ;
select '<tr><td><a name="lg2e"></a>Error Level' ;
select if(variable_value=3, '<td class="pass">Pass<td>', if(variable_value>1, '<td class="low">Fail<td>', '<td class="med">Fail<td>')),
       variable_value
  from performance_schema.global_variables
 where variable_name='log_error_verbosity';
select '<tr><td><a name="lg3"></a><b>Log analysis</b>' ;
select '<tr><td><a name="lg3a"></a>Automatic log analyze<td class="ext">External<td>Log analysis is strongly suggested' ;
select '<tr><td><a name="lg4"></a><b>Event management</b>' ;
select '<tr><td><a name="lg4a"></a>Log Management<td class="ext">External<td>Log management is strongly suggested' ;
select '<tr><td><a name="lg5"></a><b>Auditing</b>' ;
select '<tr><td><a name="lg5a"></a>Auditing active' ;
select if(count(*)>0, '<td class="pass">Pass', '<td class="high">Fail<td>Audit not enabled')
  from performance_schema.global_variables
 where variable_name='server_audit_logging'
   and variable_value='ON';
select '<tr><td><a name="lg5b"></a>Auditing event configuration' ;
select if(variable_value like '%CONNECT%', '<td class="pass">Pass', '<td class="med">Fail<td>Connections not audited')
  from performance_schema.global_variables
 where variable_name='server_audit_events';
select '<tr><td><a name="lg5c"></a>Auditing users whitelist' ;
select if(variable_value is null or variable_value='', '<td class="pass">Pass',
                              '<td class="eval">Evaluate<td>Excluded users<td>')
  from performance_schema.global_variables
 where variable_name='server_audit_excl_users';
select variable_value
  from performance_schema.global_variables
 where variable_name='server_audit_excl_users'
   and variable_value is not null;
-- LG6	End user accountability 


select '<tr><tr><td><a name="dp"></a><h4>Data Protection</h4>' ;
select '<tr><td><a name="dp1"></a><b>Application encryption</b>' ;
select '<tr><td><a name="dp2"></a><b>Tablespace encryption</b>' ;
select '<tr><td><a name="dp2a"></a>Encryption enabled' ;
select if(count(*)>0, '<td class="pass">Pass', '<td class="med">Fail<td>No at-rest encryption<td>')
  from INFORMATION_SCHEMA.TABLES
 where CREATE_OPTIONS LIKE '%ENCRYPTION="Y"%';
select '<tr><td><a name="dp2c"></a>Suspect sensitive tables' ;
select '<td class="eval">Evaluate<td>Check suspect tables.columns: <td> ';
SELECT distinct concat(table_schema, '.', table_name, '.', column_name)
  from information_schema.columns c
 where c.table_schema not in('information_schema', 'mysql', 'performance_schema','sys')
   and (column_name like '%FIRST%NAME%' OR
	column_name like '%LAST%NAME%' OR
	column_name like '%SURNAME%' OR
	column_name like '%FULL%NAME%' OR
	column_name like '%USER%NAME%' OR
	column_name like '%COGNOME%' OR
	column_name like '%MAIL%' OR
	column_name like '%POSTA%' OR
	column_name like '%TELEP%' OR
	column_name like '%EXTENS%' OR
	column_name like '%TELEF%' OR
	column_name like '%SSN%' OR
	column_name like '%FISC%' OR
	column_name like '%IBAN%' OR
	column_name like '%CCARD%' OR
	column_name like '%BANK%' OR
	column_name like '%BANCA%' OR
	column_name like '%PAYP%' OR
	column_name like '%PASS%' OR
	column_name like '%RELIGIO%' OR
	column_name like '%ACUZIE%' OR
	column_name like '%PATHOL%')
 order by 1
 limit 100;
select '...' ;
select '<tr><td><a name="dp2d"></a>Redo encryption' ;
select if(count(*)=1, '<td class="pass">Pass', '<td class="low">Fail<td>Not configured'), '<td>', variable_value
  from performance_schema.global_variables
 where variable_name='innodb_redo_log_encrypt'
   and coalesce(variable_value, 'OFF') = 'ON';
select '<tr><td><a name="dp2e"></a>Undo encryption' ;
select if(count(*)=1, '<td class="pass">Pass', '<td class="low">Fail<td>Not configured'), '<td>', variable_value
  from performance_schema.global_variables
 where variable_name='innodb_undo_encrypt'
   and coalesce(variable_value, 'OFF') = 'ON';
select '<tr><td><a name="dp4"></a><b>Network encryption</b>' ;
select '<tr><td><a name="dp4a"></a>SSL/TLS configured' ;
select if(max(variable_value)='YES', '<td class="pass">Pass', '<td class="med">Fail<td>No SSL')
  from performance_schema.global_variables
 where variable_name='have_ssl';
select '<tr><td><a name="dp4b"></a>Users required to use encryption' ;
select if(count(*)>=1, '<td class="pass">Pass', '<td class="med">Fail<td>Encryption is not required')
  from mysql.user where ssl_type <>'';
select '<tr><td><a name="dp5"></a><b>Backup</b>' ;
select '<tr><td><a name="dp5a"></a>DB Backup execution' ;
select if(count(*)>=1, '<td class="pass">Pass', '<td class="eval">Evaluate<td>No backup detected')
  from performance_schema.events_statements_summary_by_digest
 where DIGEST_TEXT like '%SQL_NO_CACHE%';
select '<tr><td><a name="dp5b"></a>Backup encryption' ;
select '<td class="ext">External<td>Check backup encryption';
select '<tr><td><a name="dp5c"></a>Backup policies' ;
select '<td class="ext">External<td>Check backup retention policies';
select '<tr><td><a name="dp5d"></a>Binlog retention' ;
select if(count(*)=1, '<td class="pass">Pass', '<td class="low">Fail<td>Not configured correctly')
  from performance_schema.global_variables
 where variable_name='expire_logs_days'
   and coalesce(variable_value, '99') <= 15
   and coalesce(variable_value, '99') != 0;
-- DP6	Production data copied to development environments 
select '<tr><td><a name="dp7"></a><b>Data Masking</b>' ;
select '<tr><td><a name="dp7a"></a>miXen package' ;
select if(count(*)>1, '<td class="pass">Pass', '<td class="low">Fail<td>miXen data masking package not found')
  from INFORMATION_SCHEMA.TABLES
 where table_schema='mixen';

select '<tr><tr><td><a name="sc"><h4>Secure configuration</h4>' ;
select '<tr><td><a name="sc1"><b>Version Check</b>' ;
select '<tr><td><a name="sc1a"></a>MySQL version' ;
select if(SUBSTRING_INDEX(version(),'.',2) in ('8.0'), '<td class="pass">Pass', '<td class="high">Fail') ;
select '<td>', SUBSTRING_INDEX(version(),'.',2);
select '<tr><td><a name="sc2"><b>Database Hardening</b>' ;
select '<tr><td><a name="sc2a"></a>Anonymous user' ; 
select if(count(*)=0, '<td class="pass">Pass', '<td class="high">Fail')
  from mysql.user
 where user='';

select '<tr><td><a name="sc2b"></a>Any host access' ; 
select if(count(*)=0, '<td class="pass">Pass', '<td class="med">Fail<td>Users can connect from everywhere<td> ')
  from mysql.user
 where account_locked='N' and host='%';
select user
  from mysql.user
 where account_locked='N' and host='%';
select '<tr><td><a name="sc2b2"></a>Many hosts access' ; 
select if(count(*)=0, '<td class="pass">Pass', '<td class="low">Fail<td>Users can connect from a subnet<td> ')
  from mysql.user
 where account_locked='N' and host like'%\%' and host<>'%';
select user
  from mysql.user
 where account_locked='N' and host like'%\%' and host<>'%';

select '<tr><td><a name="sc2b"></a>Any host access' ; 
select if(count(*)=0, '<td class="pass">Pass', '<td class="med">Fail<td>Users can connect from everywhere<td> ')
  from mysql.user
 where host='%'
   and account_locked='N';
select user
  from mysql.user
 where host='%'
   and account_locked='N';
select '<tr><td><a name="sc2b2"></a>Many host access' ; 
select if(count(*)=0, '<td class="pass">Pass', '<td class="low">Fail<td>Users can connect from a subnet<td> ')
  from mysql.user
 where host like'%\%' and host<>'%' and account_locked='N';
select user
  from mysql.user
 where host like'%\%' and host<>'%' and account_locked='N';





select '<tr><td><a name="sc2c"></a>DB Password check' ; 
select if(count(*)=0, '<td class="pass">Pass', '<td class="high">Fail<td>Some users have easy passwords<td>')
  from mysql.user
 where account_locked='N' and (authentication_string = ''
    OR (authentication_string = UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1(user))) AS CHAR)))
        AND authentication_string <> '')
    OR authentication_string in ('*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B', '*14E65567ABDB5135D0CFD9A70B3032C179A49EE7',
      '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19', '*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4',
      '*A80082C9E4BB16D9C8E41B0D7EED46126DF4A46E', '*85BB02300F877EB061967510E83F68B1A7325252',
      '*A4B6157319038724E3560894F7F932C8886EBFCF', '*4ACFE3202A5FF5CF467898FC58AAB1D615029441',
      '*A36BA850A6E748679226B01E159EF1A7BF946195', '*196BDEDE2AE4F84CA44C47D54D78478C7E2BD7B7',
      '*E74858DB86EBA20BC33D0AECAE8A8108C56B17FA', '*AF35041D44DF3E88C9F97CC8D3ACAF4695E65B69',
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('prova'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('test'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('demo'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('qwerty'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('manager'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('supervisor'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('toor'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('Qwerty'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('xxx'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('moodle'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('drupal'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('admin01'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('joomla'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('wp'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('ilikerandompasswords'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('changeme'))) AS CHAR))) )  );
select concat(user, '@\'', host,'\'')
  from mysql.user
 where account_locked='N' and (authentication_string = ''
    OR authentication_string = UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1(user))) AS CHAR)))
    OR authentication_string in ('*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B', '*14E65567ABDB5135D0CFD9A70B3032C179A49EE7',
      '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19', '*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4',
      '*A80082C9E4BB16D9C8E41B0D7EED46126DF4A46E', '*85BB02300F877EB061967510E83F68B1A7325252',
      '*A4B6157319038724E3560894F7F932C8886EBFCF', '*4ACFE3202A5FF5CF467898FC58AAB1D615029441',
      '*A36BA850A6E748679226B01E159EF1A7BF946195', '*196BDEDE2AE4F84CA44C47D54D78478C7E2BD7B7',
      '*E74858DB86EBA20BC33D0AECAE8A8108C56B17FA', '*AF35041D44DF3E88C9F97CC8D3ACAF4695E65B69',
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('prova'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('test'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('demo'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('qwerty'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('manager'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('supervisor'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('toor'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('Qwerty'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('xxx'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('moodle'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('drupal'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('admin01'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('joomla'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('wp'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('ilikerandompasswords'))) AS CHAR))),
      UPPER(CONCAT('*', CAST(SHA1(UNHEX(SHA1('changeme'))) AS CHAR))) )   );
select '<tr><td><a name="sc2d"></a>Backdoor users' ; 
select if(count(*)=0, '<td class="pass">Pass', '<td class="high">Fail<td>Found suspected users')
  from mysql.user
 where user in ('hanako', 'kisadminnew1', '401hk$', 'guest', 'Huazhongdiguo110');
select '<tr><td><a name="sc2d2"></a>Test schema' ; 
select if(count(*)=0, '<td class="pass">Pass', '<td class="med">Fail<td>Test schema found')
  from INFORMATION_SCHEMA.TABLES
 where table_schema='test';
select '<tr><td><a name="sc2e"></a>Admin users <>root' ; 
select if(count(*)=0, '<td class="pass">Pass', '<td class="eval">Evaluate<td><td> ')
  from mysql.user
 where user<>'root' and user<>'mysql.session'
   and super_priv='Y';
select concat(user,'@',host)
  from mysql.user
 where user<>'root' and user<>'mysql.session'
   and super_priv='Y'
 order by 1;
select '<tr><td><a name="sc2e2"></a>Oper users <>root' ; 
select if(count(*)=0, '<td class="pass">Pass', '<td class="eval">Evaluate<td><td> ')
  from mysql.user
 where user not in('root', 'mysql.session', 'mysql.infoschema') and super_priv='N'
   and (select_priv='Y' or update_priv='Y' or file_priv='Y' or grant_priv='Y' or alter_priv='Y' or process_priv='Y');
select concat(user,'@',host)
  from mysql.user
 where user not in('root', 'mysql.session', 'mysql.infoschema') and super_priv='N'
   and (select_priv='Y' or update_priv='Y' or file_priv='Y' or grant_priv='Y' or alter_priv='Y' or process_priv='Y')
 order by 1;

select '<tr><td><a name="sc2e3"></a>Authentication Plugin' ;
select if(count(*)=0, '<td class="pass">Pass', '<td class="eval">Evaluate<td><td> ')
  from mysql.user
 where plugin<>'caching_sha2_password'
   and account_locked='N';
select user
  from mysql.user
 where plugin<>'caching_sha2_password'
   and account_locked='N';
select '<tr><td><a name="sc2e4"></a>Password reuse history' ;
select if(count(*)=0, '<td class="pass">Pass', '<td class="eval">Evaluate<td><td> ')
  from mysql.user
 where coalesce(password_reuse_history,0)<4
   and account_locked='N';
select user
  from mysql.user
 where coalesce(password_reuse_history,0)<4
   and account_locked='N';
select '<tr><td><a name="sc2e4"></a>Password reuse time' ;
select if(count(*)=0, '<td class="pass">Pass', '<td class="eval">Evaluate<td><td> ')
  from mysql.user
 where coalesce(password_reuse_time,0)<270
   and account_locked='N';
select user
  from mysql.user
 where coalesce(password_reuse_time,0)<270
   and account_locked='N';

select '<tr><td><a name="sc2f"></a>IDS<td class="ext">External<td>Configure IDS to monitor honeypot';
select '<tr><td><a name="sc2g"></a>Spammable tables' ;
select if(count(*)=0, '<td class="pass">Pass', '<td class="eval">Evaluate<td>Suspected tables found<td>')
from tables
where (table_name like '%comments'
       or table_name like '%redirection')
and table_rows > 1000
order by table_rows desc;
select concat(table_schema, '.',table_name)
from tables
where (table_name like '%comments'
       or table_name like '%redirection')
and table_rows > 1000
order by table_rows desc;
select '<tr><td><a name="sc2h"></a>Dedicated datadir' ;
select if(count(*)=0, '<td class="pass">Pass', '<td class="med">Fail<td>Not dedicated datadir')
  from performance_schema.global_variables
 where variable_name='datadir'
   and (variable_value like '/var/%' or variable_value like '/');
select '<tr><td><a name="sc2i"></a>Memcache plugin' ;
select if(count(*)=0, '<td class="pass">Pass', '<td class="low">Fail<td>On file')
  from information_schema.plugins
 where PLUGIN_NAME='daemon_memcached';
select '<tr><td><a name="sc2l"></a>secure_file_priv' ;
select if(count(*)=1, '<td class="pass">Pass', '<td class="low">Fail<td>Not configured')
  from performance_schema.global_variables
 where variable_name='secure_file_priv'
   and coalesce(variable_value, 'Blocked') <>'';
select '<tr><td><a name="sc2m"></a>Master Info' ;
select if(count(*)=1, '<td class="pass">Pass', '<td class="low">Fail<td>On file')
  from performance_schema.global_variables
 where variable_name='master_info_repository'
   and variable_value = 'TABLE';
select '<tr><td><a name="sc2n"></a>Automatic User Creation' ;
select '<td class="pass">Pass<td>Always disabled in 8.0';
select '<tr><td><a name="sc2o"></a>Password lenght' ;
select if(max(variable_value)>=8, '<td class="pass">Pass<td>', '<td class="med">Fail<td>Too short<td>'), 
       max(variable_value)
  from performance_schema.global_variables
 where variable_name='validate_password.length';
select '<tr><td><a name="sc2p"></a>Password policy' ;
select if(count(*)>=1, '<td class="pass">Pass<td>', '<td class="med">Fail<td>Not secure<td>'),
       max(variable_value)
  from performance_schema.global_variables
 where variable_name='validate_password.policy'
   and variable_value in ('MEDIUM','STRONG');
select '<tr><td><a name="sc2p2"></a>Password validate component' ;
select if(count(*)>=1, '<td class="pass">Pass<td>', '<td class="med">Fail<td>Component not installed<td>')
  from mysql.component
 where component_urn = 'file://component_validate_password';
select '<tr><td><a name="sc2q"></a>Performance statistics' ;
select if(count(*)>=1, '<td class="pass">Pass', '<td class="low">Fail<td>my2 collector not found')
  from INFORMATION_SCHEMA.TABLES
 where table_schema='my2';
select '<tr><td><a name="sc2r"></a>local_infile' ;
select if(variable_value='OFF', '<td class="pass">Pass', '<td class="med">Fail<td>')
  from performance_schema.global_variables
 where variable_name='local_infile';
select '<tr><td><a name="sc2s"></a>Symbolic Links' ;
select if(variable_value='DISABLED', '<td class="pass">Pass', '<td class="med">Fail<td>')
  from performance_schema.global_variables
 where variable_name='have_symlink';
select '<tr><td><a name="sc2t"></a>Verify Master certificate', 
       if(ssl_verify_server_cert=1, '<td class="pass">Pass<td>', '<td class="med">Fail<td>'),
       ssl_verify_server_cert
  from mysql.slave_master_info;
select '<tr><td><a name="sc2u"></a>Skip grant' ;
select if(max(variable_value)='ON', '<td class="high">Fail<td>', '<td class="ext">Evaluate<td>Do not enable skip_grant_tables')
  from performance_schema.global_variables
 where variable_name='skip_grant_tables';

select '<tr><td><a name="sc3"><b>Patching</b>' ;
select '<tr><td><a name="sc3a"></a>MySQL update' ;
select if(SUBSTRING_INDEX(version(),'-',1) in ('8.0.11','8.0.12','8.0.13'), '<td class="pass">Pass', '<td class="med">Fail') ;
select '<td>', version();

select '<tr><td><a name="sc3c"></a>MySAT update' ;
select if(now()<'2018-11-25', '<td class="pass">Pass', '<td class="med">Fail') ;
select '<td>1.0.3' ;
select if(now() not like '20__-04-01%', '<!-- 1st April check -->', '<tr><td><td class="low">Fail<td>Never run it on April Fools\' Day') ;

select '<tr><td>&nbsp;<tr><td><a name="gdpr1"><b>GDPR Countdown</b>' ;
select '<tr><td><a name="gdpr1a"></a>Days since promulgation' ;
select if(now() > '2016-04-27', '<td class="pass">Pass', '<td class="ext">Law not yet promulgated') ;
select '<td>', datediff(now(), '2016-04-27');
select '<tr><td><a name="gdpr1b"></a>Days since application' ;
select if(now() > '2018-05-25', '<td class="pass">Pass<td>', '<td class="ext">External<td>Law not yet in force ') ;
select datediff(now(), '2018-05-25');
select '<tr><td>&nbsp;</table><p>';

select '<hr><P><A NAME="conf"></A><h2>DB Configuration</h2>';

select '<P><A NAME="status"></A>';
select '<P><table border="2"><tr><td><b>Database Summary</b></td></tr>';
select '<tr><td><b>Item</b>', '<td><b>Value</b>';

select '<tr><td>Version :', '<td>', version()
union
select '<tr><td>Created :', '<td>', min(create_time)
from tables
union
select '<tr><td>Started :', '<td>', date_format(date_sub(now(), INTERVAL variable_value second),'%Y-%m-%d %T')
from performance_schema.global_status
where variable_name='UPTIME'
union
select '<tr><td>Database Size (MB):',
	'<td align=right>',
        format(sum(data_length+index_length)/(1024*1024),0)
from tables
union
select '<tr><td>Buffers Size (MB):',
	'<td align="right">',
	format(sum(variable_value+0)/(1024*1024),0)
from performance_schema.global_variables
where lower(variable_name) like '%buffer_size' or lower(variable_name) like '%buffer_pool_size'
union
select '<tr><td>Logging Bin. :', '<td>', variable_value
from performance_schema.global_status
where variable_name='LOG_BIN'
union
select '<tr><td>Defined Users :',
 '<td align="right">', format(count(*),0)
from mysql.user
union
select '<tr><td>Defined Schemata :',
 '<td align="right">', count(*)
from schemata
where schema_name not in ('information_schema')
union
select '<tr><td>Defined Tables :',
	'<td align=right>', format(count(*),0)
from tables
union
select '<tr><td>Sessions :', '<td align="right">', format(count(*),0)
  from processlist
 union
select '<tr><td>Sessions (active) :', '<td align="right">', format(count(*),0)
  from processlist
 where command <> 'Sleep'
union
select '<tr><td>Questions (#/sec.) :',
 '<td align=right>', format(g1.variable_value/g2.variable_value,5)
  from performance_schema.global_status g1, performance_schema.global_status g2
 where g1.variable_name='QUESTIONS'
   and g2.variable_name='UPTIME'
union
select '<tr><td>Connections (#/sec.) :',
 '<td align=right>', format(g1.variable_value/g2.variable_value,5)
  from performance_schema.global_status g1, performance_schema.global_status g2
 where g1.variable_name='CONNECTIONS'
   and g2.variable_name='UPTIME'
union
select '<tr><td>BinLog Writes Day (MB) :',
 '<td align=right>', format((g1.variable_value*60*60*24)/(g2.variable_value*1024*1024),0)
  from performance_schema.global_status g1, performance_schema.global_status g2
 where g1.variable_name='INNODB_OS_LOG_WRITTEN'
   and g2.variable_name='UPTIME'
union
select '<tr><td>Hostname :', '<td>', variable_value
  from performance_schema.global_variables
 where variable_name ='hostname'
union
select '<tr><td>Port :', '<td>', variable_value
  from performance_schema.global_variables
 where variable_name ='port';
select '</table><p>' ;

select '<P><A NAME="usr"></A>';
select '<P><table border="2"><tr><td><b>Users</b></td></tr>' ;
select '<tr><td><b>User</b>',
 '<td><b>Host</b>',
 '<td><b><code>SL IUD CDGRIA CCS CAE RR SSPFSR</code></b>',
 '<td><b>Select</b>',
 '<td><b>Execute</b>',
 '<td><b>Grant</b>',
 '<td><b>Expired</b>',
 '<td><b>Locked</b>',
 '<td><b>Password lifetime</b>',
 '<td><b>Password history</b>',
 '<td><b>Plugin</b>';
SELECT '<tr><td>',user, 
	'<td>', host,
	'<td><code>', CONCAT(Select_priv, Lock_tables_priv,' ',
       Insert_priv, Update_priv, Delete_priv, ' ', Create_priv, Drop_priv,
       Grant_priv, References_priv, Index_priv, Alter_priv, ' ',
       Create_tmp_table_priv, Create_view_priv, Show_view_priv, ' ',
       Create_routine_priv, Alter_routine_priv, Execute_priv, ' ',
       Repl_slave_priv, Repl_client_priv, ' ',
       Super_priv, Shutdown_priv, Process_priv, File_priv, Show_db_priv, Reload_priv) AS grt,
	'</code><td>', select_priv, 
	'<td>', execute_priv, 
	'<td>', grant_priv,
	'<td>', password_expired,
	'<td>', account_locked,
	'<td>', password_lifetime,
	'<td>', password_reuse_history, ' over ', password_reuse_time,'gg',
	'<td>', plugin
from mysql.user d
order by user,host;
select '</table><p>' ;

select '<P><A NAME="obj"></A>' ;
select '<P><table border="2"><tr><td><b>Schema/Object Matrix</b></td></tr>' ;
select '<tr><td><b>Database</b>',
 '<td><b> Tables</b>',
 '<td><b> Indexes</b>',
 '<td><b> Routines</b>',
 '<td><b> Triggers</b>',
 '<td><b> Views</b>',
 '<td><b> Primary Keys</b>',
 '<td><b> Foreign Keys</b>',
 '<td><b> All</b>' ;

select '<tr><td>', sk,
	'<td align=right>', sum(if(otype='T',1,0)),
	'<td align=right>', sum(if(otype='I',1,0)),
	'<td align=right>', sum(if(otype='R',1,0)),
	'<td align=right>', sum(if(otype='E',1,0)),
	'<td align=right>', sum(if(otype='V',1,0)),
	'<td align=right>', sum(if(otype='P',1,0)),
	'<td align=right>', sum(if(otype='F',1,0)),
	'<td align=right>', count(*)
from ( select 'T' otype, table_schema sk, table_name name
  from tables
  union
 select 'I' otype, constraint_schema sk, concat(table_name,'.',constraint_name) name
  from key_column_usage
  where ordinal_position=1
  union
 select 'R' otype, routine_schema sk, routine_name name
  from routines
  union
 select 'E' otype, trigger_schema sk, trigger_name name
  from triggers
  union
 select 'V' otype, table_schema sk, table_name name
  from views 
  union
 select distinct 'P' otype, CONSTRAINT_SCHEMA sk, TABLE_NAME name
  from KEY_COLUMN_USAGE
  where  CONSTRAINT_NAME='PRIMARY'
  union
 select distinct 'F' otype, CONSTRAINT_SCHEMA sk, concat(TABLE_NAME,'-',CONSTRAINT_NAME) name
  from KEY_COLUMN_USAGE
  where REFERENCED_TABLE_NAME is not null
     ) a
group by sk with rollup;
select '</table><p>' ;

select '<P><A NAME="tbs"></A>' ;
select '<P><table border="2"><tr><td><b>Space Usage</b></td></tr>' ;
select '<tr><td><b>Database',
 '<td><b>Row#</b>',
 '<td><b>Data size</b>',
 '<td><b>Index size</b>',
 '<td><b>Total size</b>',
 '<td><b></b>',
 '<td><b>MyISAM</b>',
 '<td><b>InnoDB</b>',
 '<td><b>Created</b>';
select '<tr><td>', table_schema,
	'<td align=right>', format(sum(table_rows),0),
	'<td align=right>', format(sum(data_length),0),
	'<td align=right>', format(sum(index_length),0),
	'<td align=right>', format(sum(data_length+index_length),0),
	'<td>',
	'<td align=right>', format(sum((data_length+index_length)*
		if(engine='MyISAM',1,0)),0),
	'<td align=right>', format(sum((data_length+index_length)*
		if(engine='InnoDB',1,0)),0),
	'<td>', date_format(min(create_time),'%Y-%m-%d')
from tables
group by table_schema with rollup;
select '</table><p>' ;

select '<P><A NAME="big"></A>' ;
select '<P><table border="2"><tr><td><b>Biggest Objects</b></td></tr>' ;
select '<tr><td><b>Database</b>',
 '<td><b>Object</b>',
 '<td><b>Type</b>',
 '<td><b>Engine</b>',
 '<td><b>Bytes</b>',
 '<td><b>Est. rows</b>';
select '<tr><td>', table_schema,
	'<td>', table_name,
	'<td>T','<td>',engine,
	'<td align=right>', format(data_length+index_length,0),
	'<td align=right>', format(table_rows,0)
from tables
order by data_length+index_length desc
limit 10;
select '</table><p>' ;

select '<P><A NAME="prc"></A>' ;
select '<P><table border="2"><tr><td><b>Processes</b></td></tr>' ;
select '<tr><td><b>Id</b><td><b>User</b><td><b>Host</b>';
select '<td><b>DB</b><td><b>Command</b><td><b>Time</b><td><b>State</b>';
select '<tr><td>',id,
	'<td>', user,
	'<td>', host,
	'<td>', db,
	'<td>', command,
	'<td>', time,
	'<td>', state
from processlist
order by id;
select '</table><p>' ;

select '<P><A NAME="sga"></A>' ;
select '<P><table border="2"><tr><td><b>Tuning Parameters (most used ones)</b></td></tr>';
select '<tr><td><b>Parameter</b>',
 '<td><b>Value</b><td><b>Type</b>' ;
select '<tr><td>', variable_name, '<td align=right>', variable_value, '<td>Flag'
from performance_schema.global_variables
where lower(variable_name) in (
'log_bin',
'query_cache_type',
'slow_query_log',
'foo')
union
select '<tr><td>', variable_name, '<td align=right>', format(variable_value,0), '<td>Cache'
from performance_schema.global_variables
where lower(variable_name) in (
'innodb_buffer_pool_size',
'query_cache_size',
'innodb_additional_mem_pool_size',
'innodb_log_file_size',
'innodb_log_buffer_size',
'key_buffer_size',
'table_open_cache',
'tmp_table_size',
'max_heap_table_size',
'foo')
union
select '<tr><td>', variable_name, '<td align=right>', format(variable_value,0), '<td>Tuning and timeout'
from performance_schema.global_variables
where lower(variable_name) in (
'innodb_flush_log_at_trx_commit',
'innodb_flush_log_at_timeout',
'innodb_log_files_in_group',
'innodb_lock_wait_timeout',
'innodb_thread_concurrency',
'skip-external-locking',
'wait_timeout',
'long_query_time',
'sync_binlog',
'foo')
union
select '<tr><td>', variable_name, '<td align=right>', format(variable_value,0), '<td>Client Cache'
from performance_schema.global_variables
where lower(variable_name) in (
'binlog_cache_size',
'binlog_stmt_cache_size',
'max_connections',
'read_buffer_size',
'read_rnd_buffer_size',
'sort_buffer_size',
'join_buffer_size',
'thread_stack',
'foo')
order by variable_name;
select '</table><p>' ;

select '<P><A NAME="stat"></A>' ;
select '<P><table border="2"><tr><td><b>Performance Statistics Summary</b></td></tr>' ;
select '<tr><td><b>Statistic</b><td><b>Value</b><td><b>Suggested value</b><td><b>Potential Action</b>';
select '<tr><!01><td>', variable_name, ' (days)<td align=right>', round(variable_value/(3600*24),1), '', ''
from performance_schema.global_status
where variable_name='UPTIME'
union
select '<tr><!15><td>', 'Buffer Cache: MyISAM Read Hit Ratio',
 '<td align=right>', format(100-t1.variable_value*100/t2.variable_value,2), '<td> >95', '<td>Increase KEY_BUFFER_SIZE'
from performance_schema.global_status t1, performance_schema.global_status t2
where t1.variable_name='KEY_READS' and t2.variable_name='KEY_READ_REQUESTS'
union
select '<tr><!16><td>', 'Buffer Cache: InnoDB Read Hit Ratio',
 '<td align=right>', format(100-t1.variable_value*100/t2.variable_value,2), '<td> >95', '<td>Increase INNODB_BUFFER_SIZE'
from performance_schema.global_status t1, performance_schema.global_status t2
where t1.variable_name='INNODB_BUFFER_POOL_READS' and t2.variable_name='INNODB_BUFFER_POOL_READ_REQUESTS'
union
select '<tr><!17><td>', 'Buffer Cache: MyISAM Write Hit Ratio',
 '<td align=right>', format(100-t1.variable_value*100/t2.variable_value,2), '<td> >95', '<td>Increase KEY_BUFFER_SIZE'
from performance_schema.global_status t1, performance_schema.global_status t2
where t1.variable_name='KEY_WRITES' and t2.variable_name='KEY_WRITE_REQUESTS'
union
select '<tr><!18><td>', 'Log Cache: InnoDB Log Write Ratio',
 '<td align=right>', format(100-t1.variable_value*100/t2.variable_value,2), '<td> >95', '<td>Increase INNODB_LOG_BUFFER_SIZE'
from performance_schema.global_status t1, performance_schema.global_status t2
where t1.variable_name='INNODB_LOG_WRITES' and t2.variable_name='INNODB_LOG_WRITE_REQUESTS'
union
select '<tr><!19a><td>', 'Query Cache: Efficiency (Hit/Select)',
 '<td align=right>', format(t1.variable_value*100/(t1.variable_value+t2.count_star),2), '<td> >30', '<td>'
from performance_schema.global_status t1, performance_schema.events_statements_summary_global_by_event_name t2
where t1.variable_name='QCACHE_HITS'
  and t2.event_name='statement/sql/select'
union
select '<tr><!19b><td>', 'Query Cache: Hit ratio (Hit/Query Insert)',
 '<td align=right>', format(t1.variable_value*100/(t1.variable_value+t2.variable_value),2), '<td> >80', '<td>'
from performance_schema.global_status t1, performance_schema.global_status t2
where t1.variable_name='QCACHE_HITS'
  and t2.variable_name='QCACHE_INSERTS'
union
select '<tr><!20><td>', s.variable_name, '<td align=right>', concat(s.variable_value, ' /', v.variable_value),
 '<td>Far from maximum', '<td>Increase MAX_CONNECTIONS'
from performance_schema.global_status s, performance_schema.global_variables v
where s.variable_name='THREADS_CONNECTED'
and v.variable_name='MAX_CONNECTIONS'
union
select '<tr><!21><td>', variable_name, '<td align=right>', variable_value, '<td>LOW', '<td>Check user load'
from performance_schema.global_status
where variable_name='THREADS_RUNNING'
union
select '<tr><!30><td>', variable_name, '<td align=right>', format(variable_value,0), '<td>LOW', '<td>Check application'
from performance_schema.global_status
where variable_name='SLOW_QUERIES'
union
select '<tr><!40><td>', g1.variable_name, ' #/sec.<td align=right>', format(g1.variable_value/g2.variable_value,5), '', ''
from performance_schema.global_status g1, performance_schema.global_status g2
where g1.variable_name='QUESTIONS'
  and g2.variable_name='UPTIME'
union
select '<tr><!41><td>', 'SELECT', ' #/sec.<td align=right>', format(g1.count_star/g2.variable_value,5), '', ''
from performance_schema.events_statements_summary_global_by_event_name g1, performance_schema.global_status g2
where g1.EVENT_NAME = 'statement/sql/select'
  and g2.variable_name='UPTIME'
union
select '<tr><!42><td>', 'COMMIT', ' #/sec. (TPS)<td align=right>', format(g1.count_star/g2.variable_value,5), '', ''
from performance_schema.events_statements_summary_global_by_event_name g1, performance_schema.global_status g2
where g1.EVENT_NAME = 'statement/sql/commit'
  and g2.variable_name='UPTIME'
union
select '<tr><!37><td>', g1.variable_name, ' #/sec.<td align=right>', format(g1.variable_value/g2.variable_value,5), '', ''
from performance_schema.global_status g1, performance_schema.global_status g2
where g1.variable_name='CONNECTIONS'
  and g2.variable_name='UPTIME'
union
select '<tr><!45><td>','COM DML #/sec.','<td align=right>',
       format((g2.count_star+g3.count_star+g4.count_star+g5.count_star+g6.count_star
               +g7.count_star+g8.count_star+g9.count_star)/g1.variable_value,5),
       '', ''
from performance_schema.global_status g1, performance_schema.events_statements_summary_global_by_event_name g2,
     performance_schema.events_statements_summary_global_by_event_name g3, performance_schema.events_statements_summary_global_by_event_name g4,
     performance_schema.events_statements_summary_global_by_event_name g5, performance_schema.events_statements_summary_global_by_event_name g6,
     performance_schema.events_statements_summary_global_by_event_name g7, performance_schema.events_statements_summary_global_by_event_name g8,
     performance_schema.events_statements_summary_global_by_event_name g9
where g1.variable_name='UPTIME'
  and g2.event_name='statement/sql/insert'
  and g3.event_name ='statement/sql/update'
  and g4.event_name ='statement/sql/delete'
  and g5.event_name ='statement/sql/select'
  and g6.event_name ='statement/sql/update_multi'
  and g7.event_name ='statement/sql/delete_multi'
  and g8.event_name ='statement/sql/replace'
  and g9.event_name ='statement/sql/replace_select'
union
select '<tr><!50><td>', g1.variable_name, ' Mb/sec.<td align=right>',
       format(g1.variable_value*8/(g2.variable_value*1024*1024),5), '', ''
from performance_schema.global_status g1, performance_schema.global_status g2
where g1.variable_name='BYTES_SENT'
  and g2.variable_name='UPTIME'
union
select '<tr><!51><td>', g1.variable_name, ' Mb/sec.<td align=right>',
       format(g1.variable_value*8/(g2.variable_value*1024*1024),5), '', ''
from performance_schema.global_status g1, performance_schema.global_status g2
where g1.variable_name='BYTES_RECEIVED'
  and g2.variable_name='UPTIME'
union
select '<tr><!35><td>', 'DBcpu (SUM_TIMER_WAIT)', '<td align=right>',
       format((sum(SUM_TIMER_WAIT)/1000000000000)/variable_value, 5), '', ''
  from performance_schema.global_status, performance_schema.events_statements_summary_global_by_event_name
 where variable_name='UPTIME'
 group by variable_value
order by 1;
select '</table><p>';

select '<a id="sqls"></a><P><table border="2"><tr><td><b>SQL Statements</b></td>' ;
select '<td align="right">Representativeness:',
       round((1-sum(if(digest is null, count_star,0))/sum(count_star))*100,2), '%'
  from performance_schema.events_statements_summary_by_digest;
select '<tr><td><b>Schema</b>','<td><b>Text</b>',
       '<td><b>Count</b>','<td><b>Sum Timer</b>','<td><b>Human Timer</b>','<td><b>Average (sec.)</b>',
       '<td><b>Rows affected</b>','<td><b>Rows Sent</b>','<td><b>Rows Examined</b>',
       '<td><b>TMP Disk Create</b>','<td><b>TMP Create</b>',
       '<td><b>Sort Merge#</b>','<td><b>No Index</b>','<td><b>No Good Index</b>';
select '<tr><td>',SCHEMA_NAME,'<td>',substr(DIGEST_TEXT,1,132),' ...<td align="right">',COUNT_STAR,'<td align="right">',
 SUM_TIMER_WAIT,'<td align="right">',SEC_TO_TIME(SUM_TIMER_WAIT/1000000000000),'<td align="right">',
 round(AVG_TIMER_WAIT/1000000000000,3) AVG_TIMER_WAIT,'<td align="right">',
 SUM_ROWS_AFFECTED,'<td align="right">',SUM_ROWS_SENT,'<td align="right">',SUM_ROWS_EXAMINED,'<td align="right">',
 SUM_CREATED_TMP_DISK_TABLES,'<td>',SUM_CREATED_TMP_TABLES,'<td>',SUM_SORT_MERGE_PASSES,'<td>', 
 SUM_NO_INDEX_USED,'<td align="right">',SUM_NO_GOOD_INDEX_USED
  from performance_schema.events_statements_summary_by_digest order by SUM_TIMER_WAIT desc limit 5;
select '</table><p>';

select '<P><A NAME="hostc"></A>' ;
select '<P><table border="2"><tr><td><b>Host Cache</b></td></tr>' ;
select '<tr><td><b>Host</b>',
 '<td><b>IP</b>',
 '<td><b>Validated</b>',
 '<td><b>SUM Errors</b>',
 '<td><b>First Seen</b>',
 '<td><b>Last Seen</b>',
 '<td><b>Last Error Seen</b>',
 '<td><b># Handshake Err.</b>',
 '<td><b># Authentication Err.</b>',
 '<td><b># ACL Err.</b>';
select '<tr><td>', host, '<td>', ip, '<td>', host_validated,
       '<td align="right"><b>', SUM_CONNECT_ERRORS ERR,
       '</b><td>', FIRST_SEEN, '<td>', LAST_SEEN, '<td>', LAST_ERROR_SEEN,
       '<td align="right">', COUNT_HANDSHAKE_ERRORS,
       '<td align="right">', COUNT_AUTHENTICATION_ERRORS,
       '<td align="right">', COUNT_HOST_ACL_ERRORS
from performance_schema.host_cache;
select '</table><p>' ;

select '<P><A NAME="par"></A>' ;
select '<P><table border="2"><tr><td><b>MySQL Parameters</b></td></tr>';
select '<tr><td><b>Parameter</b>',
 '<td><b>Value</b>' ;
select '<tr><td>', variable_name, '<td>', substr(replace(variable_value,',',', '),1,120)
  from performance_schema.global_variables
 where variable_name<>'server_audit_loc_info'
 order by variable_name;
select '</table><p>' ;

select '<hr><P><A NAME="xgdpr"></A><h2>GDPR Cross Reference</h2>';
select '<P><table border="2"><tr><td style="text-align: center;"><b><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679">GDPR Article </a></b>';
select '<td width="40%"><b>Title</b>', '<td><b>Checks</b>';
select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e1888-1-1">6<td>Lawfulness of processing<td>';
 select '<a href="#dp2">Tablespace encryption</a>, <a href="#dp2a">Encryption enabled</a>, <a href="#dp2c">Suspect sensitive tables</a>' ;

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e2001-1-1">7<td>Conditions for consent<td>';

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e2599-1-1">16<td>Right to rectification<td>';

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e2606-1-1">17<td>Right to erasure (‘right to be forgotten’)<td>';
 select '<a href="#dp5c">Backup policies</a>, <a href="#dp5d">Binlog retention</a>, <a href="#sx2e">System backup</a>,</a>' ;

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e2700-1-1">18<td>Right to restriction of processing<td>';
 select '<a href="#ac1">Separation of Roles</a>, ';
 select '<a href="#dp7">Data Masking</a>, <a href="#dp7a">miXen package</a>';

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e2753-1-1">20<td>Right to data portability<td>';

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e3063-1-1">25<td>Data protection by design and by default<td>';
 select '<a href="#ac2">Application user credential protection</a>, <a href="#ac7a">Password expire</a>, <a href="#dp1">Application encryption</a>, ';
 select '<a href="#sc2p">Password policy</a>, <a href="#sy2c">Security Flags</a>,';
 select '<a href="#ac1">Separation of Roles</a>, ';
 select '<a href="#dp7">Data Masking</a>, <a href="#dp7a">miXen package</a>';

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e3258-1-1">29<td>Processing under the authority of the controller or processor<td>';
 select '<a href="#ac1">Separation of Roles</a>, ';
 select '<a href="#dp7">Data Masking</a>, <a href="#dp7a">miXen package</a>';

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e3265-1-1">30<td>Records of processing activities<td>';
 select '<a href="#lg4">Event management</a>, <a href="#lg4a">Log Management</a>, <a href="#lg5"> Auditing</a>' ;

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e3383-1-1">32<td>Security of processing<td>';
 select '<a href="#sc">Secure configuration</a>,';
 select '<a href="#sc2c">DB Password check</a>,';
 select '<a href="#sc2q">Performance statistics</a>,';
 select '<a href="#h4">Monitoring and Audit</a>, <a href="#lg1a">Suspect SQL</a>, <a href="#lg2">Logging</a>,';
 select '<a href="#sc2f">IDS</a>,' ;
 select '<a href="#lg5">Auditing</a>, <a href="#dp4">Network encryption</a>, <a href="#dp4a">SSL/TLS configured</a>,';
 select '<a href="#dp4b">Users required to use encryption</a>, <a href="#dp5">DB Backup execution</a>, <a href="#sx2e">System backup</a>,';
 select '<a href="#dp2">Tablespace encryption</a>, <a href="#dp2a">Encryption enabled</a>, <a href="#dp2c">Suspect sensitive tables</a>,' ;
 select '<a href="#ac1">Separation of Roles</a>,';
 select '<a href="#dp7">Data Masking</a>, <a href="#dp7a">miXen package</a>';

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e3434-1-1">33<td>Notification of a personal data breach to the supervisory authority<td>';
 select '<a href="#lg4a">Log Management</a>, <a href="#lg5"> Auditing</a>,' ;
 select '<a href="#sc2f">IDS</a>' ;

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e3490-1-1">34<td>Communication of a personal data breach to the data subject<td>';
 select '<a href="#dp2">Tablespace encryption</a>, <a href="#dp2a">Encryption enabled</a>, <a href="#dp2c">Suspect sensitive tables</a>' ;

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e3546-1-1">35<td>Data protection impact assessment<td>';
 select '<a href="#dp2c">Suspect sensitive tables</a>' ;

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e6494-1-1">89<td>Safeguards and derogations relating to processing for archiving purposes in the public interest, scientific or historical research purposes or statistical purposes<td>';
  select '<a href="#ac1">Separation of Roles</a>, ';
  select '<a href="#dp7">Data Masking</a>, <a href="#dp7a">miXen package</a>';

select '<tr><td style="text-align: center;"><a href="http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679#d1e6719-1-1">99<td>Entry into force and application<td>';
 select '<a href="#gdpr1">GDPR Countdown</a>, <a href="#gdpr1a">Days since promulgation</a>, <a href="#gdpr1b">Days since application</a>' ;
select '</table><p>' ;

select '<P><A NAME="xcis"></A><h2>CIS Benchmarks Cross Reference</h2>';
select '<P><table border="2"><tr><td style="text-align: center;"><b><a href="https://www.cisecurity.org/cis-benchmarks/">CIS Recommentations</a><br>for MySQL (for 5.7 only)</b>';
select '<td><b>Title</b>', '<td><b>Checks</b>';
select '<tr><td style="text-align: center;">1.1<td>Place Databases on Non-System Partitions<td>';
 select '<a href="#sc2h">Dedicated datadir</a>' ;
select '<tr><td style="text-align: center;">2.1.1 <td>Backup policy in place<td>';
 select '<a href="#dp5a">DB Backup execution</a>,' ;
 select '<a href="#dp5c">Backup policies</a>' ;
select '<tr><td style="text-align: center;">2.1.4 <td>The backups should be properly secured<td>';
 select '<a href="#dp5b">Backup encryption</a>' ;
select '<tr><td style="text-align: center;">2.6 <td>Set a Password Expiry Policy for Specific Users<td>';
 select '<a href="#ac7a">Password expire</a>' ; 
select '<tr><td style="text-align: center;">4.1 <td>Ensure Latest Security Patches Are Applied<td>';
 select '<a href="#sc3a">MySQL update</a>' ;
select '<tr><td style="text-align: center;">4.2 <td>Ensure the test Database Is Not Installed<td>';
 select '<a href="#sc2d2">Test schema</a>' ;
select '<tr><td style="text-align: center;">4.4 <td>Ensure local_infile Is Disabled<td>';
 select '<a href="#sc2r">local_infile</a>' ;
select '<tr><td style="text-align: center;">4.6 <td>Ensure --skip-symbolic-links Is Enabled<td>';
 select '<a href="#sc2s">Symbolic Links</a>' ;
select '<tr><td style="text-align: center;">4.7 <td>Ensure the daemon_memcached Plugin Is Disabled<td>';
 select '<a href="#sc2i">Memcache plugin</a>' ;
select '<tr><td style="text-align: center;">4.8 <td>Ensure secure_file_priv Is Not Empty<td>';
 select '<a href="#sc2l">secure_file_priv</a>' ;
select '<tr><td style="text-align: center;">4.9 <td>Ensure sql_mode Contains STRICT_ALL_TABLES<td>';
 select '<a href="#lg1b">Strict SQL mode</a>' ;
select '<tr><td style="text-align: center;">5.1 <td>Ensure Only Administrative Users Have Full Database Access<td>';
 select '<a href="#usr">Users</a>' ;
select '<tr><td style="text-align: center;">5.2 <td>Ensure file_priv Is Not Set to Y for Non-Administrative Users<td>';
 select '<a href="#sc2e">Admin or Oper users &lt;&gt;root</a>,' ;
 select '<a href="#usr">Users</a>' ;
select '<tr><td style="text-align: center;">5.3 <td>Ensure process_priv Is Not Set to Y for Non-Administrative Users<td>';
 select '<a href="#usr">Users</a>' ;
select '<tr><td style="text-align: center;">5.4 <td>Ensure super_priv Is Not Set to Y for Non-Administrative Users<td>';
 select '<a href="#sc2e">Admin or Oper users &lt;&gt;root</a>,' ;
 select '<a href="#usr">Users</a>' ;
select '<tr><td style="text-align: center;">5.5 <td>Ensure shutdown_priv Is Not Set to Y for Non-Administrative Users<td>';
 select '<a href="#usr">Users</a>' ;
select '<tr><td style="text-align: center;">5.6 <td>Ensure create_user_priv Is Not Set to Y for Non-Administrative Users<td>';
 select '<a href="#usr">Users</a>' ;
select '<tr><td style="text-align: center;">5.7 <td>Ensure grant_priv Is Not Set to Y for Non-Administrative Users<td>';
 select '<a href="#usr">Users</a>' ;
select '<tr><td style="text-align: center;">5.8 <td>Ensure repl_slave_priv Is Not Set to Y for Non-Administrative Users<td>';
 select '<a href="#usr">Users</a>' ;
select '<tr><td style="text-align: center;">5.9 <td>Ensure DML/DDL Grants Are Limited to Specific Databases and Users<td>';
 select '<a href="#ac1e">CRUD users</a>,' ;
 select '<a href="#sc2e">Admin or Oper users &lt;&gt;root</a>,' ;
 select '<a href="#usr">Users</a>' ;
select '<tr><td style="text-align: center;">6.1 <td>Ensure log_error Is Not Empty<td>';
 select '<a href="#lg2c">Error Log</a>' ;
select '<tr><td style="text-align: center;">6.2 <td>Ensure Log Files Are Stored on a Non-System Partition<td>';
 select '<a href="#lg2d">Binlog Path</a>' ;
select '<tr><td style="text-align: center;">6.3 <td>Ensure log_error_verbosity Is Not Set to 1<td>';
 select '<a href="#lg2e">Error Level</a>' ;
select '<tr><td style="text-align: center;">6.4 <td>Ensure Audit Logging Is Enabled<td>';
 select '<a href="#lg5a">Auditing active</a>,' ;
 select '<a href="#lg5b">Auditing event configuration</a>,' ;
 select '<a href="#lg5c">Auditing users whitelist</a>' ;
select '<tr><td style="text-align: center;">7.2 <td>Ensure sql_mode Contains NO_AUTO_CREATE_USER<td>';
 select '<a href="#sc2n">Automatic User Creation</a>' ; 
select '<tr><td style="text-align: center;">7.3 <td>Ensure Passwords Are Set for All MySQL Accounts<td>';
 select '<a href="#sc2c">DB Password check</a>' ;
select '<tr><td style="text-align: center;">7.4 <td>Ensure default_password_lifetime Is Less Than Or Equal To 90<td>';
 select '<a href="#ac7a">Password expire</a>' ;
select '<tr><td style="text-align: center;">7.5 <td>Ensure Password Complexity Is in Place<td>';
 select '<a href="#sc2o">Password lenght</a>,' ;
 select '<a href="#sc2p">Password policy</a>' ;
select '<tr><td style="text-align: center;">7.6 <td>Ensure No Users Have Wildcard Hostnames<td>';
 select '<a href="#sc2b">Any host access</a>' ;
select '<tr><td style="text-align: center;">7.7 <td>Ensure No Anonymous Accounts Exist<td>';
 select '<a href="#sc2a">Anonymous user</a>' ;
select '<tr><td style="text-align: center;">8.1 <td>Ensure have_ssl Is Set to YES<td>';
 select '<a href="#dp4a">SSL/TLS configured</a>' ;
select '<tr><td style="text-align: center;">8.2 <td>Ensure ssl_type Is Set to ANY, X509, or SPECIFIED for All Remote Users<td>';
 select '<a href="#dp4b">Users required to use encryption</a>' ;
select '<tr><td style="text-align: center;">9.2 <td>Ensure MASTER_SSL_VERIFY_SERVER_CERT Is Set to YES or 1<td>';
 select '<a href="#sc2t">Verify Master certificate</a>' ;
select '<tr><td style="text-align: center;">9.3 <td>Ensure master_info_repository Is Set to TABLE<td>';
 select '<a href="#sc2m">Master Info</a>' ;
select '<tr><td style="text-align: center;">9.4 <td>Ensure super_priv Is Not Set to Y for Replication Users<td>';
 select '<a href="#sc2e">Admin or Oper users &lt;&gt;root</a>,' ;
 select '<a href="#usr">Users</a>' ;
select '<tr><td style="text-align: center;">9.5 <td>Ensure No Replication Users Have Wildcard Hostnames<td>';
 select '<a href="#usr">Users</a>' ;
select '</table><p>' ;

select '<P><A NAME="xcve"></A><h2>CVE</h2>';
select '<P><table border="2"><tr><td style="text-align: center;"><b><a href="https://www.cvedetails.com/vulnerability-list.php?vendor_id=93&product_id=21801&order=3">CVE Details</a><td>for MySQL 8.0</b>';
select '<tr><td><b>Version</b>', '<td><b>CVE</b>', '<td><b>Score</b>';

select concat('<tr><td>',version()), '<td><b><a href="#sc3">Detected version</a></b>', '<td>'
union select '<tr><td>8.0.11<!---->', '<td>CVE-2018-3064', '<td style="text-align: right;"> 5.5'	
union select '<tr><td>8.0.11<!---->', '<td>CVE-2018-3060', '<td style="text-align: right;"> 5.5'
union select '<tr><td>8.0.01<!---->', '<td>CVE-2016-6663', '<td style="text-align: right;"> 4.4'	
order by 1 desc, 3 desc;
select '</table><p>' ;

select '<hr><p>' ;
select '<br>The MIT License';
select '<br>Copyright &copy; 2017-2018 XeniaLAB srl http://www.xenialab.it';
select '<p>Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),';
select ' to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,';
select ' and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:';
select '<br>The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.';

select '<p><b>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,';
select ' FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,';
select ' WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.</b><p><br>';

select '<hr><P>Statistics generated on: ', now();
select '<p>For more information or suggestions on MySAT contact' ;
select '<A HREF="mailto:mail@info.xenialab.it?subject=MySAT">XeniaLAB</A>.<hr><p></body></html>' ;
