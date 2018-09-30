# MySAT
**MySQL Database Security Assessment Tool**

MySAT performs several test to analyze database configurations and security policies.
MySAT can help to assess and therefore to increase MySQL database security.

MySAT is a simple SQL script, it is easy to understand and easy to mantain.
MySAT result is a report in HTML format.

## Running MySAT

To run MySAT execute the following command on Your MySQL database:

	mysql --user=root -pXXX --skip-column-names -f < mysat.sql > MySAT.htm

#### Report

MySAT generates a straightforward report in HTML.
MySAT report contains 3 parts:
* security check results
* configuration summary and details
* cross references with GDPR Articles and CIS Benchmarks and CVE short list

## Version support

MySAT can be used with all MySQL and MySQL forks version but
for security reasons we strongly suggest to use MySQL 5.7 or newer.
Always update to the last minor update available.
For MySQL 8.0 there are many differences and a specific script **mysat.80.sql** is available.


#### References

MySQL reference version are *MySQL Community Server 5.7* and *MySQL Community Server 8.0*.

GDPR Cross Reference contains links to GDPR articles (http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679).

CIS Benckmars Cross Reference is based on *CIS Oracle MySQL Community Server 5.7 Benchmark* v.1.0.0 (http://benchmarks.cisecurity.org).

CVE short list and scores are based on *CVE Details* (https://www.cvedetails.com).

A simple description of MySAT is available in Italian (https://www.xenialab.it/meo/web/white/oracle/mysat.htm).
