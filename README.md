# MySAT
**MySQL Database Security Assessment Tool**

MySAT performs several test to analyze database configurations and security policies.
MySAT can help to assess and therefore to increase MySQL database security.

MySAT is a simple SQL script it is easy to understand and easy to mantain.
MySAT result is a report in HTML format.

## Running MySAT

To run MySAT execute the following command on Your MySQL database:
	`mysql --user=root -pXXX --skip-column-names -f < mysat.sql > MySAT.htm`

#### Report Output

MySAT generates an easy to read output in HTML.
MySAT report contains 3 parts:
* security check results
* configuration summary and details
* check cross references with CIS Benchmarks and GDPR Articles


#### References

MySQL reference version is *MySQL Community Server 5.7*.

Cross reference section for GDPR (http://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679)
contains links for more technical articles
Cross reference section for CIS Benckmars (http://benchmarks.cisecurity.org) is based on
*CIS Oracle MySQL Community Server 5.7 v.1.0.0. 12-29-2015*

