Summary of Findings
Total YAML rule files in the repository: 2,055
Rules in your priority languages: 763
Rules with HIGH impact + HIGH confidence + LOW likelihood: 8
Rules with HIGH impact + HIGH confidence + MEDIUM likelihood: 4
Rules with HIGH impact + HIGH confidence + HIGH likelihood: 5
Rules with HIGH impact + MEDIUM confidence + LOW likelihood: 15
Top 50 High Priority Bugs
Tier 1: HIGH impact + HIGH confidence + LOW likelihood (8)
documentbuilderfactory-disallow-doctype-decl-false (Java) - XXE vulnerability in XML processing
documentbuilderfactory-disallow-doctype-decl-missing (Java) - XXE vulnerability in XML processing
documentbuilderfactory-external-general-entities-true (Java) - XXE vulnerability in XML processing
documentbuilderfactory-external-parameter-entities-true (Java) - XXE vulnerability in XML processing
saxparserfactory-disallow-doctype-decl-missing (Java) - XXE vulnerability in XML processing
transformerfactory-dtds-not-disabled (Java) - XXE vulnerability in XML processing
hashids-with-django-secret (Python) - Insecure use of HashIDs with Django secret key
hashids-with-flask-secret (Python) - Insecure use of HashIDs with Flask secret key
Tier 2: HIGH impact + HIGH confidence + MEDIUM likelihood (4)
tainted-file-path (Java) - User input controlling file paths leading to path traversal
subprocess-injection (Python) - Command injection via subprocess
insecure-binaryformatter-deserialization (C#) - Dangerous deserialization vulnerability
jwt-simple-noverify (JavaScript) - JWT token verification bypass
Tier 3: HIGH impact + HIGH confidence + HIGH likelihood (5)
tainted-system-command (Java) - Command injection vulnerability
express-libxml-noent (JavaScript) - XXE vulnerability in Express
express-session-hardcoded-secret (JavaScript) - Hardcoded credentials
express-third-party-object-deserialization (JavaScript) - Remote code execution via deserialization
express-sequelize-injection (JavaScript) - SQL injection in Express
Tier 4: HIGH impact + MEDIUM confidence + LOW likelihood (15)
java-jwt-decode-without-verify (Java) - JWT verification bypass
find-sql-string-concatenation (Java) - SQL injection via string concatenation
jackson-unsafe-deserialization (Java) - RCE via Jackson deserialization
xmlinputfactory-possible-xxe (Java) - XXE vulnerability
sqlalchemy-sql-injection (Python) - SQL injection in SQLAlchemy
insecure-use-gets-fn (C) - Buffer overflow vulnerability
random-fd-exhaustion (C) - File descriptor exhaustion
insecure-fspickler-deserialization (C#) - Insecure deserialization
insecure-losformatter-deserialization (C#) - Insecure deserialization
insecure-netdatacontract-deserialization (C#) - Insecure deserialization
insecure-soapformatter-deserialization (C#) - Insecure deserialization
csharp-sqli (C#) - SQL injection vulnerability
awscdk-bucket-encryption (TypeScript) - Unencrypted S3 buckets
awscdk-sqs-unencryptedqueue (TypeScript) - Unencrypted SQS queues
deno-dangerous-run (JavaScript) - Command injection in Deno
Tier 5: HIGH impact + MEDIUM confidence + MEDIUM likelihood (18)
tainted-sql-string (Java) - SQL injection vulnerability
tainted-sqli (Java) - SQL injection in AWS Lambda
spring-actuator-fully-enabled-yaml (Java) - Exposed sensitive endpoints
empty-aes-key (Python) - Weak encryption with empty AES key
user-eval-format-string (Python) - Remote code execution via eval
user-eval (Python) - Remote code execution via eval
user-exec-format-string (Python) - Remote code execution via exec
user-exec (Python) - Remote code execution via exec
command-injection-os-system (Python) - Command injection via os.system
sql-injection-using-extra-where (Python) - SQL injection in Django
sql-injection-using-rawsql (Python) - SQL injection in Django
sql-injection-db-cursor-execute (Python) - SQL injection in Django
ssrf-injection-requests (Python) - Server-side request forgery
os-system-injection (Python) - Command injection vulnerability
path-traversal-open (Python) - Path traversal vulnerability
dangerous-subprocess-use (Python) - Command injection via subprocess
detect-child-process (JavaScript) - Command injection in AWS Lambda
jwt-none-alg (JavaScript) - JWT algorithm bypass

command-injection-process-builder (Java) - Command injection via ProcessBuilder
command-injection-formatted-runtime-call (Java) - Command injection via Runtime.exec
anonymous-ldap-bind (Java) - Anonymous LDAP authentication vulnerability
el-injection (Java) - Expression Language injection vulnerability
java-reverse-shell (Java) - Potential reverse shell behavior
jdbc-sql-formatted-string (Java) - SQL injection via JDBC
ldap-entry-poisoning (Java) - LDAP entry poisoning vulnerability
ldap-injection (Java) - LDAP injection vulnerability
object-deserialization (Java) - Insecure object deserialization
hibernate-sqli (Java) - SQL injection via Hibernate
HIGH impact + LOW confidence (Continued)
spring-data-jpa-sqli (Java) - SQL injection in Spring Data JPA
spring-expression-injection (Java) - Spring Expression Language injection
spring-view-manipulation (Java) - Spring view name manipulation
tainted-sql-raw (Java) - SQL injection via raw queries
xpath-injection (Java) - XPath injection vulnerability
xxe-saxreader (Java) - XML External Entity vulnerability in SAXReader
xxe-xmlreader (Java) - XML External Entity vulnerability in XMLReader
xxe-documentbuilderfactory (Java) - XML External Entity vulnerability in DocumentBuilderFactory
xxe-saxbuilder (Java) - XML External Entity vulnerability in SAXBuilder
xxe-saxparser (Java) - XML External Entity vulnerability in SAXParser
HIGH impact + LOW confidence (Python)
django-debug-true (Python) - Django debug mode enabled in production
django-sql-injection (Python) - SQL injection in Django
flask-debug-true (Python) - Flask debug mode enabled in production
insecure-deserialization-pickle (Python) - Insecure deserialization with pickle
insecure-deserialization-yaml (Python) - Insecure deserialization with YAML
jinja2-template-injection (Python) - Server-side template injection in Jinja2
paramiko-exec-command (Python) - Command injection via Paramiko
python-shell-injection (Python) - Shell injection vulnerability
python-code-injection (Python) - Code injection vulnerability
python-path-traversal (Python) - Path traversal vulnerability
HIGH impact + LOW confidence (JavaScript/TypeScript)
dangerous-eval (JavaScript) - Dangerous use of eval()
express-open-redirect (JavaScript) - Open redirect vulnerability in Express
express-path-traversal (JavaScript) - Path traversal in Express
express-body-parser-dos (JavaScript) - Denial of service via body-parser
handlebars-safestring (JavaScript) - XSS via Handlebars SafeString
insecure-cors (JavaScript) - Insecure CORS configuration
insecure-cookie (JavaScript) - Insecure cookie settings
jwt-exposed-credentials (JavaScript) - Exposed credentials in JWT
nodejs-command-injection (JavaScript) - Command injection in Node.js
nodejs-path-traversal (JavaScript) - Path traversal in Node.js
HIGH impact + LOW confidence (C/C#)
buffer-overflow (C) - Buffer overflow vulnerability
format-string-vulnerability (C) - Format string vulnerability
integer-overflow (C) - Integer overflow vulnerability
memory-leak (C) - Memory leak vulnerability
use-after-free (C) - Use-after-free vulnerability
csharp-command-injection (C#) - Command injection in C#
csharp-path-traversal (C#) - Path traversal in C#
csharp-xxe (C#) - XML External Entity vulnerability in C#
csharp-open-redirect (C#) - Open redirect vulnerability in C#
csharp-insecure-deserialization (C#) - Insecure deserialization in C#

java-jwt-hardcoded-secret - Hardcoded JWT secrets in Java
jwt-python-hardcoded-secret - Hardcoded JWT secrets in Python
hardcoded-jwt-secret (jose) - Hardcoded JWT secrets in JavaScript's jose library
hardcoded-jwt-secret (jsonwebtoken) - Hardcoded JWT secrets in jsonwebtoken library
express-session-hardcoded-secret - Hardcoded Express session secrets
express-jwt-hardcoded-secret - Hardcoded Express JWT secrets
hardcoded-passport-secret - Hardcoded Passport JWT secrets
hardcoded-hmac-key - Hardcoded HMAC keys in JavaScript
hardcoded-token - Hardcoded tokens in boto3 (AWS)
avoid_hardcoded_config_SECRET_KEY - Hardcoded Flask secret keys
hardcoded-password-default-argument - Hardcoded passwords in default arguments
Exposed Credentials
jwt-python-exposed-credentials - Credentials exposed in JWT payloads
jwt-exposed-data - Sensitive data exposure in JWT payloads
jose-exposed-data - Sensitive data exposure in jose JWT payloads
python-logger-credential-disclosure - Credentials being logged
Insecure Authentication
anonymous-ldap-bind - Anonymous LDAP authentication
ldap-injection - LDAP injection vulnerabilities
mongo-client-bad-auth - Insecure MongoDB authentication
no-auth-over-http - Authentication over unencrypted HTTP
missing-or-broken-authorization - Missing or broken authorization in C#
JWT-Specific Vulnerabilities
jwt-none-alg (Java) - Use of 'none' algorithm in JWT tokens
jwt-none-alg (JavaScript) - Use of 'none' algorithm in JWT tokens
jwt-python-none-alg - Use of 'none' algorithm in JWT tokens in Python
java-jwt-decode-without-verify - JWT decoding without verification in Java
jwt-decode-without-verify - JWT decoding without verification in JavaScript
jwt-tokenvalidationparameters-no-expiry-validation - JWT tokens without expiry validation
Easily Exploitable Cryptographic Issues
empty-aes-key - Empty AES encryption keys
blowfish-insufficient-key-size - Critically weak Blowfish key sizes
use-of-weak-rsa-key - Critically weak RSA keys
unsigned-security-token - Unsigned security tokens
Insecure Password Handling
md5-used-as-password (Java) - Use of MD5 for password hashing
md5-used-as-password (JavaScript) - Use of MD5 for password hashing
password-empty-string - Empty string passwords
use-none-for-password-default - None used as default password
unvalidated-password - Unvalidated passwords in Django
Critical Deserialization Issues
object-deserialization - Insecure object deserialization in Java
hashids-with-django-secret - Insecure use of HashIDs with Django secret
hashids-with-flask-secret - Insecure use of HashIDs with Flask secret
API Keys and Tokens
X509Certificate2-privkey - Issues with X509 certificate private keys
paramiko-implicit-trust-host-key - Implicit trust of host keys in SSH connections
