use git2::{ObjectType, Repository, TreeWalkMode, TreeWalkResult};
use regex::Regex;

use crate::display;

struct SastRule {
    name: &'static str,
    severity: &'static str,
    pattern: Regex,
    extensions: &'static [&'static str],
    description: &'static str,
}

fn sast_rules() -> Vec<SastRule> {
    vec![
        // -- Taint analysis: user input flowing into dangerous sinks --
        SastRule {
            name: "SQL injection (string interpolation in query)",
            severity: "HIGH",
            pattern: Regex::new(r#"(?i)(execute|query|raw)\s*\(.*(\+|format!|f"|fmt\.Sprintf|`\$\{)"#).unwrap(),
            extensions: &[".rs", ".go", ".py", ".ts", ".js", ".java"],
            description: "User input may flow into SQL query via string concatenation or interpolation",
        },
        SastRule {
            name: "SQL injection (format string in query)",
            severity: "HIGH",
            pattern: Regex::new(r#"(?i)(\.query|\.execute|\.raw)\(.*%[sd]"#).unwrap(),
            extensions: &[".py", ".go"],
            description: "SQL query uses format string that may include unsanitized input",
        },
        // -- Insecure deserialization --
        SastRule {
            name: "Insecure deserialization (Python pickle)",
            severity: "HIGH",
            pattern: Regex::new(r"pickle\.(loads?|Unpickler)\(").unwrap(),
            extensions: &[".py"],
            description: "pickle.load/loads can execute arbitrary code from untrusted data",
        },
        SastRule {
            name: "Insecure deserialization (Python yaml.load)",
            severity: "HIGH",
            pattern: Regex::new(r"yaml\.load\(").unwrap(),
            extensions: &[".py"],
            description: "yaml.load without SafeLoader can execute arbitrary code",
        },
        SastRule {
            name: "Insecure deserialization (Java ObjectInputStream)",
            severity: "HIGH",
            pattern: Regex::new(r"ObjectInputStream|readObject\(\)").unwrap(),
            extensions: &[".java"],
            description: "Java deserialization of untrusted data can lead to RCE",
        },
        SastRule {
            name: "Insecure deserialization (PHP unserialize)",
            severity: "HIGH",
            pattern: Regex::new(r"\bunserialize\s*\(").unwrap(),
            extensions: &[".php"],
            description: "PHP unserialize of untrusted data can lead to object injection",
        },
        // -- Path traversal --
        SastRule {
            name: "Path traversal (dot-dot in path operations)",
            severity: "MEDIUM",
            pattern: Regex::new(r#"(?i)(open|read_to_string|readFile|readFileSync|os\.Open|ioutil\.ReadFile)\s*\(.*\.\."#).unwrap(),
            extensions: &[".rs", ".go", ".py", ".ts", ".js", ".java"],
            description: "File operation with potential path traversal via '..'",
        },
        SastRule {
            name: "Path traversal (user input in file path)",
            severity: "MEDIUM",
            pattern: Regex::new(r"(?i)(req\.params|req\.query|req\.body|request\.form|request\.args)\[.*\].*(?:open|read|write|path\.join)").unwrap(),
            extensions: &[".py", ".ts", ".js"],
            description: "User input from request used in file path operations",
        },
        SastRule {
            name: "Path traversal (unsanitized path join)",
            severity: "MEDIUM",
            pattern: Regex::new(r"(?:path\.Join|filepath\.Join|path\.join|os\.path\.join)\(.*(?:req|request|params|query|input|user)").unwrap(),
            extensions: &[".go", ".py", ".ts", ".js"],
            description: "Path join with potentially unsanitized user input",
        },
        // -- Unsafe eval / exec / dynamic code execution --
        SastRule {
            name: "Unsafe eval()",
            severity: "HIGH",
            pattern: Regex::new(r"\beval\s*\(").unwrap(),
            extensions: &[".js", ".ts", ".py"],
            description: "eval() executes arbitrary code and should be avoided",
        },
        SastRule {
            name: "Unsafe exec()",
            severity: "HIGH",
            pattern: Regex::new(r"\bexec\s*\(").unwrap(),
            extensions: &[".py"],
            description: "exec() executes arbitrary code and should be avoided",
        },
        SastRule {
            name: "Unsafe Function constructor",
            severity: "HIGH",
            pattern: Regex::new(r"new\s+Function\s*\(").unwrap(),
            extensions: &[".js", ".ts"],
            description: "Function constructor creates code from strings, similar to eval",
        },
        SastRule {
            name: "Dynamic import with variable",
            severity: "MEDIUM",
            pattern: Regex::new(r#"(?:require|import)\s*\(\s*[a-zA-Z_$]"#).unwrap(),
            extensions: &[".js", ".ts"],
            description: "Dynamic require/import with non-literal argument may load untrusted modules",
        },
        SastRule {
            name: "Unsafe setTimeout/setInterval with string",
            severity: "MEDIUM",
            pattern: Regex::new(r#"(?:setTimeout|setInterval)\s*\(\s*['"]"#).unwrap(),
            extensions: &[".js", ".ts"],
            description: "setTimeout/setInterval with string argument acts like eval",
        },
        // -- Language-specific rules --
        // Rust unsafe blocks
        SastRule {
            name: "Rust unsafe block",
            severity: "INFO",
            pattern: Regex::new(r"\bunsafe\s*\{").unwrap(),
            extensions: &[".rs"],
            description: "unsafe block bypasses Rust's safety guarantees — review for soundness",
        },
        SastRule {
            name: "Rust unsafe fn",
            severity: "INFO",
            pattern: Regex::new(r"\bunsafe\s+fn\b").unwrap(),
            extensions: &[".rs"],
            description: "unsafe function requires callers to uphold safety invariants",
        },
        SastRule {
            name: "Rust raw pointer dereference",
            severity: "MEDIUM",
            pattern: Regex::new(r"\*(?:const|mut)\s+\w").unwrap(),
            extensions: &[".rs"],
            description: "Raw pointer usage may lead to undefined behavior if misused",
        },
        // JavaScript prototype pollution
        SastRule {
            name: "JS prototype pollution (direct __proto__)",
            severity: "HIGH",
            pattern: Regex::new(r"__proto__").unwrap(),
            extensions: &[".js", ".ts"],
            description: "Direct __proto__ access can enable prototype pollution attacks",
        },
        SastRule {
            name: "JS prototype pollution (Object.assign with user input)",
            severity: "MEDIUM",
            pattern: Regex::new(r"Object\.assign\s*\(\s*\{\s*\}\s*,.*(?:req|request|body|params|query|input)").unwrap(),
            extensions: &[".js", ".ts"],
            description: "Object.assign with user-controlled input may allow prototype pollution",
        },
        SastRule {
            name: "JS prototype pollution (recursive merge)",
            severity: "MEDIUM",
            pattern: Regex::new(r"(?:deepMerge|merge|extend|assign)\s*\(.*(?:req|request|body|params|query|input)").unwrap(),
            extensions: &[".js", ".ts"],
            description: "Deep merge with user input may allow prototype pollution",
        },
        // ---- Go specific ----
        SastRule {
            name: "Go template injection",
            severity: "HIGH",
            pattern: Regex::new(r"template\.(HTML|JS|CSS)\(").unwrap(),
            extensions: &[".go"],
            description: "Direct use of template.HTML/JS/CSS bypasses auto-escaping",
        },
        SastRule {
            name: "Go weak TLS config",
            severity: "HIGH",
            pattern: Regex::new(r"tls\.Config\s*\{[^}]*InsecureSkipVerify\s*:\s*true").unwrap(),
            extensions: &[".go"],
            description: "InsecureSkipVerify disables TLS certificate verification",
        },
        SastRule {
            name: "Go unhandled error",
            severity: "MEDIUM",
            pattern: Regex::new(r"[^,]\s*:?=\s*\w+\.\w+\([^)]*\)\s*$").unwrap(),
            extensions: &[".go"],
            description: "Return value (possibly an error) may be silently discarded",
        },
        // ---- Command injection ----
        SastRule {
            name: "Shell command with user input",
            severity: "HIGH",
            pattern: Regex::new(r"(?:exec\.Command|subprocess\.(?:call|run|Popen)|child_process\.exec|os\.system)\s*\(.*(?:req|request|input|params|query|user|arg)").unwrap(),
            extensions: &[".go", ".py", ".js", ".ts", ".java"],
            description: "Shell command execution with potential user-controlled input",
        },

        // ================================================================
        //  Node.js / JavaScript / TypeScript
        // ================================================================

        // -- XSS --
        SastRule {
            name: "JS innerHTML assignment",
            severity: "HIGH",
            pattern: Regex::new(r"\.innerHTML\s*=").unwrap(),
            extensions: &[".js", ".ts", ".jsx", ".tsx"],
            description: "Direct innerHTML assignment can lead to XSS if input is unsanitized",
        },
        SastRule {
            name: "JS document.write",
            severity: "HIGH",
            pattern: Regex::new(r"document\.write\s*\(").unwrap(),
            extensions: &[".js", ".ts", ".jsx", ".tsx"],
            description: "document.write can inject unsanitized content into the DOM",
        },
        SastRule {
            name: "JS dangerouslySetInnerHTML",
            severity: "HIGH",
            pattern: Regex::new(r"dangerouslySetInnerHTML").unwrap(),
            extensions: &[".js", ".ts", ".jsx", ".tsx"],
            description: "dangerouslySetInnerHTML bypasses React's XSS protection",
        },
        // -- NoSQL injection --
        SastRule {
            name: "NoSQL injection (MongoDB query with user input)",
            severity: "HIGH",
            pattern: Regex::new(r"\.find\s*\(\s*\{.*(?:req\.|request\.|params\.|query\.|body\.)").unwrap(),
            extensions: &[".js", ".ts"],
            description: "MongoDB query built with user input may allow NoSQL injection",
        },
        SastRule {
            name: "NoSQL injection ($where operator)",
            severity: "HIGH",
            pattern: Regex::new(r#"\$where\s*:"#).unwrap(),
            extensions: &[".js", ".ts"],
            description: "MongoDB $where operator executes JavaScript and is vulnerable to injection",
        },
        // -- SSRF --
        SastRule {
            name: "JS SSRF (fetch/axios with user input)",
            severity: "HIGH",
            pattern: Regex::new(r"(?:fetch|axios\.get|axios\.post|http\.get|https\.get)\s*\(.*(?:req\.|request\.|params|query|body|input|user)").unwrap(),
            extensions: &[".js", ".ts"],
            description: "HTTP request with user-controlled URL may allow SSRF",
        },
        // -- Insecure crypto --
        SastRule {
            name: "JS weak hash algorithm (MD5/SHA1)",
            severity: "MEDIUM",
            pattern: Regex::new(r#"createHash\s*\(\s*['"](?:md5|sha1)['"]"#).unwrap(),
            extensions: &[".js", ".ts"],
            description: "MD5/SHA1 are cryptographically weak; use SHA-256 or stronger",
        },
        SastRule {
            name: "JS hardcoded JWT secret",
            severity: "HIGH",
            pattern: Regex::new(r#"(?:jwt\.sign|jwt\.verify)\s*\([^)]*,\s*['"][^'"]{1,}['"]"#).unwrap(),
            extensions: &[".js", ".ts"],
            description: "JWT secret appears hardcoded; use environment variables instead",
        },
        // -- Insecure headers / CORS --
        SastRule {
            name: "JS permissive CORS (wildcard origin)",
            severity: "MEDIUM",
            pattern: Regex::new(r#"(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*['"\*]?\*"#).unwrap(),
            extensions: &[".js", ".ts"],
            description: "Wildcard CORS origin allows any domain to make requests",
        },
        SastRule {
            name: "JS helmet disabled or missing",
            severity: "MEDIUM",
            pattern: Regex::new(r#"app\.disable\s*\(\s*['"]x-powered-by['"]\s*\)"#).unwrap(),
            extensions: &[".js", ".ts"],
            description: "Manually disabling x-powered-by; consider using helmet middleware instead",
        },
        // -- Regex DoS --
        SastRule {
            name: "JS ReDoS-prone regex",
            severity: "MEDIUM",
            pattern: Regex::new(r"new\s+RegExp\s*\(.*(?:req|request|params|query|body|input|user)").unwrap(),
            extensions: &[".js", ".ts"],
            description: "Regex built from user input may allow ReDoS attacks",
        },
        // -- Insecure randomness --
        SastRule {
            name: "JS Math.random for security",
            severity: "MEDIUM",
            pattern: Regex::new(r"Math\.random\s*\(\s*\)").unwrap(),
            extensions: &[".js", ".ts"],
            description: "Math.random() is not cryptographically secure; use crypto.randomBytes()",
        },
        // -- Misc Node.js --
        SastRule {
            name: "JS child_process.exec (shell injection)",
            severity: "HIGH",
            pattern: Regex::new(r"child_process\.exec\s*\(").unwrap(),
            extensions: &[".js", ".ts"],
            description: "child_process.exec uses a shell; prefer execFile or spawn for safety",
        },
        SastRule {
            name: "JS disable TLS verification",
            severity: "HIGH",
            pattern: Regex::new(r"NODE_TLS_REJECT_UNAUTHORIZED.*=.*0|rejectUnauthorized\s*:\s*false").unwrap(),
            extensions: &[".js", ".ts"],
            description: "Disabling TLS certificate verification exposes the app to MITM attacks",
        },
        SastRule {
            name: "JS unvalidated redirect",
            severity: "MEDIUM",
            pattern: Regex::new(r"(?:res\.redirect|response\.redirect)\s*\(.*(?:req\.|request\.|params|query|body)").unwrap(),
            extensions: &[".js", ".ts"],
            description: "Redirect with user-controlled URL may allow open redirect attacks",
        },

        // ================================================================
        //  Python
        // ================================================================

        // -- Command injection --
        SastRule {
            name: "Python os.system",
            severity: "HIGH",
            pattern: Regex::new(r"os\.system\s*\(").unwrap(),
            extensions: &[".py"],
            description: "os.system() executes shell commands and is vulnerable to injection",
        },
        SastRule {
            name: "Python subprocess with shell=True",
            severity: "HIGH",
            pattern: Regex::new(r"subprocess\.\w+\s*\(.*shell\s*=\s*True").unwrap(),
            extensions: &[".py"],
            description: "subprocess with shell=True is vulnerable to shell injection",
        },
        SastRule {
            name: "Python os.popen",
            severity: "HIGH",
            pattern: Regex::new(r"os\.popen\s*\(").unwrap(),
            extensions: &[".py"],
            description: "os.popen() executes shell commands; use subprocess with shell=False",
        },
        // -- SQL injection --
        SastRule {
            name: "Python SQL string formatting",
            severity: "HIGH",
            pattern: Regex::new(r#"(?:cursor\.execute|\.execute)\s*\(\s*(?:f['"]|['"].*%[sd]|['"].*\.format)"#).unwrap(),
            extensions: &[".py"],
            description: "SQL query built with string formatting; use parameterized queries",
        },
        // -- SSRF --
        SastRule {
            name: "Python SSRF (requests with user input)",
            severity: "HIGH",
            pattern: Regex::new(r"requests\.(?:get|post|put|delete|patch)\s*\(.*(?:request\.|form\[|args\[|input|user)").unwrap(),
            extensions: &[".py"],
            description: "HTTP request with user-controlled URL may allow SSRF",
        },
        // -- Insecure crypto --
        SastRule {
            name: "Python weak hash (MD5/SHA1)",
            severity: "MEDIUM",
            pattern: Regex::new(r"hashlib\.(?:md5|sha1)\s*\(").unwrap(),
            extensions: &[".py"],
            description: "MD5/SHA1 are cryptographically weak; use SHA-256 or stronger",
        },
        SastRule {
            name: "Python insecure random",
            severity: "MEDIUM",
            pattern: Regex::new(r"\brandom\.(?:random|randint|choice|randrange)\s*\(").unwrap(),
            extensions: &[".py"],
            description: "random module is not cryptographically secure; use secrets module",
        },
        // -- XXE --
        SastRule {
            name: "Python XML parsing (XXE)",
            severity: "HIGH",
            pattern: Regex::new(r"(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax)\.parse").unwrap(),
            extensions: &[".py"],
            description: "Standard XML parsers may be vulnerable to XXE; use defusedxml",
        },
        // -- SSTI --
        SastRule {
            name: "Python SSTI (Jinja2 from string)",
            severity: "HIGH",
            pattern: Regex::new(r"(?:Template|Environment)\s*\(.*(?:request|input|user|form|args)").unwrap(),
            extensions: &[".py"],
            description: "Template rendered from user input may allow server-side template injection",
        },
        SastRule {
            name: "Python render_template_string",
            severity: "HIGH",
            pattern: Regex::new(r"render_template_string\s*\(").unwrap(),
            extensions: &[".py"],
            description: "render_template_string with user input allows SSTI",
        },
        // -- Flask / Django specific --
        SastRule {
            name: "Flask debug mode in production",
            severity: "HIGH",
            pattern: Regex::new(r"app\.run\s*\(.*debug\s*=\s*True").unwrap(),
            extensions: &[".py"],
            description: "Flask debug mode exposes an interactive debugger; disable in production",
        },
        SastRule {
            name: "Django mark_safe with user input",
            severity: "HIGH",
            pattern: Regex::new(r"mark_safe\s*\(.*(?:request|input|user|form|args)").unwrap(),
            extensions: &[".py"],
            description: "mark_safe with user input bypasses Django's XSS protection",
        },
        SastRule {
            name: "Python assert for validation",
            severity: "MEDIUM",
            pattern: Regex::new(r"\bassert\s+.*(?:request|input|user|form|password|token|auth)").unwrap(),
            extensions: &[".py"],
            description: "assert statements are stripped with -O; do not use for security checks",
        },
        SastRule {
            name: "Python hardcoded secret key",
            severity: "HIGH",
            pattern: Regex::new(r#"(?:SECRET_KEY|API_KEY|PASSWORD)\s*=\s*['"][^'"]{4,}['"]"#).unwrap(),
            extensions: &[".py"],
            description: "Secret appears hardcoded; use environment variables instead",
        },
        SastRule {
            name: "Python disable SSL verification",
            severity: "HIGH",
            pattern: Regex::new(r"verify\s*=\s*False").unwrap(),
            extensions: &[".py"],
            description: "Disabling SSL verification exposes the app to MITM attacks",
        },

        // ================================================================
        //  Java
        // ================================================================

        // -- SQL injection --
        SastRule {
            name: "Java SQL injection (string concat in query)",
            severity: "HIGH",
            pattern: Regex::new(r#"(?:createStatement|executeQuery|executeUpdate|execute)\s*\(.*\+"#).unwrap(),
            extensions: &[".java"],
            description: "SQL query built with string concatenation; use PreparedStatement",
        },
        // -- Command injection --
        SastRule {
            name: "Java Runtime.exec",
            severity: "HIGH",
            pattern: Regex::new(r"Runtime\.getRuntime\(\)\.exec\s*\(").unwrap(),
            extensions: &[".java"],
            description: "Runtime.exec can execute arbitrary commands; validate all input",
        },
        SastRule {
            name: "Java ProcessBuilder with user input",
            severity: "HIGH",
            pattern: Regex::new(r"ProcessBuilder\s*\(.*(?:request|getParameter|input|user)").unwrap(),
            extensions: &[".java"],
            description: "ProcessBuilder with user-controlled input may allow command injection",
        },
        // -- XXE --
        SastRule {
            name: "Java XXE (DocumentBuilderFactory)",
            severity: "HIGH",
            pattern: Regex::new(r"DocumentBuilderFactory\.newInstance\(\)").unwrap(),
            extensions: &[".java"],
            description: "Default DocumentBuilderFactory is vulnerable to XXE; disable external entities",
        },
        SastRule {
            name: "Java XXE (SAXParserFactory)",
            severity: "HIGH",
            pattern: Regex::new(r"SAXParserFactory\.newInstance\(\)").unwrap(),
            extensions: &[".java"],
            description: "Default SAXParserFactory is vulnerable to XXE; disable external entities",
        },
        SastRule {
            name: "Java XXE (XMLInputFactory)",
            severity: "HIGH",
            pattern: Regex::new(r"XMLInputFactory\.newInstance\(\)").unwrap(),
            extensions: &[".java"],
            description: "Default XMLInputFactory is vulnerable to XXE; disable external entities",
        },
        // -- XSS --
        SastRule {
            name: "Java unescaped output in JSP",
            severity: "HIGH",
            pattern: Regex::new(r"<%=.*(?:request\.getParameter|request\.getAttribute)").unwrap(),
            extensions: &[".jsp", ".java"],
            description: "Unescaped request parameter in JSP output allows XSS",
        },
        // -- SSRF --
        SastRule {
            name: "Java SSRF (URL with user input)",
            severity: "HIGH",
            pattern: Regex::new(r"new\s+URL\s*\(.*(?:request|getParameter|input|user)").unwrap(),
            extensions: &[".java"],
            description: "URL constructed from user input may allow SSRF",
        },
        // -- Insecure crypto --
        SastRule {
            name: "Java weak cipher (DES/RC4)",
            severity: "HIGH",
            pattern: Regex::new(r#"Cipher\.getInstance\s*\(\s*['"](?:DES|RC4|RC2|Blowfish)"#).unwrap(),
            extensions: &[".java"],
            description: "DES/RC4/RC2/Blowfish are weak ciphers; use AES-256-GCM",
        },
        SastRule {
            name: "Java ECB cipher mode",
            severity: "MEDIUM",
            pattern: Regex::new(r#"Cipher\.getInstance\s*\(\s*['"]AES/ECB"#).unwrap(),
            extensions: &[".java"],
            description: "ECB mode does not provide semantic security; use CBC or GCM",
        },
        SastRule {
            name: "Java weak hash (MD5/SHA1)",
            severity: "MEDIUM",
            pattern: Regex::new(r#"MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-?1)['"]"#).unwrap(),
            extensions: &[".java"],
            description: "MD5/SHA1 are cryptographically weak; use SHA-256 or stronger",
        },
        SastRule {
            name: "Java insecure random (java.util.Random)",
            severity: "MEDIUM",
            pattern: Regex::new(r"new\s+Random\s*\(").unwrap(),
            extensions: &[".java"],
            description: "java.util.Random is predictable; use SecureRandom for security",
        },
        // -- Path traversal --
        SastRule {
            name: "Java path traversal (File with user input)",
            severity: "HIGH",
            pattern: Regex::new(r"new\s+File\s*\(.*(?:request|getParameter|input|user)").unwrap(),
            extensions: &[".java"],
            description: "File path from user input without validation allows path traversal",
        },
        // -- LDAP injection --
        SastRule {
            name: "Java LDAP injection",
            severity: "HIGH",
            pattern: Regex::new(r"(?:search|lookup)\s*\(.*(?:request|getParameter|input|user).*\+").unwrap(),
            extensions: &[".java"],
            description: "LDAP query built with user input may allow LDAP injection",
        },
        // -- Hardcoded secrets --
        SastRule {
            name: "Java hardcoded password",
            severity: "HIGH",
            pattern: Regex::new(r#"(?i)(?:password|passwd|secret|apikey)\s*=\s*"[^"]{4,}""#).unwrap(),
            extensions: &[".java"],
            description: "Password or secret appears hardcoded; use secure configuration",
        },
        // -- Misc Java --
        SastRule {
            name: "Java trust all certificates",
            severity: "HIGH",
            pattern: Regex::new(r"TrustAllCerts|X509TrustManager.*checkServerTrusted.*\{\s*\}|ALLOW_ALL_HOSTNAME_VERIFIER").unwrap(),
            extensions: &[".java"],
            description: "Trusting all certificates disables TLS verification",
        },
        SastRule {
            name: "Java Spring CSRF disabled",
            severity: "MEDIUM",
            pattern: Regex::new(r"csrf\(\)\.disable\(\)").unwrap(),
            extensions: &[".java"],
            description: "Disabling CSRF protection allows cross-site request forgery attacks",
        },
        SastRule {
            name: "Java unvalidated redirect",
            severity: "MEDIUM",
            pattern: Regex::new(r"response\.sendRedirect\s*\(.*(?:request|getParameter|input)").unwrap(),
            extensions: &[".java"],
            description: "Redirect with user-controlled URL may allow open redirect attacks",
        },
        SastRule {
            name: "Java Log injection",
            severity: "MEDIUM",
            pattern: Regex::new(r"(?:log|logger)\.(?:info|warn|error|debug)\s*\(.*(?:request\.getParameter|getHeader)").unwrap(),
            extensions: &[".java"],
            description: "Logging unsanitized user input may allow log injection/forging",
        },

        // ================================================================
        //  PHP
        // ================================================================

        SastRule {
            name: "PHP eval()",
            severity: "HIGH",
            pattern: Regex::new(r"\beval\s*\(").unwrap(),
            extensions: &[".php"],
            description: "eval() executes arbitrary PHP code and should be avoided",
        },
        SastRule {
            name: "PHP SQL injection (string concat)",
            severity: "HIGH",
            pattern: Regex::new(r#"(?:mysql_query|mysqli_query|pg_query)\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)"#).unwrap(),
            extensions: &[".php"],
            description: "SQL query with unsanitized superglobal; use prepared statements",
        },
        SastRule {
            name: "PHP system/exec/passthru",
            severity: "HIGH",
            pattern: Regex::new(r"\b(?:system|passthru|shell_exec|popen|proc_open)\s*\(").unwrap(),
            extensions: &[".php"],
            description: "Shell execution function may allow command injection",
        },
        SastRule {
            name: "PHP include with variable",
            severity: "HIGH",
            pattern: Regex::new(r"\b(?:include|require|include_once|require_once)\s*\(\s*\$").unwrap(),
            extensions: &[".php"],
            description: "Dynamic include with user-controlled path allows local/remote file inclusion",
        },
        SastRule {
            name: "PHP XSS (echo with superglobal)",
            severity: "HIGH",
            pattern: Regex::new(r"echo\s+.*\$_(?:GET|POST|REQUEST|COOKIE)").unwrap(),
            extensions: &[".php"],
            description: "Echoing unsanitized superglobal allows XSS; use htmlspecialchars()",
        },
        SastRule {
            name: "PHP extract() on user input",
            severity: "HIGH",
            pattern: Regex::new(r"extract\s*\(\s*\$_(?:GET|POST|REQUEST)").unwrap(),
            extensions: &[".php"],
            description: "extract() on superglobals can overwrite arbitrary variables",
        },
        SastRule {
            name: "PHP disable_functions bypass (preg_replace /e)",
            severity: "HIGH",
            pattern: Regex::new(r#"preg_replace\s*\(\s*['"]/.*/e"#).unwrap(),
            extensions: &[".php"],
            description: "preg_replace with /e modifier executes replacement as PHP code",
        },

        // ================================================================
        //  Ruby
        // ================================================================

        SastRule {
            name: "Ruby system/exec/backtick injection",
            severity: "HIGH",
            pattern: Regex::new(r"(?:system|exec|%x)\s*\(.*(?:params|request|input|user)").unwrap(),
            extensions: &[".rb"],
            description: "Shell execution with user input may allow command injection",
        },
        SastRule {
            name: "Ruby send with user input",
            severity: "HIGH",
            pattern: Regex::new(r"\.send\s*\(.*(?:params|request|input|user)").unwrap(),
            extensions: &[".rb"],
            description: "Dynamic method dispatch via send() with user input allows arbitrary method calls",
        },
        SastRule {
            name: "Ruby ERB render from user input",
            severity: "HIGH",
            pattern: Regex::new(r"ERB\.new\s*\(.*(?:params|request|input|user)").unwrap(),
            extensions: &[".rb"],
            description: "ERB template from user input allows server-side template injection",
        },
        SastRule {
            name: "Ruby YAML.load (unsafe)",
            severity: "HIGH",
            pattern: Regex::new(r"YAML\.load\s*\(").unwrap(),
            extensions: &[".rb"],
            description: "YAML.load can deserialize arbitrary objects; use YAML.safe_load",
        },
        SastRule {
            name: "Ruby Marshal.load (unsafe)",
            severity: "HIGH",
            pattern: Regex::new(r"Marshal\.load\s*\(").unwrap(),
            extensions: &[".rb"],
            description: "Marshal.load can execute arbitrary code from untrusted data",
        },
        SastRule {
            name: "Ruby mass assignment (permit!)",
            severity: "MEDIUM",
            pattern: Regex::new(r"\.permit!").unwrap(),
            extensions: &[".rb"],
            description: "permit! allows all parameters; use explicit permit(:field) instead",
        },
    ]
}

/// Run SAST (Static Application Security Testing) scan
pub fn sast_scan(repo: &Repository, ignore_dirs: &[String]) -> Result<(), git2::Error> {
    display::print_sub_header("Static Application Security Testing (SAST)");

    let head = repo.head()?.peel_to_tree()?;
    let rules = sast_rules();
    let skip_dirs = ["vendor/", "node_modules/", ".git/", "target/", "dist/", "build/"];

    let mut findings: Vec<(String, usize, &str, &str, &str)> = Vec::new(); // (file, line, name, severity, description)
    let mut files_scanned = 0usize;

    head.walk(TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() != Some(ObjectType::Blob) {
            return TreeWalkResult::Ok;
        }

        let path = format!("{}{}", dir, entry.name().unwrap_or(""));

        if skip_dirs.iter().any(|d| path.starts_with(d))
            || ignore_dirs.iter().any(|d| {
                let normalized = if d.ends_with('/') { d.clone() } else { format!("{d}/") };
                path.starts_with(&normalized)
            })
        {
            return TreeWalkResult::Ok;
        }

        // Skip test files
        if path.contains("_test.") || path.contains(".test.") || path.contains("/test/") || path.contains("/tests/") {
            return TreeWalkResult::Ok;
        }

        // Check if any rule applies to this file extension
        let any_applicable = rules.iter().any(|r| {
            r.extensions.iter().any(|ext| path.ends_with(ext))
        });
        if !any_applicable {
            return TreeWalkResult::Ok;
        }

        files_scanned += 1;

        if let Ok(blob) = repo.find_blob(entry.id()) {
            if let Ok(content) = std::str::from_utf8(blob.content()) {
                for (line_num, line) in content.lines().enumerate() {
                    // Skip comments
                    let trimmed = line.trim();
                    if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                        continue;
                    }

                    for rule in &rules {
                        if !rule.extensions.iter().any(|ext| path.ends_with(ext)) {
                            continue;
                        }
                        if rule.pattern.is_match(line) {
                            // yaml.load is safe when SafeLoader is specified
                            if rule.name.contains("yaml.load") && line.contains("SafeLoader") {
                                continue;
                            }
                            findings.push((
                                path.clone(),
                                line_num + 1,
                                rule.name,
                                rule.severity,
                                rule.description,
                            ));
                        }
                    }
                }
            }
        }

        TreeWalkResult::Ok
    })?;

    // Summary
    display::print_summary_stat("Files scanned", &files_scanned.to_string());

    if findings.is_empty() {
        display::print_ok("No SAST issues detected");
        return Ok(());
    }

    // Count by severity
    let high = findings.iter().filter(|f| f.3 == "HIGH").count();
    let medium = findings.iter().filter(|f| f.3 == "MEDIUM").count();
    let info = findings.iter().filter(|f| f.3 == "INFO").count();

    display::out("");
    display::print_summary_stat("Total findings", &findings.len().to_string());
    if high > 0 {
        display::print_warning(&format!("{high} HIGH severity issues"));
    }
    if medium > 0 {
        display::out(&format!("    \x1b[33m⚠  {medium} MEDIUM severity issues\x1b[0m"));
    }
    if info > 0 {
        display::print_info(&format!("{info} INFO severity issues"));
    }

    // Show findings grouped by severity
    display::out("");
    if high > 0 {
        display::out("    \x1b[1;31mHIGH Severity:\x1b[0m");
        let rows: Vec<Vec<String>> = findings
            .iter()
            .filter(|f| f.3 == "HIGH")
            .take(20)
            .map(|(file, line, name, _, _)| {
                vec![file.clone(), format!("L{line}"), name.to_string()]
            })
            .collect();
        display::print_table(&["File", "Line", "Issue"], &rows);
    }

    if medium > 0 {
        display::out("");
        display::out("    \x1b[1;33mMEDIUM Severity:\x1b[0m");
        let rows: Vec<Vec<String>> = findings
            .iter()
            .filter(|f| f.3 == "MEDIUM")
            .take(20)
            .map(|(file, line, name, _, _)| {
                vec![file.clone(), format!("L{line}"), name.to_string()]
            })
            .collect();
        display::print_table(&["File", "Line", "Issue"], &rows);
    }

    if info > 0 {
        display::out("");
        display::out("    \x1b[1;36mINFO:\x1b[0m");
        let rows: Vec<Vec<String>> = findings
            .iter()
            .filter(|f| f.3 == "INFO")
            .take(20)
            .map(|(file, line, name, _, _)| {
                vec![file.clone(), format!("L{line}"), name.to_string()]
            })
            .collect();
        display::print_table(&["File", "Line", "Issue"], &rows);
    }

    Ok(())
}
