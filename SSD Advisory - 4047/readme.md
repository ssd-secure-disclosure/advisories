# SSD Advisory - Synology DSM Remote Command Injection

## Introduction

Network-attached storage devices allow multiple users and heterogeneous client devices to retrieve data from centralized disk capacity. These NAS stations are a must for secured file sharing and thus becoming a popular target for hacking attempts. Read below on how a fellow researcher working with our team demonstrated getting access via Authenticated Remote Command into a Synology's DiskStation Manager.
Remote Command Injection and others will be discussed at <a href="https://typhooncon.com/">TyphoonCon</a>, the best All Offensive Security Conference in Asia which will take place from June 15th to June 19th 2020, in Seoul, Korea. <a href="https://www.eventbrite.com/e/typhooncon-2020-tickets-74930127027">Reserve your spot</a> for TyphoonCon and register to <a href="https://typhooncon.com/typhooncon-2019/typhoonpwn/">TyphoonPwn</a> for your chance to win up to 500K USD in prizes in our hacking challenges.

## Vulnerability Summary
The following advisory describes an Authenticated Remote Command Injection in Synology's DiskStation Manager.

## Credit
An independent Security Researcher has reported this vulnerability to SSD Secure Disclosure program.

## Affected Systems
Synology DSM version 6.2.2 before update 24922

## Vendor Response
Synology has fixed the vulnerability in DSM version 6.2.2-24922. For more information see <a href="https://www.synology.com/en-global/security/advisory/Synology_SA_19_37" target="_blank" rel="noopener noreferrer">Synology-SA-19:37 DSM</a>.

## Vulnerability Details
This vulnerability is similar to CVE-2017-12075, which was fixed in DSM 6.2-23739.

When setting PPPoE network in EZ-Internet, a username and password pair is required for authentication and is saved in _/etc/ppp/pppoe.conf_.
The following code snippet exists in Synology's DSM 6.2-23739:
``` c
// PPPoEConfigSet() in /usr/lib/libsynonetsdk.so.6
__int64 __fastcall PPPoEConfigSet(...)
{
  // ... 
  v46 = SLIBCFileSetKeyValue("/etc/ppp/pppoe.conf", "ETH", &amp;a7, "%s=%s\n");
  v47 = "/etc/ppp/pppoe.conf";
  v48 = 257LL;
  if ( v46 &lt; 0 )
    goto LABEL_17;
  v49 = "no";
  if ( a46 )
    v49 = "yes";
  v50 = SLIBCFileSetKeyValue("/etc/ppp/pppoe.conf", "DEFAULTROUTE", v49, "%s=%s\n");
  v47 = "/etc/ppp/pppoe.conf";
  v48 = 262LL;
  if ( v50 &lt; 0 )
    goto LABEL_17;
  v51 = &amp;a7;
  v73[0] = '\'';
  v52 = 1;
  while ( 1 )			// fix for CVE-2017-12075: wrap username with ''
  {
    v53 = *((_BYTE *)v51 + 16);
    v54 = v52 + 1;
    if ( !v53 )
      break;
    if ( v53 == '\'' )
    {
      if ( v52 &gt; 505 )
        break;
      v73[v52] = '\'';
      v73[v54] = '"';
      v73[v52 + 2] = '\'';
      v55 = v52 + 3;
      v52 += 4;
      v73[v55] = '"';
      v73[v52] = '\'';
    }
    else
    {
      if ( v52 &gt; 509 )
        break;
      v73[v52] = v53;
    }
    ++v52;
    v51 = (int *)((char *)v51 + 1);
  }
  v73[v52] = '\'';
  v73[v54] = 0;                   
  if ( SLIBCFileSetKeyValue("/etc/ppp/pppoe.conf", "USER", v73, "%s=%s\n") &lt; 0 )
  {
   // ...
  }
  // !!! MTU parameter still suffers from the same issue
  if ( SLIBCFileSetKeyValue("/etc/ppp/pppoe.conf", "MTU", &amp;a45, "%s=%s\n") &lt; 0 )
  {
    // ...
  }
  //...
}
```

As we can see, the username is wrapped with single quotes to fix CVE-2017-12075. In addition, there are some other parameters which will be saved in _/etc/ppp/pppoe.conf_ such as the MTU.

In the function _syno::network::PPPoEInterface::SetData()_, there exists a check against the parameters before the call to _syno::network::PPPoEInterface::Apply()_. These parameters are obtained directly from the HTTP request which is controlled by the user, including the username and mtu_config. It should be noted that the length of mtu_config is limited to less than 8 characters.

``` c
// syno::network::PPPoEInterface::Check() in /usr/lib/libwebapi-Network-Share.so 
signed __int64 __fastcall syno::network::PPPoEInterface::Check(__int64 a1, Json::Value *a2)
{
  // ...
  v2 = a1;
  if ( (unsigned __int8)Json::Value::isMember(a2, "ifname") )
  {
    Json::Value::operator[](a2, "ifname");
    Json::Value::asString((Json::Value *)&amp;v20);
    v3 = std::string::compare((std::string *)&amp;v20, "pppoe");
    // ...
    if ( v3 )
    {
      v17 = (Json::Value *)Json::Value::operator[](a2, "ifname");
      v18 = Json::Value::asCString(v17);
      syslog(3, "%s:%d Incorrect ifname [%s]", "pppoe_interface.cpp", 412LL, v18);
      result = 0xFFFFFFFFLL;
    }
    else
    {
      if ( (unsigned __int8)Json::Value::isMember(a2, "real_ifname") )
      {
        v12 = (Json::Value *)Json::Value::operator[](a2, "real_ifname");
        v13 = Json::Value::asCString(v12);
        snprintf((char *)(v2 + 396), 0x10uLL, "%s", v13);
      }
      else
      {
        snprintf((char *)(v2 + 396), 0x10uLL, "%s", v2 + 64);
      }
      if ( (unsigned __int8)Json::Value::isMember(a2, "username") )
      {
        v5 = (Json::Value *)Json::Value::operator[](a2, "username");
        v6 = Json::Value::asCString(v5);
        snprintf((char *)(v2 + 412), 0x100uLL, "%s", v6);
      }
      else
      {
        snprintf((char *)(v2 + 412), 0x100uLL, "%s", v2 + 80);
      }
      if ( (unsigned __int8)Json::Value::isMember(a2, "password") )
      {
        v7 = (Json::Value *)Json::Value::operator[](a2, "password");
        v8 = Json::Value::asCString(v7);
        snprintf((char *)(v2 + 668), 0x20uLL, "%s", v8);
      }
      else
      {
        snprintf((char *)(v2 + 668), 0x20uLL, "%s", v2 + 336);
      }
      if ( (unsigned __int8)Json::Value::isMember(a2, "mtu_config") )
      {
        v9 = (Json::Value *)Json::Value::operator[](a2, "mtu_config");
        v10 = Json::Value::asCString(v9);
        snprintf((char *)(v2 + 700), 8uLL, "%s", v10);  // !!! length is limited
      }
      else
      {
        snprintf((char *)(v2 + 700), 8uLL, "%s", v2 + 368);
      }
      if ( (unsigned __int8)Json::Value::isMember(a2, "is_default_gateway") )
      {
        v14 = (Json::Value *)Json::Value::operator[](a2, "is_default_gateway");
        *(_DWORD *)(v2 + 708) = (unsigned __int8)Json::Value::asBool(v14);
        result = 0LL;
      }
      else
      {
        *(_DWORD *)(v2 + 708) = *(_DWORD *)(v2 + 376);
        result = 0LL;
      }
    }
  }
  else
  {
    syslog(3, aSDNo, "pppoe_interface.cpp", 407LL);
    result = 0xFFFFFFFFLL;
  }
  return result;
}
```

Then in the shell script _/usr/sbin/pppoe-start_ the file _/etc/ppp/pppoe.conf_ will be executed in the shell environment.

``` shell
# content from /etc/ppp/pppoe.conf

# Ethernet card connected to DSL modem                                 
ETH=eth0                                                               
                                                                       
# PPPoE user name.                                
USER='test'

# ...

MTU=`id&gt;aa`    # corresponding to the poc.py
```

``` shell
# content from the /usr/sbin/pppoe-start script
CONFIG=/etc/ppp/pppoe.conf
USER=""
ETH=""
ME=`basename $0`

# ...

export CONFIG
. $CONFIG	# execute here
```

As we can see, the injected command through the MTU parameter will be executed thus causing the vulnerability, but it is still limited by the length of the parameter.

Note: To exploit this vulnerability the user has to be authenticated and in order to access the EZ-Internet functionality he has to be in the administration group
