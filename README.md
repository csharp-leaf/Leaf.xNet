[![Git Releases Version](https://img.shields.io/github/release/csharp-leaf/Leaf.xNet.svg)](https://github.com/csharp-leaf/Leaf.xNet/releases)
[![NuGet version](https://badge.fury.io/nu/Leaf.xNet.svg)](https://badge.fury.io/nu/Leaf.xNet)
[![Build status](https://ci.appveyor.com/api/projects/status/em4aje36etb63kdt/branch/master?svg=true)](https://ci.appveyor.com/project/grandsilence/leaf-xnet/branch/master)
[![Last Release](https://img.shields.io/github/release-date/csharp-leaf/Leaf.xNet.svg?logo=Leaf.xNet)](https://github.com/csharp-leaf/Leaf.xNet/releases)
[![Nuget installs](https://img.shields.io/nuget/dt/Leaf.xNet.svg)](https://www.nuget.org/packages/Leaf.xNet/)  


# Leaf.xNet
**Leaf.xNet** - provides HTTP/HTTPS, Socks 4A, Socks 4, Socks 5.  
It's a based on [Extreme.Net](https://github.com/Fedorus/Extreme.Net). And original library [xNet](https://github.com/X-rus/xNet).  
Usage same like original xNet.

## Gratitudes
- **Artem** (devspec) - donation support. Thank you
- **Igor' Vasilyev** - found many bugs and reported it. Thank you
- **Monaco** (BHF) - bug reporter, donations help
- **Wizard** - donation support
- **@azor83** - donation for implementation of MiddleHeaders
- **TMT** - donation for PATCH, DELETE, PUT, OPTIONS methods

## Contributors
- **[guzlewski](https://github.com/guzlewski)**: Randomizer fixes, IgnoreInvalidCookies

[Make a donation to the development of the library](#donate)

## Contacts
**Telegram**: [@kelog](https://t.me/kelog)  
**E-Mail**: mixtape774@gmail.com

# Installation via [NuGet](https://www.nuget.org/)
```
Install-Package Leaf.xNet
```

# Features
### HTTP Methods
- GET
- POST
- PATCH
- DELETE
- PUT
- OPTIONS

### Cloudflare bypass (obsolete)

> Not maintained in public Leaf.xNet anymore.  
  But you can [order private paid Leaf.xNet with support](https://t.me/kelog).  
  Telegram: [@kelog](https://t.me/kelog)
    
See demo project in the Examples folder.

```csharp
using Leaf.xNet.Services.Cloudflare;

// Check and pass CloudFlare JS Challange if it's present
// Attention: It's working when Re-Captcha enabled
var httpRequest = new HttpRequest();
var clearResp = httpRequest.GetThroughCloudflare("https://...");

// Check only (without solution)
var resp = httpRequest.Get("https://...");
bool isCloudFlared = resp.isCloudFlared();
```

#### CloudFlare bypass when ReCaptcha required
See demo project in the Examples folder.
```csharp
using Leaf.xNet.Services.Captcha;

// You can use: RucaptchaSolver | TwoCaptchaSolver | CapmonsterSolver
http.CaptchaSolver = new RucaptchaSolver {
    ApiKey = "your_key",
	
	// If you need to use Proxy (Recaptcha for example) - uncomment the line below
	// Proxy = new CaptchaProxy(CaptchaProxyType.HTTPS, "80.81.82.83:8080"),
	// // ProxyTypes: CaptchaProxyType.HTTP || HTTPS || SOCKS4 || SOCKS5
};
var clearResp = httpRequest.GetThroughCloudflare("https://...");
```

### Keep temporary headers (when redirected)
It's enabled by default. But you can disable this behavior:
```csharp
httpRequest.KeepTemporaryHeadersOnRedirect = false;
httpRequest.AddHeader(HttpHeader.Referer, "https://google.com");
httpRequest.Get("http://google.com").None();
// After redirection to www.google.com - request won't have Referer header because KeepTemporaryHeadersOnRedirect = false
```

### Middle response headers (when redirected)
```csharp
httpRequest.EnableMiddleHeaders = true;

// This requrest has a lot of redirects
var resp = httpRequest.Get("https://account.sonyentertainmentnetwork.com/");
var md = resp.MiddleHeaders;
```

### Cross Domain Cookies
Used native cookie storage from .NET with domain shared access support.  
Cookies enabled by default. If you wait to disable parsing it use:
```csharp
HttpRequest.UseCookies = false;
```
Cookies now escaping values. If you wait to disable it use:
```csharp
HttpRequest.Cookies.EscapeValuesOnReceive = false;

// UnescapeValuesOnSend by default = EscapeValuesOnReceive
// so set if to false isn't necessary
HttpRequest.Cookies.UnescapeValuesOnSend = false;
```

### Select SSL Protocols (downgrade when required)
```csharp
// By Default (SSL 2 & 3 not used)
httpRequest.SslProtocols = SslProtocols.Tls | SslProtocols.Tls12 | SslProtocols.Tls11;
```

### My HTTPS proxy returns bad response
Sometimes HTTPS proxy require relative address instead of absolute.
This behavior can be changed:
```csharp
http.Proxy.AbsoluteUriInStartingLine = false;
```

### Modern User-Agent Randomization
UserAgents were updated in January 2019.
```csharp
httpRequest.UserAgentRandomize();
// Call it again if you want change it again

// or set property
httpRequest.UserAgent = Http.RandomUserAgent();
```
When you need a specific browser just use the `Http` class same way:
- `ChromeUserAgent()`
- `FirefoxUserAgent()`
- `IEUserAgent()`
- `OperaUserAgent()`
- `OperaMiniUserAgent()`

## Cyrilic and Unicode Form parameters
```csharp
var urlParams = new RequestParams {
    { ["привет"] = "мир"  },
    { ["param2"] = "val2" }
}
// Or
// urlParams["привет"] = "мир";
// urlParams["param2"] = "val2";

string content = request.Post("https://google.com", urlParams).ToString();
```

## A lot of Substring functions
```csharp
string title = html.Substring("<title>", "</title>");

// substring or default
string titleWithDefault  = html.Substring("<title>", "</title>") ?? "Nothing";
string titleWithDefault2 = html.Substring("<title>", "</title>", fallback: "Nothing");

// substring or empty
string titleOrEmpty  = html.SubstringOrEmpty("<title>", "</title>");
string titleOrEmpty2 = html.Substring("<title>", "</title>") ?? ""; // "" or string.Empty
string titleOrEmpty3 = html.Substring("<title>", "</title>", fallback: string.Empty);

// substring or thrown exception when not found
// it will throw new SubstringException with left and right arguments in the message
string titleOrException  = html.SubstringEx("<title>", "</title>");
// when you need your own Exception
string titleOrException2 = html.Substring("<title>", "</title>")
    ?? throw MyCustomException();


```

# How to:
### Get started
Add in the beggining of file.
```csharp
using Leaf.xNet;
```
And use one of this code templates:

```csharp
using (var request = new HttpRequest()) {
    // Do something
}

// Or
HttpRequest request = null;
try {
    request = new HttpRequest();
    // Do something 
}
catch (HttpException ex) {
    // Http error handling
    // You can use ex.Status or ex.HttpStatusCode for more details.
}
catch (Exception ex) {
	// Unhandled exceptions
}
finally {
    // Cleanup in the end if initialized
    request?.Dispose();
}

```

### Send multipart requests with fields and files
Methods `AddField()` and `AddFile()` has been removed (unstable).
Use this code:
```csharp
var multipartContent = new MultipartContent()
{
    {new StringContent("Harry Potter"), "login"},
    {new StringContent("Crucio"), "password"},
    {new FileContent(@"C:\hp.rar"), "file1", "hp.rar"}
};

// When response isn't required
request.Post("https://google.com", multipartContent).None();

// Or
var resp = request.Post("https://google.com", multipartContent);
// And then read as string
string respStr = resp.ToString();
```

### Get page source (response body) and find a value between strings
```csharp
string html = request.Get("https://google.com").ToString();
string title = html.Substring("<title>", "</title>");
```

### Get response headers
```csharp
var httpResponse = httpRequest.Get("https://yoursever.com");
string responseHeader = httpResponse["X-User-Authentication-Token"];
```

### Download a file
```csharp
var resp = request.Get("http://google.com/file.zip");
resp.ToFile("C:\\myDownloadedFile.zip");
```

### Get Cookies
```csharp
string response = request.Get("https://twitter.com/login").ToString();
var cookies = request.Cookies.GetCookies("https://twitter.com");
foreach (Cookie cookie in cookies) {
    // concat your string or do what you want
    Console.WriteLine($"{cookie.Name}: {cookie.Value}");
}
```

### Proxy
Supporting proxy string templates:
```
[ip]:[port]    //e.g., http://127.0.0.1:80
[ip]:[port]:[login]:[pass]     //e.g., http://127.0.0.1:80:login:pass
[login]:[pass]@[ip]:[port]     //e.g., http://login:pass@127.0.0.1:80

```


Your proxy server:
```csharp
// Type: HTTP / HTTPS 
httpRequest.Proxy = HttpProxyClient.Parse("127.0.0.1:8080");
// Type: Socks4
httpRequest.Proxy = Socks4ProxyClient.Parse("127.0.0.1:9000");
// Type: Socks4a
httpRequest.Proxy = Socks4aProxyClient.Parse("127.0.0.1:9000");
// Type: Socks5
httpRequest.Proxy = Socks5ProxyClient.Parse("127.0.0.1:9000");

```

Debug proxy server (Charles / Fiddler):
```csharp
// HTTP / HTTPS (by default is HttpProxyClient at 127.0.0.1:8888)
httpRequest.Proxy = ProxyClient.DebugHttpProxy;

// Socks5 (by default is Socks5ProxyClient at 127.0.0.1:8889)
httpRequest.Proxy = ProxyClient.DebugSocksProxy;
```

### Add a Cookie to HttpRequest.Cookies storage
```csharp
request.Cookies.Set(string name, string value, string domain, string path = "/");

// or
var cookie = new Cookie(string name, string value, string domain, string path);
request.Cookies.Set(cookie);
```

# Donate
If this project help you reduce time to develop, you can give me a cup of coffee :)  

[at BuyMeACoffee.com](https://www.buymeacoffee.com/grandsilence)

**PayPal**: `grand.silence@mail.ru`

[**Via web-payment**: WebMoney | Steam Item | MasterCard | Visa | Sberbank.Online | Bitcoin ](https://www.digiseller.market/asp2/pay_options.asp?id_d=2582260)
[![Imgur](https://i.imgur.com/APbu91c.png)](https://www.digiseller.market/asp2/pay_options.asp?id_d=2582260)

### Wallets
**Yandex**.Money | **Яндекс**.Деньги: `410011037924983`  
**Webmoney**: `Z349403749504` | `U313788999957` | `E894184114651` | `X428336365219`  
Bitcoin **BTC**: `3MTuJDRK9RcSQURsvJysqg1gp91FFTDSs7`  
Bitcoin Gold **BTG**: `Abf3jmLwiYw6ewuwMgu4AeHw4a8WVZUySH`  
LiteCoin **LTC**: `M8rkfHAB62NyvAPkaZUG4GeQB5DPvts4xD`  
LiteCoin **LTC** (alternate): `32ecMPkD8uXZ7f7rUgUvEdPzrNcx21J5po`  

# TODO:
- Implement [Captcha Services](https://github.com/openbullet/openbullet/tree/master/RuriLib/CaptchaServices)
- Move `HttpResponse` indexer to `Headers` property and implement IEnumerable for it
- Implement new property `StoreResponseCookies` for `HttpRequest`: `HttpResponse` should have `Cookies` as `IReadOnlyKeyValueCollection<string,Cookie>` with indexer.
