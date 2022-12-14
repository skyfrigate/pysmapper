# pysmapper
Pysmapper is a simple command-line tool to map the available ciphers of a host. It can be used to check whether the ssl
is valid on a specific host.
## The command line tool
### Command line options
Here are the command line option and descritption
#### -v | --verbose
Défini si la commande doit afficher les résultats de manière facilement lisible
#### -i | --input
An option that describe a path to file a file which will be used to indicate hosts. The file must list the addresses
separated by carriage return. Addresses can be IPv4 addresses, IPv6 addresses or domain names. The path can be a standard os path,a http\
https URL, a ftp/ftps URL, a file URL or a data URL
#### -p | --port
An option that describe a specific port to check the ciphers on, by default it is set to 443 which is the HTTPS tcp port
#### -mp | --module_path
Define a specific path to the module path containing the program config, by default it will look in its current directory
#### -u | --update
Define a path to a python file update in aim to update the SSL/TLS cipher list for new versions
#### -h | --help
Give the help menu of the command line tool
#### -f | --format
Define a special format for the output, if the format is not handled format output will be csv.
There is 3 native format supported, the verbose, the csv and the openmetrics sorted by address which can be called by
passing argument `-f openmetrics-by-address` or `--format openmetrics-by-address`. 
#### -ount | --on-unsecure-text
Default text to be displayed and sent to the text handler if an unsecure cipher is detected. If not specified the
character sent is `u`.
#### -oat | --on-accepted-text
Default text to be sent to the text handler if the cipher is accepted. If not specified the character is `y`
#### -pd | --port-detection
Enable the port detection on the program. So the program will try to find port using TLS/SSL. If -port is present -pd is
ignored. Using -pd might make the program run slower as it will try to establish 11 tcp connection at each try. It will
stop his research at the first available port found.
#### -ounc | --on_unsecure_callback
Define a programm to be called if an unsecrured cipher is found, it must describe the entire command line to execute
#### -uor | --unsecure-on-refused
A boolean argument that describe if an unsecure process should be called on refused ciphers
### Updating pysmapper
To update psymapper you need to execute `pysmapper.py --update <config file>` where config file is a path to a python.
It is the same as describe just above. However, the python update file need some specific element to work well.
### The program output
#### The output format
Pysmapper natively support some format such as:
* csv
* XML
* JSON
* OpenMetrics
* A verbose output
You can specify the output format through the `-f` options and specifying the name of the format in lowercase
#### The output parameter
To have a more flexible output and to not mix up with common argument you can give specific argument to the text 
formatter by following a simple pattern in the `-f` options.
The pattern is the following :
`-f <output format>-by-<sorting>#<key-value parameter linked by a "=" and separated by a "," >`
An example would look like this :
`pysmapper -f openmetrics-by-address#name=data&type=info`
#### The output media
Pysmapper will natively allow you to select an output media for different uses. it can be a regular directory, an http 
or ftp URL.
You just have to specify the URL at the `-o` as for a regular directory
> The mimetype will be automatically selected for a http request

If no `-o` option is selected, the output will be the standard one
## Building over pysmapper
You can also use pysmapper as a simple library which allows you to reuse object and override methods to have a specific
of the program internal process. Arguments to text formatter are given as described above.
## Text format specification
Each text-formatter has its own specific description as they have different behavior. The specification of the native 
text formatter are described below
### OpenMetrics formatter
The OpenMetrics text formatter allow you to have an output in the OpenMetrics format.
It writes an output using info type. Natively, it will create a new family for each new address, and will give different
in the following pattern :<br>
``` <address>_info {protocol-version=<proto_name>, name=<addr>, cipher=<name of the cipher>,status=<status of the cipher>}```
#### OpenMetrics formatter parameters
- `one-family` : describe whether the formatter should use only one family for the whole analysis, by default the name 
will be `cipher_scan_info`
- `custom-name` : describe a custom name for the unique family. It needs to be with a one-family parameter
- `name` : specifies a specific name for the output filename
#### Sorting possibilities
OpenMetrics text formatter only support a sorting by address, and it must be specified
### XML formatter
The XML formatter allow you to have an output in the XML format. By default, it will follow a tree like this :
```xml
<?xml version="1.0" encoding="utf-8" ?>
<result>
    <protocol name="<name of the protocol>">
        <address name="<address of the target" port="<port number>">
            <cipher name="name of the cipher" status="<status of the cipher>" unsecure="<whether the cipher is secured or not>"/>
        </address>
    </protocol>
    <protocol>
        ...
    </protocol>
    ...
</result>
```