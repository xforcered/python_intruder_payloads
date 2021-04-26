# Python Intruder Payloads
This extension allows users to specify arbitrary Python2 scripts to generate or process Burp Intruder payloads.

CAUTION: Since these scripts run arbitrary code, take caution when running any script you don't trust.

# Usage
To load into Burp, click on the Extender tab, click "Add", select "Python" as the type of extension, and then specify the path to `python_intruder_payloads.py`.

Once the script is loaded, Burp will have a new tab labeled `Python Payloads`. Click on it and write or paste your script in the box labeled `Intruder Payload Generator` to control how payloads will be generated, or `Intruder Payload Processor` to change how a set of existing payloads will be processed before use in Intruder attacks.

Once the script is written into the appropriate box, you can select `Extension-generated` under `Payload type` in any Intruder attack to use your payload generation script, or select `Invoke Burp extension` and select processor `Python Intruder Payloads` to use your payload processing script.

# Writing generator scripts
When writing generator scripts, your script should place any generated payloads to use in `payloads` as a list of strings.

This generator script generates the numbers 1-10 using `range()`, converts them to strings using `map()`, and stores the result in `payloads`, which Burp will then use as the generated payloads:
```
payloads = map(str, range(10))
```

# Writing processor scripts

When writing processing scripts:
* Burp Extender [helpers](https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html) and [callbacks](https://portswigger.net/burp/extender/api/burp/IBurpExtenderCallbacks.html) are available to you via `_helpers`, and callbacks via `_callbacks`.
* `base_value` is the value from the original request where the insertion point was specified
* `original_payload` contains the payload without any processing applied
* `current_payload` contains the payload after any processing that has already been performed
* Your script should place the processed payload in `payload` as a string

This processor script takes the unprocessed payload, reverses the order of the characters, and stores the result in `payload`, which Burp will then use as the processed payload:
```
payload = current_payload[::-1]
```
