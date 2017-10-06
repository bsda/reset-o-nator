# RESET-O-NATOR

Not really useful to anyone out of the box as it's customized to internal apis.


Original use of the script was to reset passwords of accounts compromised during Credential Stuffing attack
Splunk detects compromised account and sends SQS notification to AWS.
Script monitors SQS queue and performs reset actions based on content of message.



## Message Format Expected
The body of the SQS message needs to contain a JSON field called "message" with the following:

```
{"email": "email", "userid": site2-userid, "compromised_on": "sitename"}
```


daemon.py cloned from somewhere I can't remember :-()
