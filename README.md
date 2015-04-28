# cordova-mifare

Cordova Plugin for the MIFARE SDK.   
Support for the NFC tags NTAG210 family from NXP.   

## Functions
- init(options)   
options = { "password": password }  

## Events
- onTagDetected -> { byte[] tagUID, String tagName, byte[] payload }
- onTagError -> { String nfcType, Integer nfcCode, String nfcMessage }




