/**
Copyright 2015 Frosty Elk AB

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */
/* jshint -W117 */
var exec = require('cordova/exec');

var mifareExport = {};

/**
* options = {
*   "password": password for NFC tag read operations
* }
*/
mifareExport.init = function (options, successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifarePlugin', 'init',[options]);
};

/**
* Write Tag data.
* data = {
* 	"payload": byte[]
* }
*
*/
mifareExport.writeTag = function (data, successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifarePlugin', 'writeTag',[data]);
};


module.exports = mifareExport;