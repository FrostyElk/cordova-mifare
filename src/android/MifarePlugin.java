/**
 * Copyright (C) 2015 Frosty Elk AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.frostyelk.cordova.mifare;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import com.nxp.nfclib.exceptions.SmartCardException;
import com.nxp.nfclib.ntag.NTag210;
import com.nxp.nfclib.ntag.NTag213215216;
import com.nxp.nfclib.ntag.NTag213F216F;
import com.nxp.nfclib.utils.NxpLogUtils;
import com.nxp.nfclib.utils.Utilities;
import com.nxp.nfcliblite.Interface.NxpNfcLibLite;
import com.nxp.nfcliblite.Interface.Nxpnfcliblitecallback;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.apache.cordova.PluginResult.Status;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

/**
 * This class represents the native implementation for the MIFARE Cordova plugin.
 */
public class MifarePlugin extends CordovaPlugin {

    private static final String LOGTAG = "MifarePlugin";
    private static final String ACTION_INIT = "init";
    private static final String TAG_EVENT_DETECTED = "onTagDetected";
    private static final int NTAG216_MEMORY_PAGES = 221;


    private static String TAG = "MifarePLugin";

    private String password;
    private byte[] payload;

    private void sendEventToWebView(String eventName, JSONObject jsonData) {
        final String url = "javascript:cordova.fireDocumentEvent('" + eventName + "', " + jsonData.toString() + ");";
        NxpLogUtils.i(LOGTAG, "sendEventToWebView: " + url);

        if (webView != null) {
            webView.post(new Runnable() {

                @Override
                public void run() {
                    webView.loadUrl(url);
                }
            });
        } else {
            NxpLogUtils.w(TAG, "sendEventToWebView() without a vebview active.");
        }
    }

    @Override
    public void pluginInitialize() {
        super.pluginInitialize();

        // Get and set the lib Singleton instance
        NxpNfcLibLite.getInstance().registerActivity(cordova.getActivity());


        // The default for NfcLogUtils logging is off, turn it on
        NxpLogUtils.enableLog();
        NxpLogUtils.i(LOGTAG, "MIFARE Cordova plugin pluginInitialize");
    }

    @Override
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        NxpLogUtils.i(TAG, "onNewIntent Intent: " + intent.toString());
        NxpLogUtils.i(TAG, "onNewIntent Action: " + intent.getAction());

        Tag tagInfo = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        NxpLogUtils.i(TAG, "Tag info: " + tagInfo.toString());

        Nxpnfcliblitecallback callback = new Nxpnfcliblitecallback() {
            @Override
            public void onNTag210CardDetected(NTag210 nTag210) {
                NxpLogUtils.i(TAG, "Found a NTag210 Card!");
                handleCardDetected(nTag210);
            }

            @Override
            public void onNTag213215216CardDetected(NTag213215216 nTag213215216) {
                NxpLogUtils.i(TAG, "Found a NTag213215216 Card!");
                handleCardDetected(nTag213215216);
            }

            @Override
            public void onNTag213F216FCardDetected(NTag213F216F nTag213F216F) {
                NxpLogUtils.i(TAG, "Found a NTag213F216F Card!");
                handleCardDetected(nTag213F216F);
            }
        };

        NxpNfcLibLite.getInstance().filterIntent(intent, callback);
    }

    /**
     *
     * @param nTag210 The tag
     */
    private void handleCardDetected(NTag210 nTag210) {

        byte pack[] = {0, 0};
        byte pw[] = password.getBytes();
        NxpLogUtils.i(TAG, "Sent Pw[]: " + Utilities.dumpBytes(pw));

        try {

            nTag210.connect();
            NxpLogUtils.i(TAG, "Connect successful!");

            nTag210.authenticatePwd(pw, pack);
            NxpLogUtils.i(TAG, "Authenticate successful!");

            payload = nTag210.fastRead(0, NTAG216_MEMORY_PAGES);
            NxpLogUtils.i(TAG, "Payload read: " + Utilities.dumpBytes(payload));

            JSONObject result = new JSONObject();
            JSONArray payloadArray;
            try {
                payloadArray = new JSONArray(payload);
                result.put("payload", payloadArray);
                sendEventToWebView(TAG_EVENT_DETECTED, result);
            } catch (JSONException e) {
                NxpLogUtils.v(TAG, "JSONException: " + e.getMessage());
            }

        } catch (SmartCardException e) {
            NxpLogUtils.v(TAG, "SmartCardException: " + e.getMessage());
        } catch (IOException e) {
            NxpLogUtils.v(TAG, "IOException" + e.getMessage());
        }
    }


    @Override
    public void onDestroy() {
        super.onDestroy();
        NxpLogUtils.i(LOGTAG, "onDestroy");
    }

    @Override
    public void onPause(boolean multitasking) {
        super.onPause(multitasking);
        // TODO: How do we activate background scans?
//        NxpNfcLibLite.getInstance().stopForeGroundDispatch();
        NxpLogUtils.i(LOGTAG, "onPause");
    }

    @Override
    public void onResume(boolean multitasking) {
        super.onResume(multitasking);
        NxpNfcLibLite.getInstance().startForeGroundDispatch();
        NxpLogUtils.i(LOGTAG, "onResume");
    }

    /**
     * This is the main method for the MIFARE Plugin. All API calls go through
     * here. This method determines the action, and executes the appropriate
     * call.
     *
     * @param action          The action that the plugin should execute.
     * @param args            The input parameters for the action.
     * @param callbackContext The callback context.
     * @return A PluginResult representing the result of the provided action. A
     * status of INVALID_ACTION is returned if the action is not
     * recognized.
     */
    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        PluginResult result;

        NxpLogUtils.enableLog();
        NxpLogUtils.i(LOGTAG, "MIFARE Cordova plugin execute");

        if (ACTION_INIT.equals(action)) {
            result = init(args.getJSONObject(0), callbackContext);
        } else {
            result = new PluginResult(Status.INVALID_ACTION);
        }

        if (result != null) {
            callbackContext.sendPluginResult(result);
        }

        return true;
    }

    /**
     * Initialize the plugin with options
     * @param options Options {password: tag password}
     * @param callbackContext Callback
     * @return PluginResult
     */
    private PluginResult init(final JSONObject options, final CallbackContext callbackContext) {
        // Start the dispatch here, Cordova will not send onResume at first start
        NxpNfcLibLite.getInstance().startForeGroundDispatch();

        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                NxpLogUtils.i(LOGTAG, "init: " + options.toString());
                try {
                    password = options.getString("password");
                } catch (JSONException e) {
                    NxpLogUtils.w(TAG, e.getMessage());
                    callbackContext.error("Options not JSON");
                }
                callbackContext.success("OK");
            }
        });

        return null;
    }
}
