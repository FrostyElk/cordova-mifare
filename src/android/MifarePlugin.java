/**
 * Copyright (C) 2015 Frosty Elk AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import com.nxp.nfclib.classic.MFClassic;
import com.nxp.nfclib.exceptions.SmartCardException;
import com.nxp.nfclib.icode.*;
import com.nxp.nfclib.ntag.*;
import com.nxp.nfclib.plus.PlusSL1;
import com.nxp.nfclib.ultralight.Ultralight;
import com.nxp.nfclib.ultralight.UltralightC;
import com.nxp.nfclib.ultralight.UltralightEV1;
import com.nxp.nfclib.utils.NxpLogUtils;
import com.nxp.nfclib.utils.Utilities;
import com.nxp.nfcliblite.Interface.NxpNfcLibLite;
import com.nxp.nfcliblite.Interface.Nxpnfcliblitecallback;
import com.nxp.nfcliblite.cards.DESFire;
import com.nxp.nfcliblite.cards.Plus;
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
    private static final String ACTION_WRITE_TAG_DATA = "writeTag";
    private static final String TAG_EVENT_DETECTED = "onTagDetected";
    private static final String TAG_EVENT_ERROR = "onTagError";
    private static final String TAG_EVENT_ERROR_TYPE_SECURITY = "Security";
    private static final String TAG_EVENT_ERROR_TYPE_IOREAD = "IORead";
    private static final String TAG_EVENT_ERROR_TYPE_CARD = "Card";
    private static final String TAG_EVENT_ERROR_TYPE_UNSUPPORTED = "Unsupported";
    private static final int UNIVERSAL_NUMBER = 42;
    private static final int MAX_FAST_READ_PAGES = 50;
    private static String TAG = "MifarePLugin";

    private String password;
    private byte[] payload;
    private NTag nTag;
    private Tag tagInfo;

    // It seems that password errors returns as IOException instead of SmartCardException?!
    private boolean checkForPasswordSentAtIOError = false;

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

        tagInfo = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

        // Only act on intents from a tag
        if (tagInfo == null) {
            return;
        }

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

            @Override
            public void onUltraLightCardDetected(Ultralight ultralight) {
                handleUnsupportedCards();
            }

            @Override
            public void onUltraLightCCardDetected(UltralightC ultralightC) {
                handleUnsupportedCards();
            }

            @Override
            public void onUltraLightEV1CardDetected(UltralightEV1 ultralightEV1) {
                handleUnsupportedCards();
            }

            @Override
            public void onClassicCardDetected(MFClassic mfClassic) {
                handleUnsupportedCards();
            }

            @Override
            public void onDESFireCardDetected(DESFire desFire) {
                handleUnsupportedCards();
            }

            @Override
            public void onNTag203xCardDetected(NTag203x nTag203x) {
                handleUnsupportedCards();
            }

            @Override
            public void onNTagI2CCardDetected(NTagI2C nTagI2C) {
                handleUnsupportedCards();
            }

            @Override
            public void onICodeSLIDetected(ICodeSLI iCodeSLI) {
                handleUnsupportedCards();
            }

            @Override
            public void onICodeSLISDetected(ICodeSLIS iCodeSLIS) {
                handleUnsupportedCards();
            }

            @Override
            public void onICodeSLILDetected(ICodeSLIL iCodeSLIL) {
                handleUnsupportedCards();
            }

            @Override
            public void onICodeSLIXDetected(ICodeSLIX iCodeSLIX) {
                handleUnsupportedCards();
            }

            @Override
            public void onICodeSLIXSDetected(ICodeSLIXS iCodeSLIXS) {
                handleUnsupportedCards();
            }

            @Override
            public void onICodeSLIXLDetected(ICodeSLIXL iCodeSLIXL) {
                handleUnsupportedCards();
            }

            @Override
            public void onPlusCardDetected(Plus plus) {
                handleUnsupportedCards();
            }

            @Override
            public void onPlusSL1CardDetected(PlusSL1 plusSL1) {
                handleUnsupportedCards();
            }

            @Override
            public void onICodeSLIX2Detected(ICodeSLIX2 iCodeSLIX2) {
                handleUnsupportedCards();
            }
        };

        NxpNfcLibLite.getInstance().filterIntent(intent, callback);
    }


    /**
     *
     */
    private void handleUnsupportedCards() {
        JSONObject result = new JSONObject();
        try {
            result.put("nfcType", TAG_EVENT_ERROR_TYPE_UNSUPPORTED);
            result.put("nfcCode", UNIVERSAL_NUMBER);
            result.put("nfcMessage", "Unsupported tag detected");
        } catch (JSONException e) {
            NxpLogUtils.v(TAG, "JSONException: " + e.getMessage());
        }

        sendEventToWebView(TAG_EVENT_ERROR, result);
    }


    /**
     * @param nTag210 The tag
     */
    private void handleCardDetected(NTag210 nTag210) {

        nTag = nTag210;

        byte pack[] = {0, 0};
        byte pw[] = password.getBytes();

        try {

            nTag210.connect();
            NxpLogUtils.i(TAG, "Connect successful!");

            if (!"".equals(password)) {
                NxpLogUtils.i(TAG, "Trying Authenticate with Password[]: " + Utilities.dumpBytes(pw));
                checkForPasswordSentAtIOError = true;
                nTag210.authenticatePwd(pw, pack);
                checkForPasswordSentAtIOError = false;
                NxpLogUtils.i(TAG, "Authenticate successful!");
            }

            // Read full memory
            // One page = 4 bytes
            int userAvailableMemory = nTag.getCardDetails().freeMemory;
            int numbPages = userAvailableMemory / 4;
            NxpLogUtils.i(TAG, "Card Details User Memory size: " + userAvailableMemory);

            // Older devices can only read a limited number of pages,
            // some testing ended up with the number MAX_FAST_READ_PAGES
            int startPage = 0;
            int endPage = numbPages >= MAX_FAST_READ_PAGES ? MAX_FAST_READ_PAGES - 1 : numbPages - 1;
            boolean doneReading = false;

            payload = new byte[]{};

            while (!doneReading) {
                payload = Utilities.append(payload, nTag210.fastRead(startPage, endPage));

                if (endPage >= numbPages - 1) {
                    doneReading = true;
                } else {
                    startPage = endPage + 1;
                    endPage = (endPage + MAX_FAST_READ_PAGES) >= numbPages ? numbPages - 1 : endPage + MAX_FAST_READ_PAGES;
                }
            }

            NxpLogUtils.i(TAG, "Length of payload read " + payload.length);

            JSONObject result = new JSONObject();
            JSONArray tagUID;

            try {
                tagUID = new JSONArray(nTag.getUID());
                result.put("tagUID", tagUID);
                result.put("tagName", nTag.getTagName());

                JSONArray payloadArray = new JSONArray(payload);
                result.put("payload", payloadArray);
                payload = null;

                sendEventToWebView(TAG_EVENT_DETECTED, result);
            } catch (JSONException e) {
                NxpLogUtils.v(TAG, "JSONException: " + e.getMessage());
            }

        } catch (SmartCardException e) {
            JSONObject result = new JSONObject();
            try {
                if (e.getExcetionType() == SmartCardException.EXCEPTIONTYPE_SECURITY) {
                    result.put("nfcType", TAG_EVENT_ERROR_TYPE_SECURITY);
                } else {
                    result.put("nfcType", TAG_EVENT_ERROR_TYPE_CARD);
                }
                result.put("nfcCode", e.getErrorCode());
                result.put("nfcMessage", e.getMessage());
            } catch (JSONException e1) {
                NxpLogUtils.v(TAG, "JSONException: " + e1.getMessage());
            }

            sendEventToWebView(TAG_EVENT_ERROR, result);
        } catch (IOException e) {
            JSONObject result = new JSONObject();
            try {
                // Ugly hack here to give a better response to pw errors
                if (checkForPasswordSentAtIOError) {
                    result.put("nfcType", TAG_EVENT_ERROR_TYPE_SECURITY);
                    result.put("nfcCode", UNIVERSAL_NUMBER);
                    result.put("nfcMessage", "Password Authentication failed");
                    checkForPasswordSentAtIOError = false;
                } else {
                    result.put("nfcType", TAG_EVENT_ERROR_TYPE_IOREAD);
                    result.put("nfcCode", UNIVERSAL_NUMBER);
                    result.put("nfcMessage", e.getMessage());

                }
            } catch (JSONException e1) {
                NxpLogUtils.v(TAG, "JSONException: " + e1.getMessage());
            }

            sendEventToWebView(TAG_EVENT_ERROR, result);
        } finally {
            try {
                nTag210.close();
            } catch (IOException e) {
                NxpLogUtils.v(TAG, "IOException at close(): " + e.getMessage());
            }
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
        } else if (ACTION_WRITE_TAG_DATA.equals(action)) {
            result = writeTag(args.getJSONObject(0), callbackContext);
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
     *
     * @param options         Options {password: tag password}
     * @param callbackContext Callback
     * @return PluginResult
     */
    private PluginResult init(final JSONObject options, final CallbackContext callbackContext) {
        // Start the dispatch here, Cordova will not send onResume at first start
//        NxpNfcLibLite.getInstance().startForeGroundDispatch();

        if (NxpNfcLibLite.getInstance() != null) {
            NxpLogUtils.i(LOGTAG, "Starting startForeGroundDispatch in init");
            NxpNfcLibLite.getInstance().startForeGroundDispatch();
        } else {
            NxpLogUtils.w(LOGTAG, "NxpNfcLibLite.getInstance() == null");
        }

        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                NxpLogUtils.i(LOGTAG, "init: " + options.toString());
                password = options.optString("password", "");
                callbackContext.success("OK");
            }
        });

        return null;
    }


    /**
     * Write tag data
     *
     * @param data            JSONObject
     * @param callbackContext Callback
     * @return PluginResult
     */
    private PluginResult writeTag(final JSONObject data, final CallbackContext callbackContext) {

        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                NxpLogUtils.i(LOGTAG, "writeTag executed");

                // TODO: Implement write tag

                callbackContext.success("OK");
                callbackContext.error("NOK");

            }
        });

        return null;
    }
}
