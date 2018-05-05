/*
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License, as published by the Free Software Foundation and
 *  available at http://www.fsf.org/licensing/licenses/lgpl.html,
 *  version 2.1 or above.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 * Copyright (c) 2001-2015 StrongAuth, Inc.
 *
 * $Date: 2015-10-02 15:09:15 -0700 (Fri, 02 Oct 2015) $
 * $Revision: 86 $
 * $Author: jpadavala $
 * $URL: https://svn.strongauth.com/repos/jade/trunk/FIDOTutorial-Eclipse/FIDOTutorial/misc/common.js $
 * 
 * *********************************************
 *                     888
 *                     888
 *                     888
 *   88888b.   .d88b.  888888  .d88b.  .d8888b
 *   888 "88b d88""88b 888    d8P  Y8b 88K
 *   888  888 888  888 888    88888888 "Y8888b.
 *   888  888 Y88..88P Y88b.  Y8b.          X88
 *   888  888  "Y88P"   "Y888  "Y8888   88888P'
 *
 * *********************************************
 * 
 *  Common functions used for validation and parsing data
 */
/**
 * Maps error codes returned from the in-built extension to user-friendly text
 * @param {type} code
 * @param {type} enrolling
 * @returns errorMsg
 */
var onError = function (code, enrolling) {

    var errorMsg = null;
    var errorMsg = null;
    switch (code) {
        case u2f.ErrorCodes.OTHER_ERROR:
            errorMsg = "Sign error (other)";
            break;
        case u2f.ErrorCodes.BAD_REQUEST:
            errorMsg = "Received a Bad Request. a. Check your servers app.json. b. Make sure you are using https:// c. Make sure you have your servers certificate imported to your browser.";
            break;
        case u2f.ErrorCodes.CONFIGURATION_UNSUPPORTED:
            errorMsg = "Configuration unsupported";
            break;
        case u2f.ErrorCodes.DEVICE_INELIGIBLE:
            if (enrolling)
                errorMsg = "Please try with a different token. This U2F token is already registered with this site.";
            else
                errorMsg = "NOTREGISTERED";
            break;
        case u2f.ErrorCodes.TIMEOUT:
            errorMsg = "Click here to try again. A timeout occured.";
            break;
        default:
            errorMsg = "Unknown error code = " + code;
            break;
    }
    console.log("Error from Gnubby: " + errorMsg);
    return errorMsg;
};


/**
 * Check if the browser is Google Chrome and if version greater than 43
 * @returns {Boolean}
 */
function isChromeCorrect() {
    if (typeof chrome === 'undefined') {
        return false;
    }
    else {
        var ver = parseInt(window.navigator.appVersion.match(/Chrome\/(\d+)\./)[1], 10);
        if (ver < 43) {
            return false;
        } else {
            return true;
        }
    }
}
