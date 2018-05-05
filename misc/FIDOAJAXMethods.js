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
 * $URL: https://svn.strongauth.com/repos/jade/trunk/FIDOTutorial-Eclipse/FIDOTutorial/misc/FIDOAJAXMethods.js $
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
 *  *********************************************
 *  
 *  Object to call the 4 FIDO operations.
 *  1. preregister,
 *  2. register
 *  3. preauthenticate and,
 *  4. authenticate
 *
 */

/**************************************************************************************************
 * 8888888          d8b 888    d8b          888 d8b                   888    d8b
 *   888            Y8P 888    Y8P          888 Y8P                   888    Y8P
 *   888                888                 888                       888
 *   888   88888b.  888 888888 888  8888b.  888 888 88888888  8888b.  888888 888  .d88b.  88888b.
 *   888   888 "88b 888 888    888     "88b 888 888    d88P      "88b 888    888 d88""88b 888 "88b
 *   888   888  888 888 888    888 .d888888 888 888   d88P   .d888888 888    888 888  888 888  888
 *   888   888  888 888 Y88b.  888 888  888 888 888  d88P    888  888 Y88b.  888 Y88..88P 888  888
 * 8888888 888  888 888  "Y888 888 "Y888888 888 888 88888888 "Y888888  "Y888 888  "Y88P"  888  888
 ***************************************************************************************************/

/**
 * Initialize the URLs of the object
 * @param {type} preregisterurl
 * @param {type} registerurl
 * @param {type} preauthenticateurl
 * @param {type} authenticateurl
 * @returns {fidoaction}
 */

var fidoaction = function (preregisterurl, registerurl, preauthenticateurl, authenticateurl) {
    this.preregisterurl = preregisterurl;
    this.registerurl = registerurl;
    this.preauthenticateurl = preauthenticateurl;
    this.authenticateurl = authenticateurl;
};

/**************************************************************************************************
                                                           d88P                                             888    888      
                                                          d88P                                              888    888      
                                                         d88P                                               888    888      
88888b.  888d888  .d88b.  888d888  .d88b.   .d88b.      d88P    88888b.  888d888  .d88b.   8888b.  888  888 888888 88888b.  
888 "88b 888P"   d8P  Y8b 888P"   d8P  Y8b d88P"88b    d88P     888 "88b 888P"   d8P  Y8b     "88b 888  888 888    888 "88b 
888  888 888     88888888 888     88888888 888  888   d88P      888  888 888     88888888 .d888888 888  888 888    888  888 
888 d88P 888     Y8b.     888     Y8b.     Y88b 888  d88P       888 d88P 888     Y8b.     888  888 Y88b 888 Y88b.  888  888 
88888P"  888      "Y8888  888      "Y8888   "Y88888 d88P        88888P"  888      "Y8888  "Y888888  "Y88888  "Y888 888  888 
888                                             888             888                                                         
888                                        Y8b d88P             888                                                         
888                                         "Y88P"              888                                                         
 ***************************************************************************************************/
/**
 * Create a promise to make a pre-register or a pre-authenticate web-service call
 * @param {type} username
 * @param {type} type
 * @returns {jqXHR} returns an AJAX promise
 */
fidoaction.prototype.preaction = function (username, type) {
    var preAxnData = {"username": username};
    var url = type === 'preregister' ? this.preregisterurl : this.preauthenticateurl;
    var prerAxnCall = $.ajax({
        beforeSend: function (xhr) {
            console.log("Going to call url " + url + " for username: " + username);
        },
        url: url,
        type: "POST",
        contentType: "application/x-www-form-urlencoded",
        data: {Adata: JSON.stringify(preAxnData)},
        dataType: "json"
    });
    return prerAxnCall;
};


/**************************************************************************************************
 .d8888b.           888 888        d8888          888    888                        888    d8b                   888             888       888  .d8888b.                                                                                                                   
d88P  Y88b          888 888       d88888          888    888                        888    Y8P                   888             888   o   888 d88P  Y88b                                                                                                                  
888    888          888 888      d88P888          888    888                        888                          888             888  d8b  888 Y88b.                                                                                                                       
888         8888b.  888 888     d88P 888 888  888 888888 88888b.   .d88b.  88888b.  888888 888  .d8888b  8888b.  888888  .d88b.  888 d888b 888  "Y888b.                                                                                                                    
888            "88b 888 888    d88P  888 888  888 888    888 "88b d8P  Y8b 888 "88b 888    888 d88P"        "88b 888    d8P  Y8b 888d88888b888     "Y88b.                                                                                                                  
888    888 .d888888 888 888   d88P   888 888  888 888    888  888 88888888 888  888 888    888 888      .d888888 888    88888888 88888P Y88888       "888                                                                                                                  
Y88b  d88P 888  888 888 888  d8888888888 Y88b 888 Y88b.  888  888 Y8b.     888  888 Y88b.  888 Y88b.    888  888 Y88b.  Y8b.     8888P   Y8888 Y88b  d88P                                                                                                                  
 "Y8888P"  "Y888888 888 888 d88P     888  "Y88888  "Y888 888  888  "Y8888  888  888  "Y888 888  "Y8888P "Y888888  "Y888  "Y8888  888P     Y888  "Y8888P"                  
 ***************************************************************************************************/

/**
 * Call the authenticate web-service using the data from the extension
 * @param {type} result
 * @param {type} sessionIds
 * @returns {jqXHR|String}
 */
fidoaction.prototype.CallAuthenticateWS = function (result, sessionIds) {
    result['sessionId'] = sessionIds[result.keyHandle];
    console.log("Received the following Registration"
            + " Challenge Response parameters from "
            + "the extension; ");
    console.log(result);
    if (result) {
        //Setting data structure for the FIDO Server for authenticate REST webservice call.
        var reponseData = {
            "clientData": result.clientData,
            "sessionId": result.sessionId,
            "signatureData": result.signatureData,
            "keyHandle": result.keyHandle
        };
        //Calling the Authenticate REST web-service
        //on the FIDO Server.
        var authCall = $.ajax({
            beforeSend: function (xhr) {
                console.log("Going to call the authenticate websevice");
            },
            url: this.authenticateurl,
            type: "POST",
            contentType: "application/x-www-form-urlencoded",
            data: {Adata: JSON.stringify(reponseData)},
            dataType: "json"
        });
        return authCall;
    }
    else {
        return "Browser extension returned null. Please try again.";
    }

};


/***************************************************************************************************
 *    .d8888b.                    888      888                    8888888b.                        8888888b.
 *   d88P  Y88b                   888      888                    888   Y88b                       888   Y88b
 *   888    888                   888      888                    888    888                       888    888
 *   888        88888b.  888  888 88888b.  88888b.  888  888      888   d88P .d88b.   .d88b.       888   d88P .d88b.  .d8888b  88888b.   .d88b.  88888b.  .d8888b   .d88b.
 *   888  88888 888 "88b 888  888 888 "88b 888 "88b 888  888      8888888P" d8P  Y8b d88P"88b      8888888P" d8P  Y8b 88K      888 "88b d88""88b 888 "88b 88K      d8P  Y8b
 *   888    888 888  888 888  888 888  888 888  888 888  888      888 T88b  88888888 888  888      888 T88b  88888888 "Y8888b. 888  888 888  888 888  888 "Y8888b. 88888888
 *   Y88b  d88P 888  888 Y88b 888 888 d88P 888 d88P Y88b 888      888  T88b Y8b.     Y88b 888      888  T88b Y8b.          X88 888 d88P Y88..88P 888  888      X88 Y8b.
 *    "Y8888P88 888  888  "Y88888 88888P"  88888P"   "Y88888      888   T88b "Y8888   "Y88888      888   T88b "Y8888   88888P' 88888P"   "Y88P"  888  888  88888P'  "Y8888
 *                                                    888                              888                                  888
 *                                               Y8b d88P                         Y8b d88P                                  888
 *                                                "Y88P"                           "Y88P"                                   888
 ***************************************************************************************************/
/**
 * Call the register web-service using the data from the extension
 * @param {type} result
 * @returns {jqXHR|String}
 */
fidoaction.prototype.CallRegisterWS = function (result) {
    console.log("Received the following Registration Challenge Response "
            + "parameters from the browser extension");
    console.log(result);
    //Going to call the register webservice
    if (result) {
        var DataResponse = {
            "clientData": result.clientData,
            "sessionId": result.sessionId,
            "registrationData": result.registrationData
        };
        return $.ajax({
            beforeSend: function (xhr) {
                console.log("Going to call the register webservice");
            },
            contentType: "application/x-www-form-urlencoded",
            data: {Adata: JSON.stringify(DataResponse)},
            type: "POST",
            url: this.registerurl,
            dataType: "json"
        });
    }
    else {
        return "Browser extension returned null. Please try again.";
    }
};


/*
 *   8888888b.                                                                                    888    888                        888    d8b                   888
 *   888   Y88b                                                                                   888    888                        888    Y8P                   888
 *   888    888                                                                                   888    888                        888                          888
 *   888   d88P 8888b.  888d888 .d8888b   .d88b.       88888b.  888d888 .d88b.   8888b.  888  888 888888 88888b.   .d88b.  88888b.  888888 888  .d8888b  8888b.  888888 .d88b.
 *   8888888P"     "88b 888P"   88K      d8P  Y8b      888 "88b 888P"  d8P  Y8b     "88b 888  888 888    888 "88b d8P  Y8b 888 "88b 888    888 d88P"        "88b 888   d8P  Y8b
 *   888       .d888888 888     "Y8888b. 88888888      888  888 888    88888888 .d888888 888  888 888    888  888 88888888 888  888 888    888 888      .d888888 888   88888888
 *   888       888  888 888          X88 Y8b.          888 d88P 888    Y8b.     888  888 Y88b 888 Y88b.  888  888 Y8b.     888  888 Y88b.  888 Y88b.    888  888 Y88b. Y8b.
 *   888       "Y888888 888      88888P'  "Y8888       88888P"  888     "Y8888  "Y888888  "Y88888  "Y888 888  888  "Y8888  888  888  "Y888 888  "Y8888P "Y888888  "Y888 "Y8888
 *                                                     888
 *                                                     888
 *                                                     888
 */
/**
 * Parse the response of the preauthenticate web-service
 * @param {type} retMsg
 * @returns {fidoaction.prototype.paResp.FIDOAJAXMethodsAnonym$3}
 */
fidoaction.prototype.paResp = function (retMsg) {
    if (retMsg) {
        //SignRequest for authentication
        var signDataAuth = new Array();
        //Parsing out the data from the server
        $.each(retMsg, function (key, value) {
            //key response contains
            if (key === "Challenge") {
                if (value !== "") {
                    for (var i = 0; i < value.SignRequest.length; i++) {
                        //add each SignRequest item to an array.
                        var tmp = value.SignRequest[i];
                        signDataAuth[i] = tmp;
                    }
                }
                else {
                    console.log("No message received");
                }
            }
            else if (key === "Message") {
                if (value !== "") {
                    console.log("Message received " + value);
                }
                else {
                    console.log("No message received");
                }
            }
            else if (key === "Error") {
                if (value !== "") {
                    console.log("Error received " + value);
                    return value;
                }
                else {
                    console.log("No error received");
                }
            }
        });
    }
    else {
        return null;
    }
    return {signDataArray: signDataAuth};
};




/*
 *   8888888b.                                                                                           d8b          888
 *   888   Y88b                                                                                          Y8P          888
 *   888    888                                                                                                       888
 *   888   d88P 8888b.  888d888 .d8888b   .d88b.       88888b.  888d888 .d88b.  888d888 .d88b.   .d88b.  888 .d8888b  888888 .d88b.  888d888
 *   8888888P"     "88b 888P"   88K      d8P  Y8b      888 "88b 888P"  d8P  Y8b 888P"  d8P  Y8b d88P"88b 888 88K      888   d8P  Y8b 888P"
 *   888       .d888888 888     "Y8888b. 88888888      888  888 888    88888888 888    88888888 888  888 888 "Y8888b. 888   88888888 888
 *   888       888  888 888          X88 Y8b.          888 d88P 888    Y8b.     888    Y8b.     Y88b 888 888      X88 Y88b. Y8b.     888
 *   888       "Y888888 888      88888P'  "Y8888       88888P"  888     "Y8888  888     "Y8888   "Y88888 888  88888P'  "Y888 "Y8888  888
 *                                                     888                                           888
 *                                                     888                                      Y8b d88P
 *                                                     888                                       "Y88P"
 */

/**
 * Parse the response of the preregister web-service
 * @param {type} retMsg
 * @returns {fidoaction.prototype.prResp.FIDOAJAXMethodsAnonym$4}
 */
fidoaction.prototype.prResp = function (retMsg) {
    if (retMsg) {
        //Array to hold signData returned from FIDO Server after preregister.
        var signDataArray = new Array();
        //parsing through the response retMsg
        $.each(retMsg, function (key, value) {
            if (key === "Challenge") {
                if (value !== "") {
                    console.log("U2FRegistration challenge parameters from the FIDO server: ");
                    console.log(value);
                    $.each(value, function (k1, v1) {
                        if (k1 === "RegisterRequest") {
                            if (v1[0] !== "") {
                                var temp = v1[0];
                                //setting enrollData to be sent to the Chrome Extension
                                enrollData.appId = temp.appId;
                                enrollData.challenge = temp.challenge;
                                enrollData.version = temp.version;

                            }
                            else {
                                console.log("No RegisterRequest received from the server");
                            }
                        }
                        else if (k1 === "sessionId") {
                            if (v1 !== "") {
                                //setting sessionId
                                enrollData.sessionId = v1;
                            }
                            else {
                                //No sessionID received from the server
                                console.log("No sessionID received from the server");
                            }
                        }
                        else if (k1 === "SignRequest") {
                            if (v1.length > 0) {
                                //initialize array of signData
                                console.log("signData received of length, " + v1.length + " Details: ");
                                console.log(v1);

                                for (var i = 0; i < v1.length; i++) {
                                    //setting signDataArray to be sent to the Chrome Extension
                                    signDataArray[i] = v1[i];
                                }
                            }
                            else {
                                console.log("SignRequest is empty");
                            }
                        }
                    });
                }
                else {
                    console.log(key + " returned no value");
                }
            }
            else if (key === "Message") {

                if (value !== "") {
                    console.log("Message returned " + value);
                }
                else {
                    console.log(key + " returned no value");

                }
            }
            else if (key === "Error") {

                if (value !== "") {
                    console.log("Error returned " + value);
                    $("#msg").text("Error returned from the server: " + value);
                }
                else {
                    console.log(key + " returned no value");

                }
            }
        });

        return {
            signData: signDataArray,
            enrollData: enrollData
        };

    }
    else {
        return null;
    }
};
