/**
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
 * Copyright (c) 2001-2016 StrongAuth, Inc.
 *
 * $Date: 2016-02-12 14:22:26 -0800 (Fri, 12 Feb 2016) $
 * $Revision: 123 $
 * $Author: jpadavala $
 * $URL: https://svn.strongauth.com/repos/jade/trunk/FIDOTutorial-Eclipse/FIDOTutorial/misc/SKFERestClient.java $
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
 * A class to encapsulate RESTful web-service calls to the StrongKey 
 * FIDOEngine - a module of StrongKey CryptoEngine (SKCE).
 *
 * SKFE provides FIDO Alliance (https://fidoalliance.org) Universal 2nd
 * Factor (U2F)-based webservices (SOAP and REST) too support registration
 * and authentication.  This class demonstrates RESTful calls to SKFE.
 *
 */
package com.strongauth.fidotutorial.postfido;

import com.strongauth.fidotutorial.utilities.Common;
import com.strongauth.fidotutorial.utilities.Constants;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.logging.Level;
import javax.json.Json;
import javax.json.JsonObject;
import org.apache.http.client.utils.URIBuilder;

public class SKFERestClient {

    /**
     * StrongKey FidoEngine service credentials
     */
    private final String skcedid = "1";
    private final String svcusername = "svcfidouser";
    private final String svcpassword = "Abcd1234!";
    private final String fidoprotocol = "U2F_V2";
       
    /**
     * Global variables
     */
    private JsonObject responsejson;

    /************************************************************************
     *                                                        d8b          888
     *                                                        Y8P          888
     *                                                                     888
     *    88888b.  888d888  .d88b.  888d888  .d88b.   .d88b.  888 .d8888b  888888  .d88b.  888d888
     *    888 "88b 888P"   d8P  Y8b 888P"   d8P  Y8b d88P"88b 888 88K      888    d8P  Y8b 888P"
     *    888  888 888     88888888 888     88888888 888  888 888 "Y8888b. 888    88888888 888
     *    888 d88P 888     Y8b.     888     Y8b.     Y88b 888 888      X88 Y88b.  Y8b.     888
     *    88888P"  888      "Y8888  888      "Y8888   "Y88888 888  88888P'  "Y888  "Y8888  888
     *    888                                             888
     *    888                                        Y8b d88P
     *    888                                         "Y88P"
     ***********************************************************************/
     
    /**
     * Step-1 for FIDO U2F Authenticator registration.  
     * 
     * This methods makes a preregister() REST web-service call (denoted by
     * Constants.PRE_REGISTER_ENDPOINT) to SKFE, which returns a challenge.
     * The response from the SKFE is a JSON string whose format is:
     * 
     *      {
     *          "Challenge" : "....",
     *          "Message" : "....",
     *          "Error" : "...."
     *      }
     *
     * It then parses through the SKFE response to extract the "Challenge", a
     * JSON string containing a FIDO-U2F compliant challenge to be digitally 
     * signed by the Token during registration.
     *
     * @param username - String Name of the user attempting to register a
     * FIDO U2F authenticator to his/her account.
     * @return JsonObject Response sent back by the SKFE server.
     * @throws URISyntaxException, ProtocolException, MalformedURLException, 
     * IOException
     */
    public JsonObject preregister(final String username) throws URISyntaxException, 
                        ProtocolException, MalformedURLException, IOException 
    {
        // Check parameter
        if (username == null || username.isEmpty())
            return null;

        // Private method to call the SKFE preregister() web-service 
        String skferesponse = getFidoChallenge(username, Constants.PRE_REGISTER_ENDPOINT);
        JsonObject error = checkForError(skferesponse);
        if (error != null)
            return error;
        
        // Read the "Challenge", a JsonObject element in the response
        JsonObject challenge = (JsonObject) Common.getJsonValue(skferesponse, "Challenge", "JsonObject");
        if (challenge == null)
            return Json.createObjectBuilder().add(Constants.REST_SERVICE_ERROR, "Challenge is empty").build();
        
        // Return response from SKFE
        Common.log(Level.INFO, "FIDOTUT-MSG-1000", "Preregister() challenge from SKFE: \n" + challenge);
        return Common.converToJsonObject(skferesponse);
    }

    /************************************************************************
     *                                d8b          888
     *                                Y8P          888
     *                                             888
     *      888d888  .d88b.   .d88b.  888 .d8888b  888888  .d88b.  888d888
     *      888P"   d8P  Y8b d88P"88b 888 88K      888    d8P  Y8b 888P"
     *      888     88888888 888  888 888 "Y8888b. 888    88888888 888
     *      888     Y8b.     Y88b 888 888      X88 Y88b.  Y8b.     888
     *      888      "Y8888   "Y88888 888  88888P'  "Y888  "Y8888  888
     *                            888
     *                       Y8b d88P
     *                        "Y88P"
     ************************************************************************/
     
    /**
     * Step-2 for FIDO U2F Authenticator registration.  
     * 
     * * This methods makes a register() REST web-service call (denoted by
     * Constants.REGISTER_ENDPOINT) to SKFE with the signed challenge from
     * the preregister() call earlier.  The preregister() and register() 
     * webservice methods on the SKFE are time-linked; meaning, register() 
     * should be called within a limited time after preregister() is finished - 
     * otherwise, the user session is invalidated on SKFE.
     *
     * @param location String containing information from where the user is
     * attempting to register the authenticator from.  This is used to store
     * meta-data about the registration event.
     * @param tokendata JsonObject containing the response from the FIDO U2F
     * Token after it generates a new key-pair and digitally signs the SKFE
     * challenge from preregister() with the newly minted private-key
     * @return String JsonObject response from SKFE is shown below:
     *
     * If the registration request is successful:
     * 
     *      {
     *          "Response" : "Successfully processed registration response",
     *          "Message" : "....",
     *          "Error" : "...."
     *      }
     *
     * If the registration request failed:
     * 
     *      {
     *          "Response" : "",
     *          "Message" : "....",
     *          "Error" : "FIDO-ERR-[CODE]: Error registering key"
     *      }
     * 
     * @throws MalformedURLException URISyntaxException IOException
     */
    public String register(final String location, final JsonObject tokendata) throws 
                            MalformedURLException, URISyntaxException, IOException 
    {
        if (location == null || location.isEmpty() || tokendata == null)
            return null;

        // Private method to call the SKFE register() web-service 
        String skferesponse = submitFidoResponse(location, tokendata, Constants.REGISTER_ENDPOINT);
        Common.log(Level.INFO, "FIDOTUT-MSG-1000", "Register() response from SKFE: " + skferesponse);
        return skferesponse;
    }

    /*************************************************************************
                                            888    888                        888    d8b                   888             
                                            888    888                        888    Y8P                   888             
                                            888    888                        888                          888             
88888b.  888d888  .d88b.   8888b.  888  888 888888 88888b.   .d88b.  88888b.  888888 888  .d8888b  8888b.  888888  .d88b.  
888 "88b 888P"   d8P  Y8b     "88b 888  888 888    888 "88b d8P  Y8b 888 "88b 888    888 d88P"        "88b 888    d8P  Y8b 
888  888 888     88888888 .d888888 888  888 888    888  888 88888888 888  888 888    888 888      .d888888 888    88888888 
888 d88P 888     Y8b.     888  888 Y88b 888 Y88b.  888  888 Y8b.     888  888 Y88b.  888 Y88b.    888  888 Y88b.  Y8b.     
88888P"  888      "Y8888  "Y888888  "Y88888  "Y888 888  888  "Y8888  888  888  "Y888 888  "Y8888P "Y888888  "Y888  "Y8888  
888                                                                                                                        
888                                                                                                                        
888                                                                                                     
     ************************************************************************/
    
    /**
     * Step-1 for FIDO U2F Authenticator authentication.  
     * 
     * This methods makes a preauthenticate() REST web-service call (denoted 
     * by Constants.PRE_AUTHENTICATE_ENDPOINT) to SKFE, which returns a 
     * challenge.  The response from the SKFE is a JSON string whose format is:
     * 
     *      {
     *          "Challenge" : "....",
     *          "Message" : "....",
     *          "Error" : "...."
     *      }
     *
     * It then parses through the SKFE response to extract the "Challenge", a
     * JSON string containing a FIDO-U2F compliant challenge to be digitally 
     * signed by the Token during authentication.
     *
     * @param username - String Name of the user attempting to authenticate
     * with a FIDO U2F authenticator to his/her account.
     * @return JsonObject Response sent back by the SKFE server.
     * @throws URISyntaxException, MalformedURLException, IOException
     *
     */
    public JsonObject preauthenticate(final String username) throws URISyntaxException, 
                            MalformedURLException, IOException 
    {
        // Check parameter
        if (username == null || username.isEmpty())
            return null;

        // Private method to call the SKFE preauthenticate() web-service 
        String skferesponse = getFidoChallenge(username, Constants.PRE_AUTHENTICATE_ENDPOINT);
        
        // Check for an error
        JsonObject error = checkForError(skferesponse);
        if (error != null)
            return error;

        // Read the "Challenge", a JsonObject element in the response
        JsonObject challenge = (JsonObject) Common.getJsonValue(skferesponse, "Challenge", "JsonObject");
        if (challenge == null)
            return Json.createObjectBuilder().add(Constants.REST_SERVICE_ERROR, "Challenge is empty").build();
        
        // Return response from SKFE
        Common.log(Level.INFO, "FIDOTUT-MSG-1000", "Preauthenticate() challenge from SKFE: \n" + challenge);
        return Common.converToJsonObject(skferesponse);
    }

    /************************************************************************
     *                        888    888                        888    d8b                   888
     *                        888    888                        888    Y8P                   888
     *                        888    888                        888                          888
     *       8888b.  888  888 888888 88888b.   .d88b.  88888b.  888888 888  .d8888b  8888b.  888888  .d88b.
     *          "88b 888  888 888    888 "88b d8P  Y8b 888 "88b 888    888 d88P"        "88b 888    d8P  Y8b
     *      .d888888 888  888 888    888  888 88888888 888  888 888    888 888      .d888888 888    88888888
     *      888  888 Y88b 888 Y88b.  888  888 Y8b.     888  888 Y88b.  888 Y88b.    888  888 Y88b.  Y8b.
     *      "Y888888  "Y88888  "Y888 888  888  "Y8888  888  888  "Y888 888  "Y8888P "Y888888  "Y888  "Y8888
     *
     ************************************************************************/
    
    /**
     * Step-2 for FIDO U2F Authenticator authentication.  
     * 
     * * This methods makes an authenticate() REST web-service call (denoted by
     * Constants.AUTHENTICATE_ENDPOINT) to SKFE with the signed challenge from
     * the preauthenticate() call earlier.  The preauthenticate() and authenticate() 
     * webservice methods on the SKFE are time-linked; meaning, authenticate() 
     * should be called within a limited time after preauthenticate() is finished - 
     * otherwise, the user session is invalidated on SKFE.
     *
     * @param location String containing information from where the user is
     * attempting to register the authenticator from.  This is used to store
     * meta-data about the registration event.
     * @param tokendata JsonObject containing the response from the FIDO U2F
     * Token after it generates a new key-pair and digitally signs the SKFE
     * challenge from preregister() with the newly minted private-key
     * @return String JsonObject response from SKFE is shown below:
     *
     * If the authentication request is successful:
     * 
     *      {
     *          "Response" : "Successfully processed sign response",
     *          "Message" : "....",
     *          "Error" : "...."
     *      }
     *
     * If the authentication request failed:
     * 
     *      {
     *          "Response" : "",
     *          "Message" : "....",
     *          "Error" : "FIDO-ERR-[CODE]: Error authenticating key"
     *      }
     * 
     * @throws MalformedURLException URISyntaxException IOException
     */
    public String authenticate(final String location, final JsonObject tokendata) throws 
                        URISyntaxException, MalformedURLException, IOException 
    {
        if (location == null || location.isEmpty() || tokendata == null)
            return null;

        // Private method to call the SKFE register() web-service 
        String skferesponse = submitFidoResponse(location, tokendata, Constants.AUTHENTICATE_ENDPOINT);
        Common.log(Level.INFO, "FIDOTUT-MSG-1000", "Authenticate() response from SKFE: " + skferesponse);
        return skferesponse;
    }

    /***************************************************************************
                  888    888     888         888  .d8888b.                                               888    d8b                   
                  888    888     888         888 d88P  Y88b                                              888    Y8P                   
                  888    888     888         888 888    888                                              888                          
 .d88b.   .d88b.  888888 888     888 888d888 888 888         .d88b.  88888b.  88888b.   .d88b.   .d8888b 888888 888  .d88b.  88888b.  
d88P"88b d8P  Y8b 888    888     888 888P"   888 888        d88""88b 888 "88b 888 "88b d8P  Y8b d88P"    888    888 d88""88b 888 "88b 
888  888 88888888 888    888     888 888     888 888    888 888  888 888  888 888  888 88888888 888      888    888 888  888 888  888 
Y88b 888 Y8b.     Y88b.  Y88b. .d88P 888     888 Y88b  d88P Y88..88P 888  888 888  888 Y8b.     Y88b.    Y88b.  888 Y88..88P 888  888 
 "Y88888  "Y8888   "Y888  "Y88888P"  888     888  "Y8888P"   "Y88P"  888  888 888  888  "Y8888   "Y8888P  "Y888 888  "Y88P"  888  888 
     888                                                                                                                              
Y8b d88P                                                                                                                              
 "Y88P"                                                                                                                               
     ****************************************************************************/
    
    /**
     * Makes a Http URL connection object using supplied URL and WS end-point
     *
     * @param methodendpoint String; the REST api endpoint of the method to be 
     * called on SKCE server
     * @return HttpUrlConnection object
     * @throws MalformedURLException IOException
     */
    private HttpURLConnection getUrlConnection(final String methodendpoint) 
            throws URISyntaxException, MalformedURLException, IOException 
    {
        //  Build service information           
        String svcinfo = Json.createObjectBuilder()
                .add("did", skcedid)
                .add("svcusername", svcusername)
                .add("svcpassword", svcpassword)
                .add("protocol", fidoprotocol)
                .build().toString();

        //  Build the url and add query parameters
        URIBuilder uribuilder = new URIBuilder(Common.SKFE_REST_URI + methodendpoint);
        uribuilder.addParameter("svcinfo", svcinfo);
            
        // Build a url object and open a connection
        URL url = new URL(uribuilder.toString());
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        // Set connection properties
        conn.setReadTimeout(Constants.TIMEOUT_VALUE);
        conn.setConnectTimeout(Constants.TIMEOUT_VALUE);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Content-Type", "application/json");

        return conn;
    }

    /***************************************************************************
                  888    8888888888 d8b      888           .d8888b.  888               888 888                                     
                  888    888        Y8P      888          d88P  Y88b 888               888 888                                     
                  888    888                 888          888    888 888               888 888                                     
 .d88b.   .d88b.  888888 8888888    888  .d88888  .d88b.  888        88888b.   8888b.  888 888  .d88b.  88888b.   .d88b.   .d88b.  
d88P"88b d8P  Y8b 888    888        888 d88" 888 d88""88b 888        888 "88b     "88b 888 888 d8P  Y8b 888 "88b d88P"88b d8P  Y8b 
888  888 88888888 888    888        888 888  888 888  888 888    888 888  888 .d888888 888 888 88888888 888  888 888  888 88888888 
Y88b 888 Y8b.     Y88b.  888        888 Y88b 888 Y88..88P Y88b  d88P 888  888 888  888 888 888 Y8b.     888  888 Y88b 888 Y8b.     
 "Y88888  "Y8888   "Y888 888        888  "Y88888  "Y88P"   "Y8888P"  888  888 "Y888888 888 888  "Y8888  888  888  "Y88888  "Y8888  
     888                                                                                                              888          
Y8b d88P                                                                                                         Y8b d88P          
 "Y88P"                                                                                                           "Y88P"           
     ***************************************************************************/
    
    /**
     * Makes a web-service call 'preregister' or 'preauthenticate' based on
     * the methodendpoint provided. Both of these web-services will return
     * a fido registration/authentication challenge.
     *
     * @param username String; username of the account holder trying to register
     * or authenticate
     * @param methodendpoint String; "preregister" or "preauthenticate" based
     * on the operation being performed
     * @return String; SKFE response
     * @throws URISyntaxException
     * @throws MalformedURLException
     * @throws ProtocolException
     * @throws IOException
     */
    private String getFidoChallenge(final String username, final String methodendpoint) 
            throws URISyntaxException, MalformedURLException, ProtocolException, IOException 
    {
        //  Input checks
        if (username == null || username.isEmpty() || 
            methodendpoint == null || methodendpoint.isEmpty() || 
            (!methodendpoint.equalsIgnoreCase(Constants.PRE_REGISTER_ENDPOINT) && 
            !methodendpoint.equalsIgnoreCase(Constants.PRE_AUTHENTICATE_ENDPOINT))) 
        {
            return null;
        }
        
        //  Build service information           
        String svcinfo = Json.createObjectBuilder()
                .add("did", skcedid)
                .add("svcusername", svcusername)
                .add("svcpassword", svcpassword)
                .add("protocol", fidoprotocol)
                .build().toString();

        //  Create a SKFE compliant payload object to pass in the username.
        String payload = Json.createObjectBuilder()
                .add(Constants.JSON_KEY_SERVLET_INPUT_USERNAME, username)
                .build().toString();

        try {
            //  Make the call
            String response = callSKCEServer(methodendpoint, svcinfo, payload);
            if (response==null || response.isEmpty()) {
                //  If error from SKCE server
                responsejson = Json.createObjectBuilder()
                        .add(Constants.REST_SERVER_ERROR, "Server error : "
                             + "Check application logs or contact support")
                        .build();
                Common.log(Level.WARNING, "FIDOTUT-ERR-1000", "Server error : "
                             + "Check application logs or contact support");
                return null;
            } else {
                return response;
            }
        } catch (Exception ex) {
            //  If error from SKCE server
            responsejson = Json.createObjectBuilder()
                    .add(Constants.REST_SERVER_ERROR, "Server error : " + ex.getLocalizedMessage()
                         + ". Check application logs or contact support")
                    .build();
            Common.log(Level.WARNING, "FIDOTUT-ERR-1000", "Server error : " + ex.getLocalizedMessage()
                         + ". Check application logs or contact support");
            return null;
        }
    }
    
    /***************************************************************************
                  888 888  .d8888b.  888                         .d8888b.                                             
                  888 888 d88P  Y88b 888                        d88P  Y88b                                            
                  888 888 Y88b.      888                        Y88b.                                                 
 .d8888b  8888b.  888 888  "Y888b.   888  888  .d8888b  .d88b.   "Y888b.    .d88b.  888d888 888  888  .d88b.  888d888 
d88P"        "88b 888 888     "Y88b. 888 .88P d88P"    d8P  Y8b     "Y88b. d8P  Y8b 888P"   888  888 d8P  Y8b 888P"   
888      .d888888 888 888       "888 888888K  888      88888888       "888 88888888 888     Y88  88P 88888888 888     
Y88b.    888  888 888 888 Y88b  d88P 888 "88b Y88b.    Y8b.     Y88b  d88P Y8b.     888      Y8bd8P  Y8b.     888     
 "Y8888P "Y888888 888 888  "Y8888P"  888  888  "Y8888P  "Y8888   "Y8888P"   "Y8888  888       Y88P    "Y8888  888 
 
     ***************************************************************************/
    /**
     * Makes HTTP call with svcinfo and payload as input. Parses the
     * response back from the HTTP request and returns the same as string.
     * 
     * @param methodname    String; SKFE RESTful interface method end point.
     * @param svcinfo   String; service credentials input to SKCE service.
     * @param payload   String; payload input to be provided to the SKCE service.
     * @return 
     * @throws java.io.IOException 
     */
    public static String callSKCEServer(final String methodname, 
                                        String svcinfo, 
                                        String payload) 
                                            throws IOException
    {
        if (methodname==null || methodname.isEmpty())
            return null;

        if ( svcinfo==null || svcinfo.trim().isEmpty() ) {
            svcinfo="";
        }
        
        if ( payload==null || payload.trim().isEmpty() ) {
            payload="";
        }
        
        Common.log(Level.INFO, "FIDOTUT-MSG-1000", "Calling FIDO webservice: " 
                    + Common.SKFE_REST_URI + methodname);
        
        try {           
            // Build a url object and open a connection
            URIBuilder uribuilder = new URIBuilder(Common.SKFE_REST_URI + methodname);
            URL url = new URL(uribuilder.toString());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // Set connection properties
            conn.setReadTimeout(Constants.TIMEOUT_VALUE);
            conn.setConnectTimeout(Constants.TIMEOUT_VALUE);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            
            // Write out form parameters
            String formparams = "svcinfo=" + svcinfo + "&payload=" + payload;
            conn.setFixedLengthStreamingMode(formparams.getBytes().length);
            PrintWriter out = new PrintWriter(conn.getOutputStream());
            out.print(formparams);
            out.close();
            
            // Error from SKCE server
            if (conn.getResponseCode() != 200) {
                throw new RuntimeException("Failed: HTTP error code : " + conn.getResponseCode());
            }

            // Read SKCE server response
            String output, response="";
            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
            while ((output = br.readLine()) != null) {
                response = response + output;
            }

            return response;
            
        } catch (URISyntaxException | IOException ex) {
            System.out.println("Exception : " + ex.getLocalizedMessage());
            return null;
        }
    }
    
    /********************************************************************************
                  888                    d8b 888    8888888888 d8b      888          8888888b.                                                                 
                  888                    Y8P 888    888        Y8P      888          888   Y88b                                                                
                  888                        888    888                 888          888    888                                                                
.d8888b  888  888 88888b.  88888b.d88b.  888 888888 8888888    888  .d88888  .d88b.  888   d88P  .d88b.  .d8888b  88888b.   .d88b.  88888b.  .d8888b   .d88b.  
88K      888  888 888 "88b 888 "888 "88b 888 888    888        888 d88" 888 d88""88b 8888888P"  d8P  Y8b 88K      888 "88b d88""88b 888 "88b 88K      d8P  Y8b 
"Y8888b. 888  888 888  888 888  888  888 888 888    888        888 888  888 888  888 888 T88b   88888888 "Y8888b. 888  888 888  888 888  888 "Y8888b. 88888888 
     X88 Y88b 888 888 d88P 888  888  888 888 Y88b.  888        888 Y88b 888 Y88..88P 888  T88b  Y8b.          X88 888 d88P Y88..88P 888  888      X88 Y8b.     
 88888P'  "Y88888 88888P"  888  888  888 888  "Y888 888        888  "Y88888  "Y88P"  888   T88b  "Y8888   88888P' 88888P"   "Y88P"  888  888  88888P'  "Y8888  
                                                                                                                  888                                          
                                                                                                                  888                                          
                                                                                                                  888               
     ********************************************************************************/

    /**
     * Makes a web-service call to 'register' or 'authenticate' based on the
     * supplied methodendpoint. 
     *
     * @param location String; URL location of the webservice
     * @param adata JsonObject, FIDO U2F authenticator's signed challenge
     * @param methodendpoint String; "register" or "authenticate"
     * @return String containing the JSON response from SKFE
     * @throws URISyntaxException MalformedURLException ProtocolException IOException
     */
    private String submitFidoResponse(final String location, 
                                    final JsonObject tokendata, 
                                    final String methodendpoint) 
            throws
            URISyntaxException, MalformedURLException, ProtocolException, IOException 
    {
        // Check parameters
        if (location == null || location.isEmpty() || tokendata == null || 
                methodendpoint == null || methodendpoint.isEmpty() || 
                (!methodendpoint.equalsIgnoreCase(Constants.REGISTER_ENDPOINT) && 
                !methodendpoint.equalsIgnoreCase(Constants.AUTHENTICATE_ENDPOINT))) {
            return null;
        }

        //  Build service information           
        String svcinfo = Json.createObjectBuilder()
                .add("did", skcedid)
                .add("svcusername", svcusername)
                .add("svcpassword", svcpassword)
                .add("protocol", fidoprotocol)
                .build().toString();
        
        // Build metadata object with location information
        String locationkey = (methodendpoint.equalsIgnoreCase(Constants.REGISTER_ENDPOINT))
                ? "create_location" : "last_used_location";
        JsonObject metadata = javax.json.Json.createObjectBuilder()
                .add("version", "1.0") // only supported version currently
                .add(locationkey, location).
                build();

        // Create SKFE payload object with data from FIDO Token
        String payload = Json.createObjectBuilder()
                .add(Constants.JSON_KEY_SERVLET_INPUT_METADATA, metadata)
                .add(Constants.JSON_KEY_SERVLET_INPUT_RESPONSE, tokendata)
                .build().toString();
        if (payload == null) {
            return null;
        }
        
        try {
            //  Make the call
            String response = callSKCEServer(methodendpoint, svcinfo, payload);
            if (response==null || response.isEmpty()) {
                //  If error from SKCE server
                responsejson = Json.createObjectBuilder()
                        .add(Constants.REST_SERVER_ERROR, "Server error : "
                             + "Check application logs or contact support")
                        .build();
                Common.log(Level.WARNING, "FIDOTUT-ERR-1000", "Server error : "
                             + "Check application logs or contact support");
                return null;
            } else {
                return response;
            }
        } catch (Exception ex) {
            //  If error from SKCE server
            responsejson = Json.createObjectBuilder()
                    .add(Constants.REST_SERVER_ERROR, "Server error : " + ex.getLocalizedMessage()
                         + ". Check application logs or contact support")
                    .build();
            Common.log(Level.WARNING, "FIDOTUT-ERR-1000", "Server error : " + ex.getLocalizedMessage()
                         + ". Check application logs or contact support");
            return null;
        }
    }

    /***************************************************************************
         888                        888      8888888888                  8888888888                                  
         888                        888      888                         888                                         
         888                        888      888                         888                                         
 .d8888b 88888b.   .d88b.   .d8888b 888  888 8888888     .d88b.  888d888 8888888    888d888 888d888  .d88b.  888d888 
d88P"    888 "88b d8P  Y8b d88P"    888 .88P 888        d88""88b 888P"   888        888P"   888P"   d88""88b 888P"   
888      888  888 88888888 888      888888K  888        888  888 888     888        888     888     888  888 888     
Y88b.    888  888 Y8b.     Y88b.    888 "88b 888        Y88..88P 888     888        888     888     Y88..88P 888     
 "Y8888P 888  888  "Y8888   "Y8888P 888  888 888         "Y88P"  888     8888888888 888     888      "Y88P"  888     
     ***************************************************************************/
    
    /**
     * Checks if response from SKFE has a non-empty error element in it
     * @param skferesponse String with JSON content
     * @return JsonObject if anything erroneous is found, null otherwise.
     */
    private JsonObject checkForError(String skferesponse) 
    {
        String error;
        if (skferesponse == null || skferesponse.isEmpty()) {
            error = "Empty response from SKCE server";
        } else {
            //  Read the "Error", a String element in the response
            error = (String) Common.getJsonValue(skferesponse, "Error", "String");
        }
        
        if (error != null && !error.trim().isEmpty())
            return Json.createObjectBuilder().add(Constants.REST_SERVICE_ERROR, error).build();
        else
            return null;
    }

}
