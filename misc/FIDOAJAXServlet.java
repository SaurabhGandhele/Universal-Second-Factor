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
 * Copyright (c) 2001-2016 StrongAuth, Inc.
 *
 * $Date: 2016-02-12 14:22:26 -0800 (Fri, 12 Feb 2016) $
 * $Revision: 123 $
 * $Author: jpadavala $
 * $URL: https://svn.strongauth.com/repos/jade/trunk/FIDOTutorial-Eclipse/FIDOTutorial/misc/FIDOAJAXServlet.java $
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

 * Servlet to handle XHR Requests to perform the following FIDO operations:
 *  1. Authenticate
 *  2. Pre-register
 *  3. Register
 *  NOTE: preauthenticate can be found at JSPServlet.java
 *
 * The calls in this servlet make calls to SKFERestClient.java which is a class that
 * demonstrates how to make RESTful calls to SKFE to achieve FIDO U2F authenticator
 * registrations and authentications.
 *
 */
package com.strongauth.fidotutorial.postfido;

import com.strongauth.fidotutorial.utilities.Common;
import com.strongauth.fidotutorial.utilities.Constants;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.logging.Level;
import javax.json.JsonObject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class FIDOAJAXServlet extends HttpServlet {
    /**
     * Global Variables
     */
    
    /**
     * variable to set the response after the request is processed.
     */
    String RequestDispatcherURL;
    /**
     * Variable to store the String result of a request which will be sent back
     * to the user
     */
    String reqResponse;
    /**
     * Variable to store a JSON Object sent back as a result
     */
    JsonObject responseJSON = null;
    /**
     * Instantiating a class to make RESTful web-service calls to SKFE to
     * achieve FIDO U2F authenticator registrations and authentications.
     */
    SKFERestClient skceclient = new SKFERestClient();

    /**
     * Sends back a String response to an XHR request
     * @param response HttpServletResponse
     * @throws IOException
     */
    void StringResponse(HttpServletResponse response) throws IOException {
        response.setContentType("application/json");
        try (PrintWriter pw = response.getWriter()) {
            pw.println(reqResponse);
        }
    }

    /**
     * Sends back a JSON response to an XHR request
     * @param response HttpServletResponse
     * @throws IOException
     */
    void JSONResponse(HttpServletResponse response) throws IOException {
        response.setContentType("application/json");
        try (PrintWriter pw = response.getWriter()) {
            pw.println(responseJSON);
        }
    }

    /**
     * Handles the HTTP <code>GET</code> method. NOTE: Not needed at this point.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Common.log(Level.INFO, "FIDOTUT-MSG-1000", "Inside doGet of FIDOAJAXServlet");
    }

    /*
     ************************************************************************
     *                        888    888                        888    d8b                   888
     *                        888    888                        888    Y8P                   888
     *                        888    888                        888                          888
     *       8888b.  888  888 888888 88888b.   .d88b.  88888b.  888888 888  .d8888b  8888b.  888888  .d88b.
     *          "88b 888  888 888    888 "88b d8P  Y8b 888 "88b 888    888 d88P"        "88b 888    d8P  Y8b
     *      .d888888 888  888 888    888  888 88888888 888  888 888    888 888      .d888888 888    88888888
     *      888  888 Y88b 888 Y88b.  888  888 Y8b.     888  888 Y88b.  888 Y88b.    888  888 Y88b.  Y8b.
     *      "Y888888  "Y88888  "Y888 888  888  "Y8888  888  888  "Y888 888  "Y8888P "Y888888  "Y888  "Y8888
     *
     ************************************************************************
     */
    /**
     * Step-2 or last step of authentication process using a FIDO U2F
     * authenticator. This method receives the U2F authentication response
     * parameters which is processed and the authentication result is notified
     * back to the caller.
     *
     * Both preauthenticate and authenticate methods are time linked. Meaning,
     * authenticate should happen with in a certain time limit after the
     * preregister is finished; otherwise, the user session would be invalidated
     * on SKFE.
     *
     * @param location String; location information from where the user is
     * trying to authenticate from? This is used to build metadata of the
     * authentication event.
     *
     * @param jauthGnubby
     * @return String of web-service result for 'authenticate'. The response
     * back from the SKFE is a JSON string; the format of which is given below.
     *
     * Success - "Successfully processed authentication response"
     *
     */
    private void authenticate() throws IOException {
        try {
            reqResponse = skceclient.authenticate("unknown", responseJSON);
        } catch (URISyntaxException | MalformedURLException ex) {
            Common.log(Level.WARNING, "FIDO-ERR-1001", ex.getLocalizedMessage());
        }
    }

    /*
     ************************************************************************
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
     *************************************************************************
     */
    /**
     * Step-2 or last step of FIDO U2F authenticator registration process. This
     * method receives the U2F registration response parameters which is
     * processed and the registration result is notified back to the caller.
     *
     * Both preregister and register methods are time linked. Meaning, register
     * should happen with in a certain time limit after the preregister is
     * finished; otherwise, the user session would be invalidated on SKFE.
     *
     * @param location String; location information from where the user is
     * trying to register the authenticator from? This is used to build metadata
     * of the registration event.
     *
     * @param jpreregGnubby
     * @return String of web-service result for 'register'. The response back
     * from the SKFE is a JSON string; the format of which is given below.
     */
    private void register() throws IOException {
        try {
            reqResponse = skceclient.register("unknown", responseJSON);
        } catch (URISyntaxException ex) {
            Common.log(Level.WARNING, "FIDO-ERR-1001", ex.getLocalizedMessage());
        }
    }

    /*
     ************************************************************************
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
     ************************************************************************
     */
    /**
     * Step-1 for fido authenticator registration. This methods makes a REST
     * web-service call to SKFE which returns a challenge. The response back
     * from the SKFE is a JSON string; the format of which is given below. {
     * "Challenge" : "....", "Message" : "....", "Error" : "...." }
     *
     * @param username - String; Name of the user trying to register a FIDO U2F
     * authenticator to his/her account.
     * @return JsonObject; Response being sent back by the SKFE server. A
     * Jsonobject with error in case of errors.
     *
     * @throws java.net.URISyntaxException
     * @throws java.net.ProtocolException
     * @throws java.net.MalformedURLException
     */
    private void preregister() throws IOException {
        try {
            responseJSON = skceclient.preregister(responseJSON.getString("username"));
        } catch (URISyntaxException ex) {
            Common.log(Level.WARNING, "FIDO-ERR-1001", ex.getLocalizedMessage());
        }
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException 
    {
        // Get ServletPath of the request
        String requestpath = request.getServletPath();
        Common.log(Level.INFO, "FIDOTUT-MSG-1000", "Received HTTP request: " + requestpath);
        
        // Retrieve request parameter; if "Adata" is empty 
        String requestparam = request.getParameter("Adata");
        if (requestparam == null || requestparam.length() == 0) {
            requestpath = "EMPTY_PARAMETER";
        }
        else {
            // Convert parameter to JSON
            responseJSON = Common.stringToJSON(requestparam);
        }
        switch (requestpath) {
            case "/" + Constants.PREREGISTER:
                Common.log(Level.INFO, "FIDOTUT-MSG-1000", "Preregister() request parameter: " + requestparam);
                Common.log(Level.INFO, "FIDOTUT-MSG-1000", "username: " + responseJSON.get("username"));
                preregister(); // XHR Request to the FIDO preregister webservice
                JSONResponse(response);
                break;
            case "/" + Constants.REGISTER:
                Common.log(Level.INFO, "FIDOTUT-MSG-1000", "Register() request parameter: " + requestparam);
                register(); // XHR Request to the FIDO register webservice
                StringResponse(response);
                break;
            case "/" + Constants.AUTHENTICATE:
                Common.log(Level.INFO, "FIDOTUT-MSG-1000", "Authenticate() request parameter: " + requestparam);
                authenticate();  // XHR Request to the FIDO authenticate webservice
                StringResponse(response);
                break;
            case "EMPTY_PARAMETER":
                Common.log(Level.WARNING, "FIDOTUT-ERR-1000", "Did not recieve parameter (adata) from UI");
                break;
            default:
                Common.log(Level.WARNING, "FIDOTUT-ERR-1000", "Invalid HTTP request-path");
                break;
        }
    }

    /**
     * Returns a short description of the servlet.
     * @return String containing name of the application/servlet
     */
    @Override
    public String getServletInfo() {
        return "StrongAuth, Inc.'s StrongKey CryptoEngine POST-FIDO Tutorial AJAX Servlet";
    }

}
