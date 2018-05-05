<%--
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
 * $URL: https://svn.strongauth.com/repos/jade/trunk/FIDOTutorial-Eclipse/FIDOTutorial/misc/fidoregister.jsp $
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
 *  JSP to allow users who have logged into register a token
 */
--%>
<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Register your FIDO 2.0 token | CRUD application</title>
        <link rel="stylesheet" type="text/css" href="css/bootstrap.css">
    </head>
    <body>


        <div class="container well">
            <div class="row">
                <div class="col-md-1"></div>
                <div class="col-md-10">
                    <div class="row">
                        <h1 class="text-center">Register your FIDO Token for user: <c:out value="${sessionScope.username}"/></h1>
                        <div class="col-md-2"></div>
                        <div class="col-md-8">

                            <p><a href="logout">Log out as  <c:out value="${sessionScope.username}" /></a></p>
                            <p><strong>To register using your token, you must use the following:</strong></p>
                            <ol>
                                <li>Chrome Version 43 or higher.
                                    <a href="http://www.google.com/chrome/browser" target="_blank">
                                        Download from here
                                    </a>
                                </li>
                                <li>Your FIDO U2F authenticator</li>
                            </ol>
                            <div class="text-center">
                                <button type="button" name="register" id="register">Click to begin registration</button>
                            </div>
                            <br>
                            <div id="msg"></div>
                        </div>
                        <div class="col-md-2"></div>
                    </div>
                    <div class="row text-center">Copyright &COPY; <a href="http://www.strongauth.com" target="_blank"><img title="StrongAuth, Inc." src="img/strongauth_logo_200.png" width="60" alt="StrongAuth, Inc."/></a> 2001 - <span id="year"></span></div>
                </div>
                <div class="col-md-1"></div>
            </div>
        </div>





        <input type="hidden" value="${sessionScope.username}" id="uname">
        <script src="js/jquery-2.0.0.min.js" type="text/javascript"></script>
        <script src="js/FIDOAJAXMethods.js" type="text/javascript"></script>
        <script src="js/common.js" type="text/javascript"></script>
        <script src="js/u2f-api.js" type="text/javascript"></script>
        <script src="js/enrolldata.js" type="text/javascript"></script>
        <script type="text/javascript">
            document.getElementById("year").innerHTML = new Date().getFullYear();

            $(document).ready(function () {

                var uname = $("#uname").val();
                console.log(uname);
                //If username exists in the session, show user the register token button.
                if (uname.length !== 0) {
                    //show user the register token button.
                    $("#register").show();
                }
                else {
                    //else hide it.
                    $("#register").hide();
                    $("#msg").empty().removeClass().addClass("alert alert-danger")
                    .append($('<a>').addClass("alert-link").attr('href', 'logout')
                    .append("Sorry, we encountered an unknown error. Click here to logout and then try again."));
                }

                $("#register").click(function () {
                    //check if chrome is being used
                    if (isChromeCorrect()) {
                        //initialize the fidoaction object
                        var f1 = new fidoaction("preregister", "register", "", "");
                        //call the preregister web-service call through the fidoaction object
                        f1.preaction(uname, "preregister").then(function (data) {
                            //parse the response received from the SKCE server
                            var gd = f1.prResp(data);
                            console.log(gd);
                            console.log("Confirm user presence");
                            $("#msg").empty().removeClass().addClass("alert alert-info")
                            .append($('<span>').addClass("alert-link")
                            .append("Please confirm user presence").addClass("strong"),
                            $('<img>').attr({'src': 'img/loading.gif'}));
                            //Call the inbuilt chrome extension
                            u2f.register([gd.enrollData],
                            gd.signData, function (result) {
                                //If an error was returned
                                if (result.errorCode) {
                                    console.log("Error " + result.errorCode);
                                    //Print the error on the JSP
                                    $("#msg").empty().removeClass().addClass("alert alert-danger")
                                    .append($('<span>').append(onError(result.errorCode, true))
                                    .addClass("alert-link"));
                                }
                                else {
                                    //call the register web-service
                                    f1.CallRegisterWS(result).then(function (retMsg) {
                                        console.log(retMsg);
                                        if (retMsg) {
                                            //If successful, ask the user to log-in again.
                                            if (retMsg.Response.indexOf("Success") !== -1) {
                                                $("#msg").empty().removeClass().addClass("alert alert-success").append(
                                                $('<a>').addClass("alert-link").attr('href', 'login.jsp').append("Successfully registered token. Click here to login again.")
                                                );
                                            }
                                            else {
                                                $("#msg").empty().removeClass().addClass("alert alert-danger").text(retMsg);
                                            }
                                        } else {
                                            $("#msg").empty().removeClass().addClass("alert alert-danger").text("No response returned from the server");
                                        }
                                    }, function (jqXHR, textStatus, errorThrown) {
                                        console.log("Error " + jqXHR.responseText);
                                    });
                                }
                            });
                        }, function (jqXHR, textStatus, errorThrown) {
                            console.log("Error " + jqXHR.responseText);
                        });
                    }
                    else {
                        console.log("Please use Chrome 43 or higher to run this application.");
                        $("#msg").empty().removeClass().addClass("alert alert-danger").append($('<a>').addClass("alert-link").attr({'href': 'http://www.google.com/chrome/browser', 'target': '_blank'}).append("Click here to download the latest Chrome. You need Chrome 43 or higher to run this application."));
                    }
                });
            });
        </script>
    </body>
</html>
