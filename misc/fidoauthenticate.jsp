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
 * $URL: https://svn.strongauth.com/repos/jade/trunk/FIDOTutorial-Eclipse/FIDOTutorial/misc/fidoauthenticate.jsp $
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
 *  JSP to authenticate a token after the user has successfully logged in
 */
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Authenticate using your FIDO 2.0 token</title>
        <link rel="stylesheet" type="text/css" href="css/bootstrap.css">
    </head>
    <body>


        <div class="container well">
            <div class="row">
                <div class="col-md-1"></div>
                <div class="col-md-10">
                    <div class="row">
                        <h1 class="text-center">Authenticate using your token for  <c:out value="${sessionScope.username}" /></h1>
                        <div class="col-md-3"></div>
                        <div class="col-md-7">

                            <p><a href="logout">Log out as  <c:out value="${sessionScope.username}" /></a></p>
                            <p><strong>To authenticate using your token, you must use the following:</strong></p>
                            <ol>
                                <li>Chrome Version 43 or higher.
                                    <a href="http://www.google.com/chrome/browser" target="_blank">
                                        Download from here
                                    </a>
                                </li>
                                <li>Your FIDO U2F authenticator</li>
                            </ol>
                            <div class="text-center">
                                <button type="button" name="authenticate" id="authenticate">Click to begin authentication</button>

                            </div>

                            <div id="msg">
                            </div>
                        </div>
                        <div class="col-md-2"></div>
                    </div>
                    <div class="row text-center">Copyright &COPY; <a href="http://www.strongauth.com" target="_blank"><img title="StrongAuth, Inc." src="img/strongauth_logo_200.png" width="60" alt="StrongAuth, Inc."/></a> 2001 - <span id="year"></span></div>
                </div>
                <div class="col-md-1"></div>
            </div>
        </div>

        <form action="index" method="GET" id="indexPage"></form>
        <input type="hidden" value="${sessionScope.username}" id="uname">
        <script src="js/jquery-2.0.0.min.js" type="text/javascript"></script>
        <script src="js/FIDOAJAXMethods.js"></script>
        <script src="js/common.js" type="text/javascript"></script>
        <script src="js/u2f-api.js" type="text/javascript"></script>
        <script src="js/enrolldata.js" type="text/javascript"></script>
        <script type="text/javascript">
            document.getElementById("year").innerHTML = new Date().getFullYear();

            $("#authenticate").click(function () {
                //check if chrome is being used
                if (isChromeCorrect()) {
                    //initialize the fidoaction object
                    var f1 = new fidoaction("", "", "preauthenticate", "authenticate");
                    //call the preauthenticate web-service call through the fidoaction object
                    f1.preaction(uname, "preauthenticate").then(function (data) {
                        //parse the response received from the SKCE server
                        var gd = f1.paResp(data);
                        console.log(gd);
                        //If signDataArray is not null
                        if (gd.signDataArray) {
                            //if a signDataArray is greater than 1 i.e. if there are keys found for the user
                            if (gd.signDataArray.length > 0) {
                                var sda = gd.signDataArray;
                                //Change UI to confirm user presence
                                console.log("Going to send to Gnubby....");
                                console.log(sda);
                                console.log("Please confirm user presence");
                                $("#msg").empty().addClass("alert alert-info").append(
                                $('<span>').append("Please confirm user presence NOW").addClass("alert-link"),
                                $('<img>').attr({'src': 'img/loading.gif'}));

                                // Store sessionIds
                                var sessionIds = {};
                                for (var i = 0; i < sda.length; i++) {
                                    sessionIds[sda[i].keyHandle] = sda[i].sessionId;
                                    delete sda[i]['sessionId'];
                                }
                                //Call the inbuilt chrome extension
                                u2f.sign(sda, function (response) {
                                    //If an error was returned
                                    if (response.errorCode) {
                                        if (response.errorCode === 5) {
                                            //display the authentication button
                                            $("#authenticate").show();
                                        }
                                        var res = onError(response.errorCode, false);
                                        if (res.indexOf("NOTREGISTERED") !== -1) {
                                            $("#msg").empty().removeClass().addClass("alert alert-danger").append(
                                            $('<a>')
                                            .addClass("alert-link")
                                            .attr({'href': 'fidoregister.jsp'})
                                            .append("This U2F token is not yet registered. Click here to register this token.")
                                            );
                                        } else {
                                            $("#msg").empty().removeClass().addClass("alert alert-danger").append(
                                            $('<a>')
                                            .attr({'href': 'fidoauthenticate'})
                                            .addClass("alert-link")
                                            .append(res)
                                            );

                                        }


                                    } else {
                                        //call the authenticate web-service
                                        console.log("Going to send to server");
                                        f1.CallAuthenticateWS(response, sessionIds).then(function (retMsg) {
                                            console.log(retMsg);
                                            if (retMsg) {
                                                if (retMsg.Response.indexOf("Success") !== -1) {
                                                    //redirect to dashboard
                                                    //                                                    $("#msg").text(retMsg.Response).append($('<a>').attr('href', 'index').append("Go to the home page"));
                                                    $("#indexPage").submit();
                                                }
                                                else {
                                                    $("#msg").empty().removeClass().addClass("alert alert-danger").text(retMsg.Response);
                                                }
                                            } else {
                                                $("#msg").empty().removeClass().addClass("alert alert-danger").text("No response returned from the server");

                                            }
                                        },
                                        function (jqXHR, textStatus, errorThrown) {
                                            console.log("Error " + jqXHR.responseText);
                                        }
                                        );
                                    }
                                });
                            }
                            else {
                                //alert user that there are no keys associated with this account
                                console.log("Could not find any keys associated with this account.");
                                $("#msg").empty().removeClass().addClass("alert alert-danger").append($('<a>').addClass("alert-link").append("Click here to register a key. This one is not registered with this account.").attr({'href': 'fidoregister.jsp'}));
                            }
                        }
                        else {
                            //alert user that signDataArray is empty
                            $("#msg").empty().removeClass().html(gd);
                        }

                    }, function (jqXHR, textStatus, errorThrown) {
                        console.log("Error " + jqXHR.responseText);
                    });
                }
                else {
                    //ask user to download the correct Chrome version
                    console.log("Please use Chrome 43 or higher to run this application.");
                    $("#msg").empty().removeClass().addClass("alert alert-danger").append($('<a>').addClass("alert-link").attr({'href': 'http://www.google.com/chrome/browser', 'target': '_blank'}).append("Click here to download the latest Chrome. You need Chrome 43 or higher to run this application."));

                }
            });

            var uname = $("#uname").val();
            console.log(uname);
            $("#authenticate").hide();
            //If user was added successfully, show user the register token button.
            if (uname.length !== 0) {
                //click the authenticate token button.
                $("#authenticate").click();
            }
            else {
                $("#msg").empty().removeClass().addClass("alert alert-danger").append($('<a>').attr('href', 'logout')
                .addClass("alert-link").append("Sorry, there was an unknown error. Click here to logout and then try again."));
            }
        </script>
    </body>
</html>
