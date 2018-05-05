/**
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License, as published by the Free Software Foundation and
 * available at http://www.fsf.org/licensing/licenses/lgpl.html,
 * version 2.1 or above.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * Copyright (c) 2001-2012 StrongAuth, Inc.
 *
 ***********************************************
 *
 *  888b    888          888
 *  8888b   888          888
 *  88888b  888          888
 *  888Y88b 888  .d88b.  888888  .d88b.  .d8888b
 *  888 Y88b888 d88""88b 888    d8P  Y8b 88K
 *  888  Y88888 888  888 888    88888888 "Y8888b.
 *  888   Y8888 Y88..88P Y88b.  Y8b.          X88
 *  888    Y888  "Y88P"   "Y888  "Y8888   88888P'
 *
 ************************************************
 * $Date:
 * $Revision:
 * $Author
 * $URL:
 *******************************************************
 * JavaScript Object to hold EnrollData Object.
 */

/*
 * 8888888          d8b 888    d8b          888 d8b                   888    d8b
 *   888            Y8P 888    Y8P          888 Y8P                   888    Y8P
 *   888                888                 888                       888
 *   888   88888b.  888 888888 888  8888b.  888 888 88888888  8888b.  888888 888  .d88b.  88888b.
 *   888   888 "88b 888 888    888     "88b 888 888    d88P      "88b 888    888 d88""88b 888 "88b
 *   888   888  888 888 888    888 .d888888 888 888   d88P   .d888888 888    888 888  888 888  888
 *   888   888  888 888 Y88b.  888 888  888 888 888  d88P    888  888 Y88b.  888 Y88..88P 888  888
 * 8888888 888  888 888  "Y888 888 "Y888888 888 888 88888888 "Y888888  "Y888 888  "Y88P"  888  888
 */
/*
 * Initializing the values of the object.
 */
var enrollData = {
sessionId: null,
appId: null,
challenge: null,
version: null
};