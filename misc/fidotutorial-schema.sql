/**
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License, as published by the Free Software Foundation and
 *  available at http://www.fsf.org/licensing/licenses/lgpl.html,
 *  version 2.1 or above.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Lesser General Public License for more details.
 *
 * Copyright (c) 2001-2015 StrongAuth
 *
 * $Date: 2015-10-02 15:09:15 -0700 (Fri, 02 Oct 2015) $
 * $Revision: 86 $
 * $Author: jpadavala $
 * $URL: https://svn.strongauth.com/repos/jade/trunk/FIDOTutorial-Eclipse/FIDOTutorial/misc/fidotutorial-schema.sql $
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
 * SQL file to create the CUSTOMERS and USERS tables in the 
 * FIDOTUTORIAL database, for use with StrongKey CryptoEngine.
 *  
 */

CREATE TABLE `CUSTOMERS` (
    `CID` 	   smallint NOT NULL,
    `NAME` 	   varchar(64),
    `ADDRESSLINE1` varchar(64),
    `ADDRESSLINE2` varchar(64),
    `CITY` 	   varchar(64),
    `STATE` 	   varchar(16),
    `ZIP` 	   varchar(9) NOT NULL,
    `PHONE` 	   varchar(15),
    `EMAIL` 	   varchar(256),
  PRIMARY KEY (`CID`),
  UNIQUE KEY `NAME` (`NAME`)
) ENGINE=InnoDB;

INSERT INTO `CUSTOMERS` VALUES 
(1,'StrongAuth, Inc.','150 W Iowa Ave','Suite 204','Sunnyvale',
	'CA','94086','4083312000','info@strongauth.com'),
(2,'Acme Anvils, Inc.','123 Main Street','Suite 100','Mesa',
	'CA','90210','1235551212','ylekyote@acmeanvils.com');

CREATE TABLE `USERS` (
    `USERNAME` 	   varchar(32),
    `PASSWORD` 	   varchar(32),
  PRIMARY KEY (`USERNAME`)
) ENGINE=InnoDB;

/* EOF */
