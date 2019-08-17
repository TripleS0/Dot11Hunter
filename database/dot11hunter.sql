-- MySQL dump 10.17  Distrib 10.3.14-MariaDB, for debian-linux-gnueabihf (armv8l)
--
-- Host: localhost    Database: dot11_hunter
-- ------------------------------------------------------
-- Server version	10.3.14-MariaDB-1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `ap`
--

DROP TABLE IF EXISTS `ap`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ap` (
  `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `ssid` varchar(32) DEFAULT NULL COMMENT 'name of ap',
  `mac_id` mediumint(8) unsigned DEFAULT NULL,
  `first_seen` timestamp NULL DEFAULT NULL COMMENT 'first time when this AP was sniffered. Since it may be from probe request, thus this cannot depend on first_time in mac.',
  `last_seen` timestamp NULL DEFAULT NULL COMMENT 'last time when this AP was sniffered. Since it may be from probe request, thus this cannot depend on first_time in mac.',
  `count` mediumint(8) unsigned NOT NULL COMMENT 'how many times this ssid was detected',
  `from_probe_req` tinyint(3) unsigned DEFAULT NULL COMMENT 'True: the ap info is extracted from probe request',
  `from_probe_resp` tinyint(3) unsigned DEFAULT NULL COMMENT 'True: the ap info is extracted from probe response',
  `from_beacon` tinyint(3) unsigned DEFAULT NULL COMMENT 'True: the ap info is extracted from beacon',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=18322 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `association`
--

DROP TABLE IF EXISTS `association`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `association` (
  `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `mac_id` mediumint(8) unsigned NOT NULL COMMENT 'mac address of station',
  `ap_id` mediumint(8) unsigned NOT NULL,
  `first_seen` timestamp NULL DEFAULT NULL COMMENT 'date when the addr was first seen',
  `last_seen` timestamp NULL DEFAULT NULL COMMENT 'date when the addr was last seen',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=311490 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `geo`
--

DROP TABLE IF EXISTS `geo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `geo` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `mac_id` mediumint(8) unsigned NOT NULL,
  `latitude` decimal(9,6) DEFAULT NULL COMMENT 'latitude',
  `longitude` decimal(9,6) DEFAULT NULL COMMENT 'longitude',
  `seen` timestamp NULL DEFAULT NULL COMMENT ' date seen',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12730 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mac`
--

DROP TABLE IF EXISTS `mac`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `mac` (
  `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT COMMENT 'MAC address sniffered',
  `addr` bigint(20) unsigned NOT NULL,
  `first_seen` timestamp NULL DEFAULT NULL COMMENT 'date when the addr was first seen',
  `last_seen` timestamp NULL DEFAULT NULL COMMENT 'date when the addr was last seen',
  `count` mediumint(8) unsigned NOT NULL COMMENT 'how many times this mac address was detected',
  `oui_id` smallint(5) unsigned DEFAULT NULL,
  `from_mgmt` tinyint(3) unsigned DEFAULT NULL COMMENT 'True: if this mac addr is from management frame',
  `from_data` tinyint(3) unsigned DEFAULT NULL COMMENT 'True: if this mac addr sent data',
  `from_ctrl` tinyint(3) unsigned DEFAULT NULL COMMENT 'True: if this mac addr sent data',
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=269733 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `oui`
--

DROP TABLE IF EXISTS `oui`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `oui` (
  `id` smallint(5) unsigned NOT NULL AUTO_INCREMENT COMMENT 'Total number of OUI from wireshark is  36985.',
  `ouicol` mediumint(8) unsigned NOT NULL COMMENT 'Three octets',
  `name` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `ouicol_UNIQUE` (`ouicol`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2019-08-17 22:36:38
