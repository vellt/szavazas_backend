-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Gép: 127.0.0.1
-- Létrehozás ideje: 2026. Már 18. 10:47
-- Kiszolgáló verziója: 10.4.28-MariaDB
-- PHP verzió: 8.2.4

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Adatbázis: `szavazas`
--
CREATE DATABASE IF NOT EXISTS `szavazas` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `szavazas`;

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `felhasznalok`
--

DROP TABLE IF EXISTS `felhasznalok`;
CREATE TABLE `felhasznalok` (
  `id` int(10) UNSIGNED NOT NULL,
  `email` varchar(255) NOT NULL,
  `felhasznalonev` varchar(255) NOT NULL,
  `jelszo` varchar(255) NOT NULL,
  `admin` tinyint(4) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- A tábla adatainak kiíratása `felhasznalok`
--

INSERT INTO `felhasznalok` (`id`, `email`, `felhasznalonev`, `jelszo`, `admin`) VALUES
(1, 'ujemail@email.com', 'teszt', '$2b$10$/Uu5qz5rxfAW9yByA39k8OjnCNbWbkns0RLz.d2D3GbZ4Cw9ABOyS', 1),
(2, 'ujemail4@email.com', 'teszt2', '$2b$10$SXbA.CNwuSwY9gMV/f/0xuJHmxObg/Z2CD0eiOghxWhsu8n.41BGW', 1),
(3, 'tesztelek3@teszt.hu', 'tesztelek3', '$2b$10$NihlUsJdQFAJTe6HcH6TeefNiiPZotZa/nv22v9Fhh5zL5acaS2si', 0),
(4, 'teszt6@gmail.com', 'tesztalak', '$2b$10$.QuotNjy4stuqAbB66YQIuM0UcFja7.DJfkG6iDLMkYRd1i0lrZme', 1),
(5, 'tesztelek5@teszt.hu', 'tesztelek', '$2b$10$6jYX/e79FUZdI8UXYg9qH.4Lb7Zqg2OiNHBHik8HPdIhMqV3C1o16', 0);

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `kepek`
--

DROP TABLE IF EXISTS `kepek`;
CREATE TABLE `kepek` (
  `felhasznalo_id` int(10) UNSIGNED NOT NULL,
  `zsuri_id` int(10) UNSIGNED NOT NULL,
  `kep_neve` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- A tábla adatainak kiíratása `kepek`
--

INSERT INTO `kepek` (`felhasznalo_id`, `zsuri_id`, `kep_neve`) VALUES
(2, 1, '1773222625681.png'),
(2, 2, '1773222982313.png');

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `szavazasok`
--

DROP TABLE IF EXISTS `szavazasok`;
CREATE TABLE `szavazasok` (
  `felhasznalo_id` int(10) UNSIGNED NOT NULL,
  `zsuri_id` int(10) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Tábla szerkezet ehhez a táblához `zsurik`
--

DROP TABLE IF EXISTS `zsurik`;
CREATE TABLE `zsurik` (
  `id` int(10) UNSIGNED NOT NULL,
  `nev` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- A tábla adatainak kiíratása `zsurik`
--

INSERT INTO `zsurik` (`id`, `nev`) VALUES
(1, 'Curtis'),
(2, 'Herceg Erika'),
(3, 'Marics Peti'),
(4, 'Tóth Gabi');

--
-- Indexek a kiírt táblákhoz
--

--
-- A tábla indexei `felhasznalok`
--
ALTER TABLE `felhasznalok`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `felhasznalok_email_unique` (`email`),
  ADD UNIQUE KEY `felhasznalok_felhasznalonev_unique` (`felhasznalonev`);

--
-- A tábla indexei `kepek`
--
ALTER TABLE `kepek`
  ADD KEY `kepek_felhasznalo_id_index` (`felhasznalo_id`),
  ADD KEY `kepek_zsuri_id_index` (`zsuri_id`);

--
-- A tábla indexei `szavazasok`
--
ALTER TABLE `szavazasok`
  ADD KEY `szavazasok_felhasznalo_id_index` (`felhasznalo_id`),
  ADD KEY `szavazasok_zsuri_id_index` (`zsuri_id`);

--
-- A tábla indexei `zsurik`
--
ALTER TABLE `zsurik`
  ADD PRIMARY KEY (`id`);

--
-- A kiírt táblák AUTO_INCREMENT értéke
--

--
-- AUTO_INCREMENT a táblához `felhasznalok`
--
ALTER TABLE `felhasznalok`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT a táblához `zsurik`
--
ALTER TABLE `zsurik`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- Megkötések a kiírt táblákhoz
--

--
-- Megkötések a táblához `kepek`
--
ALTER TABLE `kepek`
  ADD CONSTRAINT `kepek_felhasznalo_id_foreign` FOREIGN KEY (`felhasznalo_id`) REFERENCES `felhasznalok` (`id`),
  ADD CONSTRAINT `kepek_zsuri_id_foreign` FOREIGN KEY (`zsuri_id`) REFERENCES `zsurik` (`id`);

--
-- Megkötések a táblához `szavazasok`
--
ALTER TABLE `szavazasok`
  ADD CONSTRAINT `szavazasok_felhasznalo_id_foreign` FOREIGN KEY (`felhasznalo_id`) REFERENCES `felhasznalok` (`id`),
  ADD CONSTRAINT `szavazasok_zsuri_id_foreign` FOREIGN KEY (`zsuri_id`) REFERENCES `zsurik` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
