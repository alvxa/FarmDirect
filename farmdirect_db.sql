-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Oct 30, 2026 at 01:43 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `farmdirect_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `audit_log`
--

CREATE TABLE `audit_log` (
  `id` int(11) NOT NULL,
  `admin_id` int(11) NOT NULL,
  `action` varchar(50) NOT NULL,
  `target_id` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `messages`
--

CREATE TABLE `messages` (
  `id` int(11) NOT NULL,
  `sender_id` int(11) NOT NULL,
  `receiver_id` int(11) NOT NULL,
  `product_id` int(11) DEFAULT NULL,
  `body` text NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `messages`
--

INSERT INTO `messages` (`id`, `sender_id`, `receiver_id`, `product_id`, `body`, `created_at`) VALUES
(1, 2, 1, 1, 'HEY', '2026-10-18 15:46:07'),
(2, 2, 1, 1, 'SUNTUKAN TAYO', '2026-10-18 15:46:15'),
(3, 1, 2, 1, 'ARAY KO PO', '2026-10-18 15:46:50'),
(4, 1, 2, 1, 'HAHAHAHAHHAHAHA', '2026-10-18 15:47:05'),
(5, 2, 1, 1, 'guard gising na sya', '2026-10-18 15:47:50'),
(6, 2, 1, 1, 'hi, miss u :(', '2026-10-19 11:33:38'),
(7, 2, 1, 1, 'HEHEEHEHEHE', '2026-10-20 06:02:12'),
(8, 1, 2, 1, 'baliw', '2026-10-20 06:02:51'),
(9, 11, 10, 3, 'enc:HllGmOsQB0TeheNjHztV1hSMA1TJ/XE4y9KwfJ9I', '2026-10-27 07:27:25'),
(10, 10, 11, 3, 'enc:b7w5yB/p5CJjTCKVQCRrQ2oUSih1pwtjAiatwKfjqAg=', '2026-10-28 10:34:39'),
(11, 11, 10, 3, 'enc:SKvlLRQMIbvqS1LdlDfl5sHxyf+VYKUaRQm0K0tig2k=', '2026-10-28 12:32:36');

-- --------------------------------------------------------

--
-- Table structure for table `offers`
--

CREATE TABLE `offers` (
  `id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `buyer_id` int(11) NOT NULL,
  `seller_id` int(11) NOT NULL,
  `quantity` int(11) NOT NULL,
  `price` decimal(10,2) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'Pending',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `offers`
--

INSERT INTO `offers` (`id`, `product_id`, `buyer_id`, `seller_id`, `quantity`, `price`, `status`, `created_at`) VALUES
(1, 1, 2, 1, 1, 100.00, 'Pending', '2026-10-18 15:46:00'),
(2, 3, 11, 10, 1, 592324.00, 'Accepted', '2026-10-28 12:32:49');

-- --------------------------------------------------------

--
-- Table structure for table `orders`
--

CREATE TABLE `orders` (
  `id` int(11) NOT NULL,
  `buyer_id` int(11) NOT NULL,
  `seller_id` int(11) NOT NULL,
  `total` decimal(12,2) NOT NULL DEFAULT 0.00,
  `payment_method` varchar(32) NOT NULL DEFAULT 'COD',
  `status` varchar(32) NOT NULL DEFAULT 'Pending',
  `delivery_name` varchar(120) NOT NULL DEFAULT '',
  `delivery_phone` varchar(40) NOT NULL DEFAULT '',
  `delivery_barangay` varchar(120) NOT NULL DEFAULT '',
  `delivery_street` varchar(255) NOT NULL DEFAULT '',
  `delivery_notes` varchar(255) NOT NULL DEFAULT '',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `order_ref` varchar(32) DEFAULT NULL,
  `fulfillment` varchar(16) NOT NULL DEFAULT 'COD',
  `payment_status` varchar(16) NOT NULL DEFAULT 'Unpaid',
  `paid_at` timestamp NULL DEFAULT NULL,
  `pickup_location` varchar(255) NOT NULL DEFAULT '',
  `pickup_notes` varchar(255) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `orders`
--

INSERT INTO `orders` (`id`, `buyer_id`, `seller_id`, `total`, `payment_method`, `status`, `delivery_name`, `delivery_phone`, `delivery_barangay`, `delivery_street`, `delivery_notes`, `created_at`, `updated_at`, `order_ref`, `fulfillment`, `payment_status`, `paid_at`, `pickup_location`, `pickup_notes`) VALUES
(1, 11, 10, 59.00, 'Cash on Delivery', 'Delivered', 'GD', '09122183348', 'Alsam Ilaya', 'DG', 'DG', '2026-10-28 13:03:28', '2026-10-29 10:18:23', 'FD-20261028-0001', 'COD', 'Paid', '2026-10-29 10:18:11', '', ''),
(2, 11, 10, 295.00, 'Cash on Pickup', 'Confirmed', 'gojo', '09122183348', '', '', '', '2026-10-28 14:08:02', '2026-10-29 10:17:56', 'FD-20261028-0002', 'PICKUP', 'Unpaid', NULL, 'Angeles Zone IV (Pob.), Tayabas City', 'gg');

-- --------------------------------------------------------

--
-- Table structure for table `order_items`
--

CREATE TABLE `order_items` (
  `id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `product_name` varchar(200) NOT NULL DEFAULT '',
  `unit` varchar(50) NOT NULL DEFAULT '',
  `price` decimal(12,2) NOT NULL DEFAULT 0.00,
  `quantity` int(11) NOT NULL DEFAULT 1,
  `image` varchar(255) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `order_items`
--

INSERT INTO `order_items` (`id`, `order_id`, `product_id`, `product_name`, `unit`, `price`, `quantity`, `image`) VALUES
(1, 1, 3, 'Starbucks', 'kg', 59.00, 1, 'uploads/products/3cb3ab0a7b1cfbfddb61.png'),
(2, 2, 3, 'Starbucks', 'kg', 59.00, 5, 'uploads/products/3cb3ab0a7b1cfbfddb61.png');

-- --------------------------------------------------------

--
-- Table structure for table `order_timeline`
--

CREATE TABLE `order_timeline` (
  `id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `status` varchar(32) NOT NULL,
  `note` varchar(255) NOT NULL DEFAULT '',
  `actor_id` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `order_timeline`
--

INSERT INTO `order_timeline` (`id`, `order_id`, `status`, `note`, `actor_id`, `created_at`) VALUES
(1, 2, 'Pending', 'Order placed. Pickup scheduled.', 11, '2026-10-28 14:08:02'),
(2, 2, 'Confirmed', 'Status changed to Confirmed.', 10, '2026-10-29 10:17:56'),
(3, 1, 'Confirmed', 'Status changed to Confirmed.', 10, '2026-10-29 10:18:04'),
(4, 1, 'Paid', 'Cash payment received (Cash on Delivery).', 10, '2026-10-29 10:18:11'),
(5, 1, 'Shipped', 'Status changed to Shipped.', 10, '2026-10-29 10:18:20'),
(6, 1, 'Delivered', 'Delivered — collect cash payment from the buyer.', 10, '2026-10-29 10:18:23');

-- --------------------------------------------------------

--
-- Table structure for table `products`
--

CREATE TABLE `products` (
  `id` int(11) NOT NULL,
  `seller_id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `category` varchar(100) NOT NULL,
  `unit` varchar(50) NOT NULL,
  `price` decimal(10,2) NOT NULL,
  `stock` int(11) NOT NULL,
  `min_order` int(11) NOT NULL,
  `description` text DEFAULT NULL,
  `city` int(11) NOT NULL,
  `images` varchar(255) DEFAULT NULL,
  `barangay` varchar(100) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `street` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `products`
--

INSERT INTO `products` (`id`, `seller_id`, `name`, `category`, `unit`, `price`, `stock`, `min_order`, `description`, `city`, `images`, `barangay`, `created_at`, `street`) VALUES
(1, 1, 'Sukuna', 'Vegetables', 'per kg', 100.00, 12, 1, 'Masarap', 0, '[\"uploads\\/products\\/df53f5933b2f926136f6.png\"]', 'Mateuna', '2026-10-18 08:53:05', 0),
(2, 1, 'Starbucks', 'Dairy', 'per pc', 59.00, 1, 1, 'Masarap', 0, '[\"uploads\\/products\\/ac827b59ea047b79530f.jpg\"]', 'Angeles Zone IV (Pob.)', '2026-10-18 09:40:09', 0),
(3, 10, 'Starbucks', 'Grains', 'per kg', 59.00, 87, 1, 'Ewan', 0, '[\"uploads\\/products\\/3cb3ab0a7b1cfbfddb61.png\"]', 'Angeles Zone IV (Pob.)', '2026-10-27 07:19:42', 0);

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` varchar(10) NOT NULL DEFAULT 'Buyer',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `session_version` int(11) NOT NULL DEFAULT 0,
  `notify_offers` tinyint(4) NOT NULL DEFAULT 1,
  `notify_messages` tinyint(4) NOT NULL DEFAULT 1,
  `email_verified` tinyint(4) NOT NULL DEFAULT 0,
  `verify_token` varchar(64) DEFAULT NULL,
  `verify_expires` datetime DEFAULT NULL,
  `profile_pic` varchar(255) DEFAULT NULL,
  `is_suspended` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password`, `role`, `created_at`, `session_version`, `notify_offers`, `notify_messages`, `email_verified`, `verify_token`, `verify_expires`, `profile_pic`, `is_suspended`) VALUES
(10, 'Kaye', 'alexakayemendez@gmail.com', '$2y$10$PI/csxL7Ru52MKMv3fortOvPQrU0aSVK4qe.ZhOos/6NR8GfnHwbK', 'Seller', '2026-10-27 07:17:58', 0, 1, 1, 1, NULL, NULL, 'uploads/profiles/profile_10_1793177647.jpg', 0),
(11, 'Cole', 'cole@gmail.com', '$2y$10$RW2A6WAwXOBdjH/D.F6CH.qRTGBIOTq1GXrPe0Hu5amzznSbgKz/y', 'Buyer', '2026-10-27 07:21:47', 0, 1, 1, 1, NULL, NULL, NULL, 0),
(14, 'admin', 'farmdirect@gmail.com', '$2y$10$hAWsuN9Ai6GQWZPttWR8.OFL9giqmPXb5T2ZE0EH5BfWaBt1dCErq', 'Admin', '2026-10-28 10:18:58', 0, 1, 1, 1, NULL, NULL, NULL, 0),
(16, 'jaynelyn', 'jaynelyncole@gmail.com', '$2y$10$BdRK0Klm7qFH9nZoMRHsi.7ENVVawUkq./O4DX2gvn0oZ.miHWocq', 'Buyer', '2026-10-30 00:21:49', 0, 1, 1, 0, 'c7c847fe5cab4c0ff540f9eb85267fdec8151c1ef9f3ec7afe7a832e1ab26590', '2026-10-31 01:21:49', NULL, 0);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `audit_log`
--
ALTER TABLE `audit_log`
  ADD PRIMARY KEY (`id`),
  ADD KEY `admin_id` (`admin_id`),
  ADD KEY `created_at` (`created_at`);

--
-- Indexes for table `messages`
--
ALTER TABLE `messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `sender_id` (`sender_id`),
  ADD KEY `receiver_id` (`receiver_id`);

--
-- Indexes for table `offers`
--
ALTER TABLE `offers`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `orders`
--
ALTER TABLE `orders`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_buyer` (`buyer_id`),
  ADD KEY `idx_seller` (`seller_id`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_orders_order_ref` (`order_ref`);

--
-- Indexes for table `order_items`
--
ALTER TABLE `order_items`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_order` (`order_id`),
  ADD KEY `idx_product` (`product_id`);

--
-- Indexes for table `order_timeline`
--
ALTER TABLE `order_timeline`
  ADD PRIMARY KEY (`id`),
  ADD KEY `order_id` (`order_id`);

--
-- Indexes for table `products`
--
ALTER TABLE `products`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `audit_log`
--
ALTER TABLE `audit_log`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `messages`
--
ALTER TABLE `messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- AUTO_INCREMENT for table `offers`
--
ALTER TABLE `offers`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `orders`
--
ALTER TABLE `orders`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `order_items`
--
ALTER TABLE `order_items`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `order_timeline`
--
ALTER TABLE `order_timeline`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `products`
--
ALTER TABLE `products`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
