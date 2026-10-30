<?php
session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax']);
session_start();
require 'connect.php';

// --- ENCRYPTION (AES-256-GCM para sa laman ng messages) ---
function app_key() { return hash('sha256', defined('APP_KEY') ? APP_KEY : 'change-this-key-in-connect-php', true); }
function enc_text($plain) {
    $iv = random_bytes(12); $tag = '';
    $c = openssl_encrypt($plain, 'aes-256-gcm', app_key(), OPENSSL_RAW_DATA, $iv, $tag);
    return 'enc:' . base64_encode($iv . $tag . $c);
}
function dec_text($s) {
    if (strpos($s, 'enc:') !== 0) return $s;
    $raw = base64_decode(substr($s, 4));
    $p = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', app_key(), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
    return $p === false ? '[unable to decrypt]' : $p;
}

// --- EMAIL VERIFICATION ---
function send_verification($email, $username, $token) {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $link = $scheme . '://' . $_SERVER['HTTP_HOST'] . strtok($_SERVER['REQUEST_URI'], '?') . '?verify=' . $token;
    $body = "Hi $username,\n\nClick this link to verify your FarmDirect email:\n$link\n\nThis link expires in 24 hours.\nIf you did not sign up, ignore this email.";
    $sent = @mail($email, 'Verify your FarmDirect account', $body, "From: no-reply@farmdirect.local");
    return [$sent, $link];
}

function api_prepare($conn, $sql) {
    $s = $conn->prepare($sql);
    if (!$s) { echo json_encode(['error' => 'Database error: ' . $conn->error]); exit(); }
    return $s;
}

// --- ADMIN AUDIT LOG HELPER ---
function admin_log($conn, $admin_id, $action, $target_id = null) {
    try {
        $s = $conn->prepare("INSERT INTO audit_log (admin_id, action, target_id) VALUES (?, ?, ?)");
        if (!$s) return;
        $s->bind_param("isi", $admin_id, $action, $target_id);
        $s->execute(); $s->close();
    } catch (Throwable $e) { /* silent — audit must never break user flow */ }
}

// --- ORDER REFERENCE GENERATOR ---
function gen_order_ref($conn, $orderId) {
    return 'FD-' . date('Ymd') . '-' . str_pad((string)$orderId, 4, '0', STR_PAD_LEFT);
}

// --- ORDER TIMELINE HELPER ---
function order_timeline_add($conn, $orderId, $status, $note = '', $actorId = null) {
    try {
        $s = $conn->prepare("INSERT INTO order_timeline (order_id, status, note, actor_id) VALUES (?, ?, ?, ?)");
        if (!$s) return;
        $s->bind_param("issi", $orderId, $status, $note, $actorId);
        $s->execute(); $s->close();
    } catch (Throwable $e) { /* silent */ }
}

// --- ENSURE ORDER TABLES EXIST (auto-migrate, safe to run repeatedly) ---
function ensure_order_schema($conn) {
    try {
        // Base orders table
        $conn->query("CREATE TABLE IF NOT EXISTS orders (
            id INT AUTO_INCREMENT PRIMARY KEY,
            order_ref VARCHAR(32) DEFAULT NULL,
            buyer_id INT NOT NULL,
            seller_id INT NOT NULL,
            total DECIMAL(12,2) NOT NULL DEFAULT 0,
            fulfillment VARCHAR(16) NOT NULL DEFAULT 'COD',
            payment_method VARCHAR(32) NOT NULL DEFAULT 'Cash on Delivery',
            payment_status VARCHAR(16) NOT NULL DEFAULT 'Unpaid',
            paid_at TIMESTAMP NULL DEFAULT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'Pending',
            delivery_name VARCHAR(120) NOT NULL DEFAULT '',
            delivery_phone VARCHAR(40) NOT NULL DEFAULT '',
            delivery_barangay VARCHAR(120) NOT NULL DEFAULT '',
            delivery_street VARCHAR(255) NOT NULL DEFAULT '',
            delivery_notes VARCHAR(255) NOT NULL DEFAULT '',
            pickup_location VARCHAR(255) NOT NULL DEFAULT '',
            pickup_notes VARCHAR(255) NOT NULL DEFAULT '',
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX (buyer_id), INDEX (seller_id), INDEX (status), INDEX (order_ref)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Order items
        $conn->query("CREATE TABLE IF NOT EXISTS order_items (
            id INT AUTO_INCREMENT PRIMARY KEY,
            order_id INT NOT NULL,
            product_id INT NOT NULL,
            product_name VARCHAR(200) NOT NULL DEFAULT '',
            unit VARCHAR(50) NOT NULL DEFAULT '',
            price DECIMAL(12,2) NOT NULL DEFAULT 0,
            quantity INT NOT NULL DEFAULT 1,
            image VARCHAR(255) NOT NULL DEFAULT '',
            INDEX (order_id), INDEX (product_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Timeline / audit trail per order
        $conn->query("CREATE TABLE IF NOT EXISTS order_timeline (
            id INT AUTO_INCREMENT PRIMARY KEY,
            order_id INT NOT NULL,
            status VARCHAR(32) NOT NULL,
            note VARCHAR(255) NOT NULL DEFAULT '',
            actor_id INT NULL DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX (order_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // --- Safe column additions for existing installs (MySQL 5.7+/MariaDB 10.2+) ---
        $add_cols = [
            'order_ref'        => "ALTER TABLE orders ADD COLUMN order_ref VARCHAR(32) DEFAULT NULL",
            'fulfillment'      => "ALTER TABLE orders ADD COLUMN fulfillment VARCHAR(16) NOT NULL DEFAULT 'COD'",
            'payment_status'   => "ALTER TABLE orders ADD COLUMN payment_status VARCHAR(16) NOT NULL DEFAULT 'Unpaid'",
            'paid_at'          => "ALTER TABLE orders ADD COLUMN paid_at TIMESTAMP NULL DEFAULT NULL",
            'pickup_location'  => "ALTER TABLE orders ADD COLUMN pickup_location VARCHAR(255) NOT NULL DEFAULT ''",
            'pickup_notes'     => "ALTER TABLE orders ADD COLUMN pickup_notes VARCHAR(255) NOT NULL DEFAULT ''",
        ];
        foreach ($add_cols as $col => $sql) {
            $r = $conn->query("SHOW COLUMNS FROM orders LIKE " . $conn->real_escape_string("'$col'"));
            if ($r && $r->num_rows === 0) {
                @$conn->query($sql);
            }
        }
        // Change payment_method default label for legacy rows
        @$conn->query("UPDATE orders SET payment_method = 'Cash on Delivery' WHERE payment_method = 'COD'");
    } catch (Throwable $e) { /* tables may already exist */ }
}
ensure_order_schema($conn);

if (isset($_SESSION['user_id'])) {
    try {
        $svq = $conn->query("SELECT session_version, role FROM users WHERE id = " . (int)$_SESSION['user_id']);
        if ($svq) {
            $svr = $svq->fetch_assoc();
            if (!$svr || (isset($_SESSION['sv']) && (int)$_SESSION['sv'] !== (int)$svr['session_version'])) {
                session_unset();
            } else {
                // Keep role in sync with DB (in case admin promoted/demoted someone)
                $_SESSION['role'] = $svr['role'];
            }
        }
    } catch (Throwable $e) { }
}

if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    if (!isset($_SESSION['user_id'])) { echo json_encode(['error' => 'Please log in first.']); exit(); }
    $me = (int)$_SESSION['user_id'];
    $role = $_SESSION['role'] ?? '';
    $api = $_GET['api'];
    $out = ['error' => 'Unknown action.'];

    // ============================================================
    // ADMIN GUARD — placed as a single helper used below
    // ============================================================
    $require_admin = function() use ($role) {
        if ($role !== 'Admin') {
            echo json_encode(['error' => 'Unauthorized.']);
            exit();
        }
    };
    // Used by transactor APIs — blocks admin from acting as buyer/seller
    $block_admin = function() use ($role) {
        if ($role === 'Admin') {
            echo json_encode(['error' => 'Administrators cannot perform marketplace transactions.']);
            exit();
        }
    };

    // ============================================================
    // EXISTING ENDPOINTS (with added role guards where relevant)
    // ============================================================
    if ($api === 'send_offer') {
        $block_admin();
        $pid = (int)($_POST['product_id'] ?? 0);
        $qty = (int)($_POST['quantity'] ?? 0);
        $price = (float)($_POST['price'] ?? 0);
        $s = api_prepare($conn, "SELECT seller_id, stock FROM products WHERE id = ?");
        $s->bind_param("i", $pid); $s->execute();
        $p = $s->get_result()->fetch_assoc(); $s->close();
        if (!$p) $out = ['error' => 'Product not found.'];
        elseif ((int)$p['seller_id'] === $me) $out = ['error' => "You can't make an offer on your own product."];
        elseif ($qty < 1 || $price <= 0) $out = ['error' => 'Enter a valid quantity and price.'];
        elseif ($qty > (int)$p['stock']) $out = ['error' => 'Not enough stock.'];
        else {
            $sid = (int)$p['seller_id'];
            $s = api_prepare($conn, "INSERT INTO offers (product_id, buyer_id, seller_id, quantity, price) VALUES (?, ?, ?, ?, ?)");
            $s->bind_param("iiiid", $pid, $me, $sid, $qty, $price);
            $out = $s->execute() ? ['ok' => true] : ['error' => 'Could not send the offer.'];
            $s->close();
        }
    } elseif ($api === 'offers') {
        $block_admin();
        $seller = ($role === 'Seller');
        $mine = $seller ? 'seller_id' : 'buyer_id';
        $other = $seller ? 'buyer_id' : 'seller_id';
        $s = api_prepare($conn, "SELECT o.id, o.product_id, o.quantity, o.price, o.status, o.created_at, o.$other AS other_id, u.username AS other_name, p.name, p.unit, p.images FROM offers o JOIN products p ON p.id = o.product_id JOIN users u ON u.id = o.$other WHERE o.$mine = ? ORDER BY o.id DESC");
        $s->bind_param("i", $me); $s->execute();
        $rows = $s->get_result()->fetch_all(MYSQLI_ASSOC); $s->close();
        foreach ($rows as &$r) {
            $imgs = json_decode($r['images'] ?? '[]', true) ?: [];
            $r['img'] = $imgs[0] ?? 'farm.jpg';
            $r['unit'] = preg_replace('/^per\s+/', '', $r['unit']);
            unset($r['images']);
        }
        unset($r);
        $out = ['mode' => $seller ? 'seller' : 'buyer', 'offers' => $rows];
    } elseif ($api === 'offer_status') {
        $block_admin();
        $oid = (int)($_POST['offer_id'] ?? 0);
        $st = $_POST['status'] ?? '';
        if (!in_array($st, ['Accepted', 'Declined'], true)) {
            $out = ['error' => 'Invalid status.'];
        } else {
            $s = api_prepare($conn, "UPDATE offers SET status = ? WHERE id = ? AND seller_id = ? AND status = 'Pending'");
            $s->bind_param("sii", $st, $oid, $me); $s->execute();
            $out = $s->affected_rows > 0 ? ['ok' => true] : ['error' => 'Offer not found or already answered.'];
            $s->close();
        }
    } elseif ($api === 'conversations') {
        $s = api_prepare($conn, "SELECT u.id, u.username, m.id AS msg_id, m.sender_id, m.body, m.created_at FROM messages m JOIN users u ON u.id = IF(m.sender_id = ?, m.receiver_id, m.sender_id) WHERE m.id IN (SELECT MAX(id) FROM messages WHERE sender_id = ? OR receiver_id = ? GROUP BY IF(sender_id = ?, receiver_id, sender_id)) ORDER BY m.id DESC");
        $s->bind_param("iiii", $me, $me, $me, $me); $s->execute();
        $convs = $s->get_result()->fetch_all(MYSQLI_ASSOC); $s->close();
        foreach ($convs as &$cv) { $cv['body'] = dec_text($cv['body']); } unset($cv);
        $out = ['conversations' => $convs];
    } elseif ($api === 'thread') {
        $with = (int)($_GET['with'] ?? 0);
        $s = api_prepare($conn, "SELECT id, sender_id, body, product_id, created_at FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY id ASC LIMIT 300");
        $s->bind_param("iiii", $me, $with, $with, $me); $s->execute();
        $rows = $s->get_result()->fetch_all(MYSQLI_ASSOC); $s->close();
        $pid = 0;
        foreach ($rows as &$rr) { $rr['body'] = dec_text($rr['body']); } unset($rr);
        foreach ($rows as $r) { if ($r['product_id']) $pid = (int)$r['product_id']; }
        $out = ['messages' => $rows, 'product_id' => $pid, 'me' => $me];
    } elseif ($api === 'send_message') {
        $block_admin();
        $to = (int)($_POST['to'] ?? 0);
        $body = mb_substr(trim($_POST['body'] ?? ''), 0, 1000);
        $pid = (int)($_POST['product_id'] ?? 0);
        $pidv = $pid > 0 ? $pid : null;
        $s = api_prepare($conn, "SELECT id FROM users WHERE id = ?");
        $s->bind_param("i", $to); $s->execute();
        $exists = $s->get_result()->num_rows > 0; $s->close();
        if ($to === $me || !$exists || $body === '') {
            $out = ['error' => 'Cannot send this message.'];
        } else {
            $s = api_prepare($conn, "INSERT INTO messages (sender_id, receiver_id, product_id, body) VALUES (?, ?, ?, ?)");
            $enc = enc_text($body);
            $s->bind_param("iiis", $me, $to, $pidv, $enc);
            $out = $s->execute() ? ['ok' => true] : ['error' => 'Could not send the message.'];
            $s->close();
        }
    } elseif ($api === 'change_password') {
        $cur = $_POST['current'] ?? '';
        $new = $_POST['new'] ?? '';
        $con = $_POST['confirm'] ?? '';
        $s = api_prepare($conn, "SELECT password FROM users WHERE id = ?");
        $s->bind_param("i", $me); $s->execute();
        $row = $s->get_result()->fetch_assoc(); $s->close();
        if (!$row || !password_verify($cur, $row['password'])) $out = ['error' => 'Current password is incorrect.'];
        elseif (strlen($new) < 8) $out = ['error' => 'New password must be at least 8 characters.'];
        elseif ($new !== $con) $out = ['error' => 'New passwords do not match.'];
        elseif ($new === $cur) $out = ['error' => "Choose a password you haven't used before."];
        else {
            $hash = password_hash($new, PASSWORD_DEFAULT);
            $s = api_prepare($conn, "UPDATE users SET password = ? WHERE id = ?");
            $s->bind_param("si", $hash, $me);
            $out = $s->execute() ? ['ok' => true] : ['error' => 'Could not update the password.'];
            $s->close();
        }
    } elseif ($api === 'settings') {
        $s = api_prepare($conn, "SELECT notify_offers, notify_messages FROM users WHERE id = ?");
        $s->bind_param("i", $me); $s->execute();
        $out = $s->get_result()->fetch_assoc() ?: ['error' => 'User not found.']; $s->close();
    } elseif ($api === 'save_settings') {
        $no = !empty($_POST['notify_offers']) ? 1 : 0;
        $nm = !empty($_POST['notify_messages']) ? 1 : 0;
        $s = api_prepare($conn, "UPDATE users SET notify_offers = ?, notify_messages = ? WHERE id = ?");
        $s->bind_param("iii", $no, $nm, $me);
        $out = $s->execute() ? ['ok' => true] : ['error' => 'Could not save your settings.'];
        $s->close();
    } elseif ($api === 'logout_all') {
        $s = api_prepare($conn, "UPDATE users SET session_version = session_version + 1 WHERE id = ?");
        $s->bind_param("i", $me); $s->execute(); $s->close();
        session_unset(); session_destroy();
        $out = ['ok' => true];
    } elseif ($api === 'delete_account') {
        $s = api_prepare($conn, "SELECT password, role FROM users WHERE id = ?");
        $s->bind_param("i", $me); $s->execute();
        $row = $s->get_result()->fetch_assoc(); $s->close();
        if ($row && $row['role'] === 'Admin') {
            $out = ['error' => 'Administrators cannot delete their own account through this endpoint.'];
        } elseif (!$row || !password_verify($_POST['password'] ?? '', $row['password'])) {
            $out = ['error' => 'Incorrect password.'];
        } else {
            $queries = [
                "DELETE FROM order_timeline WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = ? OR seller_id = ?)" => 2,
                "DELETE FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = ? OR seller_id = ?)" => 2,
                "DELETE FROM orders WHERE buyer_id = ? OR seller_id = ?" => 2,
                "DELETE FROM offers WHERE buyer_id = ? OR seller_id = ?" => 2,
                "DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?" => 2,
                "DELETE FROM products WHERE seller_id = ?" => 1,
                "DELETE FROM users WHERE id = ?" => 1,
            ];
            foreach ($queries as $sql => $n) {
                $s = api_prepare($conn, $sql);
                if ($n === 2) $s->bind_param("ii", $me, $me); else $s->bind_param("i", $me);
                $s->execute(); $s->close();
            }
            session_unset(); session_destroy();
            $out = ['ok' => true];
        }
    }

    // ============================================================
    // REAL ORDER ENDPOINTS — Pickup or COD, with payment tracking
    // ============================================================
    elseif ($api === 'place_order') {
        $block_admin();
        if ($role !== 'Buyer') { echo json_encode(['error' => 'Only buyers can place orders.']); exit(); }

        // Fulfillment: 'Pickup' or 'COD'
        $fulfillment = strtoupper(trim($_POST['fulfillment'] ?? 'COD'));
        if (!in_array($fulfillment, ['PICKUP', 'COD'], true)) $fulfillment = 'COD';
        $payment_method = ($fulfillment === 'PICKUP') ? 'Cash on Pickup' : 'Cash on Delivery';

        $delivery_name = trim($_POST['delivery_name'] ?? '');
        $delivery_phone = trim($_POST['delivery_phone'] ?? '');
        $delivery_barangay = trim($_POST['delivery_barangay'] ?? '');
        $delivery_street = trim($_POST['delivery_street'] ?? '');
        $delivery_notes = mb_substr(trim($_POST['delivery_notes'] ?? ''), 0, 255);
        $pickup_notes = mb_substr(trim($_POST['pickup_notes'] ?? ''), 0, 255);

        $itemsRaw = $_POST['items'] ?? '[]';
        $items = json_decode($itemsRaw, true);

        if (!is_array($items) || count($items) === 0) {
            $out = ['error' => 'Your cart is empty.'];
        } elseif ($delivery_name === '' || $delivery_phone === '') {
            $out = ['error' => 'Please enter your full name and phone number.'];
        } elseif ($fulfillment === 'COD' && ($delivery_barangay === '' || $delivery_street === '')) {
            $out = ['error' => 'Please complete the delivery address (barangay and street).'];
        } elseif (!preg_match('/^[0-9+\-\s()]{7,20}$/', $delivery_phone)) {
            $out = ['error' => 'Please enter a valid phone number.'];
        } else {
            // Group items by seller
            $bySeller = [];
            foreach ($items as $it) {
                $pid = (int)($it['id'] ?? 0);
                $qty = (int)($it['quantity'] ?? 0);
                if ($pid <= 0 || $qty <= 0) continue;
                $s = api_prepare($conn, "SELECT id, seller_id, name, unit, price, stock, images, barangay, street FROM products WHERE id = ?");
                $s->bind_param("i", $pid); $s->execute();
                $p = $s->get_result()->fetch_assoc(); $s->close();
                if (!$p) { continue; }
                $sid = (int)$p['seller_id'];
                if ($sid === $me) continue; // can't buy own product
                if ($qty > (int)$p['stock']) {
                    echo json_encode(['error' => 'Not enough stock for ' . $p['name'] . '. Only ' . $p['stock'] . ' left.']);
                    exit();
                }
                $imgs = json_decode($p['images'] ?? '[]', true) ?: [];
                $bySeller[$sid][] = [
                    'product_id' => (int)$p['id'],
                    'name' => $p['name'],
                    'unit' => preg_replace('/^per\s+/', '', $p['unit']),
                    'price' => (float)$p['price'],
                    'quantity' => $qty,
                    'image' => $imgs[0] ?? 'farm.jpg',
                    'seller_barangay' => $p['barangay'] ?? '',
                    'seller_street' => $p['street'] ?? '',
                ];
            }
            if (count($bySeller) === 0) {
                $out = ['error' => 'No valid items in your cart.'];
            } else {
                $conn->begin_transaction();
                try {
                    $orderIds = [];
                    $refs = [];
                    foreach ($bySeller as $sid => $lines) {
                        $total = 0;
                        foreach ($lines as $l) { $total += $l['price'] * $l['quantity']; }

                        // Pickup location = seller's registered address for that seller's order
                        $pickup_location = '';
                        if ($fulfillment === 'PICKUP') {
                            $pickup_location = trim(($lines[0]['seller_street'] ? $lines[0]['seller_street'] . ', ' : '') . ($lines[0]['seller_barangay'] ? $lines[0]['seller_barangay'] . ', ' : '') . 'Tayabas City');
                        }

                        $s = api_prepare($conn, "INSERT INTO orders (buyer_id, seller_id, total, fulfillment, payment_method, payment_status, status, delivery_name, delivery_phone, delivery_barangay, delivery_street, delivery_notes, pickup_location, pickup_notes) VALUES (?, ?, ?, ?, ?, 'Unpaid', 'Pending', ?, ?, ?, ?, ?, ?, ?)");
                        $s->bind_param("iidsssssssss", $me, $sid, $total, $fulfillment, $payment_method, $delivery_name, $delivery_phone, $delivery_barangay, $delivery_street, $delivery_notes, $pickup_location, $pickup_notes);
                        if (!$s->execute()) { throw new Exception('Could not create order.'); }
                        $oid = $conn->insert_id; $s->close();

                        // Generate readable reference now that we have the id
                        $ref = gen_order_ref($conn, $oid);
                        $u = api_prepare($conn, "UPDATE orders SET order_ref = ? WHERE id = ?");
                        $u->bind_param("si", $ref, $oid); $u->execute(); $u->close();
                        $orderIds[] = $oid;
                        $refs[] = $ref;

                        order_timeline_add($conn, $oid, 'Pending', 'Order placed. ' . ($fulfillment === 'PICKUP' ? 'Pickup scheduled.' : 'For delivery via COD.'), $me);

                        foreach ($lines as $l) {
                            $s = api_prepare($conn, "INSERT INTO order_items (order_id, product_id, product_name, unit, price, quantity, image) VALUES (?, ?, ?, ?, ?, ?, ?)");
                            $s->bind_param("iissdis", $oid, $l['product_id'], $l['name'], $l['unit'], $l['price'], $l['quantity'], $l['image']);
                            if (!$s->execute()) { throw new Exception('Could not save order items.'); }
                            $s->close();
                            // Deduct stock
                            $s = api_prepare($conn, "UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?");
                            $s->bind_param("iii", $l['quantity'], $l['product_id'], $l['quantity']);
                            if (!$s->execute() || $s->affected_rows === 0) { throw new Exception('Stock changed for ' . $l['name'] . '.'); }
                            $s->close();
                        }
                        // Mark matching offers accepted (auto-accept pending offers for this product from buyer)
                        $s = api_prepare($conn, "UPDATE offers SET status = 'Accepted' WHERE buyer_id = ? AND seller_id = ? AND status = 'Pending' AND product_id IN (" . implode(',', array_fill(0, count($lines), '?')) . ")");
                        $types = 'ii' . str_repeat('i', count($lines));
                        $params = [$me, $sid];
                        foreach ($lines as $l) { $params[] = $l['product_id']; }
                        $s->bind_param($types, ...$params);
                        $s->execute(); $s->close();
                    }
                    $conn->commit();
                    $out = ['ok' => true, 'order_ids' => $orderIds, 'order_refs' => $refs, 'count' => count($orderIds), 'fulfillment' => $fulfillment, 'payment_method' => $payment_method];
                } catch (Throwable $e) {
                    $conn->rollback();
                    $out = ['error' => $e->getMessage() ?: 'Could not place order.'];
                }
            }
        }
    }
    elseif ($api === 'my_orders') {
        $block_admin();
        $s = api_prepare($conn, "SELECT o.*, u.username AS seller_name FROM orders o JOIN users u ON u.id = o.seller_id WHERE o.buyer_id = ? ORDER BY o.id DESC");
        $s->bind_param("i", $me); $s->execute();
        $orders = $s->get_result()->fetch_all(MYSQLI_ASSOC); $s->close();
        if (count($orders) > 0) {
            $ids = array_column($orders, 'id');
            $in = implode(',', array_map('intval', $ids));
            $r = $conn->query("SELECT order_id, product_id, product_name, unit, price, quantity, image FROM order_items WHERE order_id IN ($in)");
            $itemsByOrder = [];
            if ($r) { while ($x = $r->fetch_assoc()) { $itemsByOrder[(int)$x['order_id']][] = $x; } }
            $t = $conn->query("SELECT order_id, status, note, created_at FROM order_timeline WHERE order_id IN ($in) ORDER BY id ASC");
            $timelineByOrder = [];
            if ($t) { while ($x = $t->fetch_assoc()) { $timelineByOrder[(int)$x['order_id']][] = $x; } }
            foreach ($orders as &$o) {
                $o['items'] = $itemsByOrder[(int)$o['id']] ?? [];
                $o['timeline'] = $timelineByOrder[(int)$o['id']] ?? [];
            }
            unset($o);
        }
        $out = ['orders' => $orders];
    }
    elseif ($api === 'seller_orders') {
        $block_admin();
        if ($role !== 'Seller') { echo json_encode(['error' => 'Only sellers can view seller orders.']); exit(); }
        $s = api_prepare($conn, "SELECT o.*, u.username AS buyer_name FROM orders o JOIN users u ON u.id = o.buyer_id WHERE o.seller_id = ? ORDER BY o.id DESC");
        $s->bind_param("i", $me); $s->execute();
        $orders = $s->get_result()->fetch_all(MYSQLI_ASSOC); $s->close();
        if (count($orders) > 0) {
            $ids = array_column($orders, 'id');
            $in = implode(',', array_map('intval', $ids));
            $r = $conn->query("SELECT order_id, product_id, product_name, unit, price, quantity, image FROM order_items WHERE order_id IN ($in)");
            $itemsByOrder = [];
            if ($r) { while ($x = $r->fetch_assoc()) { $itemsByOrder[(int)$x['order_id']][] = $x; } }
            $t = $conn->query("SELECT order_id, status, note, created_at FROM order_timeline WHERE order_id IN ($in) ORDER BY id ASC");
            $timelineByOrder = [];
            if ($t) { while ($x = $t->fetch_assoc()) { $timelineByOrder[(int)$x['order_id']][] = $x; } }
            foreach ($orders as &$o) {
                $o['items'] = $itemsByOrder[(int)$o['id']] ?? [];
                $o['timeline'] = $timelineByOrder[(int)$o['id']] ?? [];
            }
            unset($o);
        }
        $out = ['orders' => $orders];
    }
    elseif ($api === 'update_order_status') {
        $block_admin();
        $oid = (int)($_POST['order_id'] ?? 0);
        $st = $_POST['status'] ?? '';
        $allowed = ['Confirmed','Shipped','Delivered','Cancelled'];
        if ($oid <= 0 || !in_array($st, $allowed, true)) { $out = ['error' => 'Invalid request.']; }
        else {
            $s = api_prepare($conn, "SELECT seller_id, status, fulfillment FROM orders WHERE id = ?");
            $s->bind_param("i", $oid); $s->execute();
            $o = $s->get_result()->fetch_assoc(); $s->close();
            if (!$o || (int)$o['seller_id'] !== $me) { $out = ['error' => 'Order not found.']; }
            else {
                $from = $o['status'];
                $valid = [
                    'Pending'   => ['Confirmed','Cancelled'],
                    'Confirmed' => ['Shipped','Delivered','Cancelled'],
                    'Shipped'   => ['Delivered'],
                    'Delivered' => [],
                    'Cancelled' => [],
                ];
                if (!in_array($st, $valid[$from] ?? [], true)) {
                    $out = ['error' => "Cannot change order from $from to $st."];
                } else {
                    $s = api_prepare($conn, "UPDATE orders SET status = ? WHERE id = ?");
                    $s->bind_param("si", $st, $oid);
                    if ($s->execute()) {
                        // Restore stock if cancelled
                        if ($st === 'Cancelled') {
                            $r = $conn->query("SELECT product_id, quantity FROM order_items WHERE order_id = " . (int)$oid);
                            if ($r) {
                                while ($it = $r->fetch_assoc()) {
                                    $u = api_prepare($conn, "UPDATE products SET stock = stock + ? WHERE id = ?");
                                    $u->bind_param("ii", $it['quantity'], $it['product_id']);
                                    $u->execute(); $u->close();
                                }
                            }
                        }
                        // If marked delivered and it's a COD order, payment should follow
                        $note = ($st === 'Delivered' && ($o['fulfillment'] ?? 'COD') === 'COD')
                            ? 'Delivered — collect cash payment from the buyer.'
                            : 'Status changed to ' . $st . '.';
                        order_timeline_add($conn, $oid, $st, $note, $me);
                        $out = ['ok' => true];
                    } else {
                        $out = ['error' => 'Could not update order.'];
                    }
                    $s->close();
                }
            }
        }
    }
    elseif ($api === 'cancel_order') {
        $block_admin();
        $oid = (int)($_POST['order_id'] ?? 0);
        if ($oid <= 0) { $out = ['error' => 'Invalid order.']; }
        else {
            $s = api_prepare($conn, "SELECT buyer_id, status, payment_status FROM orders WHERE id = ?");
            $s->bind_param("i", $oid); $s->execute();
            $o = $s->get_result()->fetch_assoc(); $s->close();
            if (!$o || (int)$o['buyer_id'] !== $me) { $out = ['error' => 'Order not found.']; }
            elseif (($o['payment_status'] ?? 'Unpaid') === 'Paid') { $out = ['error' => 'Paid orders can no longer be cancelled. Contact the seller.']; }
            elseif (!in_array($o['status'], ['Pending','Confirmed'], true)) { $out = ['error' => 'This order can no longer be cancelled.']; }
            else {
                $s = api_prepare($conn, "UPDATE orders SET status = 'Cancelled' WHERE id = ?");
                $s->bind_param("i", $oid);
                if ($s->execute()) {
                    $r = $conn->query("SELECT product_id, quantity FROM order_items WHERE order_id = " . (int)$oid);
                    if ($r) {
                        while ($it = $r->fetch_assoc()) {
                            $u = api_prepare($conn, "UPDATE products SET stock = stock + ? WHERE id = ?");
                            $u->bind_param("ii", $it['quantity'], $it['product_id']);
                            $u->execute(); $u->close();
                        }
                    }
                    order_timeline_add($conn, $oid, 'Cancelled', 'Cancelled by buyer. Stock restored.', $me);
                    $out = ['ok' => true];
                } else {
                    $out = ['error' => 'Could not cancel order.'];
                }
                $s->close();
            }
        }
    }

    // --- PAYMENT ENDPOINTS ---
    elseif ($api === 'mark_paid') {
        $block_admin();
        $oid = (int)($_POST['order_id'] ?? 0);
        $role = $_SESSION['role'] ?? '';
        if ($oid <= 0) { $out = ['error' => 'Invalid order.']; }
        else {
            $s = api_prepare($conn, "SELECT * FROM orders WHERE id = ?");
            $s->bind_param("i", $oid); $s->execute();
            $o = $s->get_result()->fetch_assoc(); $s->close();
            if (!$o) { $out = ['error' => 'Order not found.']; }
            elseif ($role === 'Buyer' && (int)$o['buyer_id'] !== $me) { $out = ['error' => 'Not your order.']; }
            elseif ($role === 'Seller' && (int)$o['seller_id'] !== $me) { $out = ['error' => 'Not your order.']; }
            elseif (($o['payment_status'] ?? 'Unpaid') === 'Paid') { $out = ['error' => 'This order is already marked as paid.']; }
            elseif (!in_array($o['status'], ['Confirmed','Shipped','Delivered'], true)) { $out = ['error' => 'Payment can only be recorded after the order is confirmed.' ]; }
            else {
                $s = api_prepare($conn, "UPDATE orders SET payment_status = 'Paid', paid_at = NOW() WHERE id = ?");
                $s->bind_param("i", $oid);
                if ($s->execute()) {
                    order_timeline_add($conn, $oid, 'Paid', 'Cash payment received (' . $o['payment_method'] . ').', $me);
                    $out = ['ok' => true];
                } else {
                    $out = ['error' => 'Could not record payment.'];
                }
                $s->close();
            }
        }
    }
    elseif ($api === 'refund_order') {
        // Seller-only; only for delivered COD orders that were paid
        $block_admin();
        $oid = (int)($_POST['order_id'] ?? 0);
        $s = api_prepare($conn, "SELECT seller_id, status, payment_status FROM orders WHERE id = ?");
        $s->bind_param("i", $oid); $s->execute();
        $o = $s->get_result()->fetch_assoc(); $s->close();
        if (!$o || (int)$o['seller_id'] !== $me) { $out = ['error' => 'Order not found.']; }
        elseif (($o['payment_status'] ?? 'Unpaid') !== 'Paid') { $out = ['error' => 'Only paid orders can be refunded.']; }
        else {
            $s = api_prepare($conn, "UPDATE orders SET payment_status = 'Refunded' WHERE id = ?");
            $s->bind_param("i", $oid);
            if ($s->execute()) {
                order_timeline_add($conn, $oid, 'Refunded', 'Payment refunded to buyer.', $me);
                $out = ['ok' => true];
            } else {
                $out = ['error' => 'Could not refund.'];
            }
            $s->close();
        }
    }

    // ============================================================
    // NEW ADMIN ENDPOINTS
    // ============================================================

    elseif ($api === 'admin_stats') {
        $require_admin();
        $stats = ['users' => 0, 'sellers' => 0, 'buyers' => 0, 'products' => 0, 'pending_offers' => 0, 'transactions' => 0, 'orders_pending' => 0, 'orders_total_value' => 0, 'revenue_collected' => 0];
        $r = $conn->query("SELECT
            (SELECT COUNT(*) FROM users WHERE role <> 'Admin') AS users,
            (SELECT COUNT(*) FROM users WHERE role = 'Seller') AS sellers,
            (SELECT COUNT(*) FROM users WHERE role = 'Buyer') AS buyers,
            (SELECT COUNT(*) FROM products) AS products,
            (SELECT COUNT(*) FROM offers WHERE status = 'Pending') AS pending_offers,
            (SELECT COUNT(*) FROM offers) AS transactions,
            (SELECT COUNT(*) FROM orders WHERE status = 'Pending') AS orders_pending,
            (SELECT COALESCE(SUM(total),0) FROM orders WHERE status IN ('Confirmed','Shipped','Delivered')) AS orders_total_value,
            (SELECT COALESCE(SUM(total),0) FROM orders WHERE payment_status = 'Paid') AS revenue_collected");
        if ($r) $stats = $r->fetch_assoc();
        $out = ['stats' => $stats];
    }

    elseif ($api === 'admin_activity') {
        $require_admin();
        $latest = ['users' => [], 'products' => [], 'offers' => []];
        $r = $conn->query("SELECT id, username, role, profile_pic, email_verified, session_version, created_at FROM users WHERE role <> 'Admin' ORDER BY id DESC LIMIT 10");
        if ($r) while ($x = $r->fetch_assoc()) $latest['users'][] = $x;
        $r = $conn->query("SELECT p.id, p.name, p.price, p.images, u.username AS seller FROM products p JOIN users u ON u.id = p.seller_id ORDER BY p.id DESC LIMIT 10");
        if ($r) while ($x = $r->fetch_assoc()) {
            $imgs = json_decode($x['images'] ?? '[]', true) ?: [];
            $x['img'] = $imgs[0] ?? 'farm.jpg';
            unset($x['images']);
            $latest['products'][] = $x;
        }
        $r = $conn->query("SELECT o.id, o.quantity, o.price, o.status, o.created_at, p.name AS product, b.username AS buyer, s.username AS seller FROM offers o JOIN products p ON p.id=o.product_id JOIN users b ON b.id=o.buyer_id JOIN users s ON s.id=o.seller_id ORDER BY o.id DESC LIMIT 10");
        if ($r) while ($x = $r->fetch_assoc()) $latest['offers'][] = $x;
        $out = ['activity' => $latest];
    }

    elseif ($api === 'admin_users') {
        $require_admin();
        $q = trim($_GET['q'] ?? '');
        $f = $_GET['filter'] ?? 'All';
        $where = []; $params = []; $types = '';
        if ($q !== '') { $where[] = "(username LIKE ? OR email LIKE ?)"; $like = "%$q%"; $params[] = $like; $params[] = $like; $types .= 'ss'; }
        if (in_array($f, ['Buyer','Seller','Admin'], true)) { $where[] = "role = ?"; $params[] = $f; $types .= 's'; }
        $sql = "SELECT id, username, email, role, email_verified, profile_pic, session_version, is_suspended, created_at FROM users";
        if ($where) $sql .= " WHERE " . implode(' AND ', $where);
        $sql .= " ORDER BY id DESC";
        $s = api_prepare($conn, $sql);
        if ($types) $s->bind_param($types, ...$params);
        $s->execute();
        $rows = $s->get_result()->fetch_all(MYSQLI_ASSOC);
        $s->close();
        $out = ['users' => $rows, 'me' => $me];
    }

    elseif ($api === 'admin_user_action') {
        $require_admin();
        $targetId = (int)($_POST['user_id'] ?? 0);
        $action = $_POST['action'] ?? '';
        if ($targetId <= 0) { $out = ['error' => 'Invalid user.']; }
        else {
            $s = api_prepare($conn, "SELECT id, role, session_version FROM users WHERE id = ?");
            $s->bind_param("i", $targetId); $s->execute();
            $target = $s->get_result()->fetch_assoc(); $s->close();

            if (!$target) { $out = ['error' => 'User not found.']; }
            elseif ($action === 'verify') {
                $s = api_prepare($conn, "UPDATE users SET email_verified = 1, verify_token = NULL, verify_expires = NULL WHERE id = ?");
                $s->bind_param("i", $targetId);
                $out = $s->execute() ? ['ok' => true] : ['error' => 'Could not verify.']; $s->close();
                admin_log($conn, $me, 'verify_user', $targetId);
            }
            elseif ($action === 'suspend') {
                if ($targetId === $me) { $out = ['error' => 'You cannot suspend your own account.']; }
                else {
                    $s = api_prepare($conn, "UPDATE users SET is_suspended = 1, session_version = session_version + 1 WHERE id = ?");
                    $s->bind_param("i", $targetId);
                    $out = $s->execute() ? ['ok' => true] : ['error' => 'Could not suspend.']; $s->close();
                    admin_log($conn, $me, 'suspend_user', $targetId);
                }
            }
            elseif ($action === 'unsuspend') {
                $s = api_prepare($conn, "UPDATE users SET is_suspended = 0 WHERE id = ?");
                $s->bind_param("i", $targetId);
                $out = $s->execute() ? ['ok' => true] : ['error' => 'Could not unsuspend.']; $s->close();
                admin_log($conn, $me, 'unsuspend_user', $targetId);
            }
            elseif ($action === 'promote') {
                if ($target['role'] === 'Admin') { $out = ['error' => 'User is already an Admin.']; }
                else {
                    $s = api_prepare($conn, "UPDATE users SET role = 'Admin', email_verified = 1, session_version = session_version + 1 WHERE id = ?");
                    $s->bind_param("i", $targetId);
                    $out = $s->execute() ? ['ok' => true] : ['error' => 'Could not promote.']; $s->close();
                    admin_log($conn, $me, 'promote_admin', $targetId);
                }
            }
            elseif ($action === 'delete') {
                if ($targetId === $me) { $out = ['error' => 'You cannot delete your own account.']; }
                else {
                    $queries = [
                        ["DELETE FROM order_timeline WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = ? OR seller_id = ?)", 2],
                        ["DELETE FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE buyer_id = ? OR seller_id = ?)", 2],
                        ["DELETE FROM orders WHERE buyer_id = ? OR seller_id = ?", 2],
                        ["DELETE FROM offers WHERE buyer_id = ? OR seller_id = ?", 2],
                        ["DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?", 2],
                        ["DELETE FROM products WHERE seller_id = ?", 1],
                        ["DELETE FROM users WHERE id = ?", 1],
                    ];
                    foreach ($queries as [$sql, $n]) {
                        $s = api_prepare($conn, $sql);
                        if ($n === 2) $s->bind_param("ii", $targetId, $targetId); else $s->bind_param("i", $targetId);
                        $s->execute(); $s->close();
                    }
                    admin_log($conn, $me, 'delete_user', $targetId);
                    $out = ['ok' => true];
                }
            }
            elseif ($action === 'demote') {
                $cnt = 0;
                $r = $conn->query("SELECT COUNT(*) AS c FROM users WHERE role = 'Admin'");
                if ($r) $cnt = (int)$r->fetch_assoc()['c'];
                if ($cnt <= 1) { $out = ['error' => 'Cannot demote the last remaining Admin.']; }
                elseif ($targetId === $me) { $out = ['error' => 'You cannot demote your own account.']; }
                else {
                    $s = api_prepare($conn, "UPDATE users SET role = 'Buyer', session_version = session_version + 1 WHERE id = ?");
                    $s->bind_param("i", $targetId);
                    $out = $s->execute() ? ['ok' => true] : ['error' => 'Could not demote.']; $s->close();
                    admin_log($conn, $me, 'demote_admin', $targetId);
                }
            }
            else { $out = ['error' => 'Unknown action.']; }
        }
    }

    elseif ($api === 'admin_products') {
        $require_admin();
        $q = trim($_GET['q'] ?? '');
        $where = []; $params = []; $types = '';
        if ($q !== '') { $where[] = "(p.name LIKE ? OR u.username LIKE ?)"; $like = "%$q%"; $params[] = $like; $params[] = $like; $types .= 'ss'; }
        $cat = $_GET['category'] ?? '';
        if ($cat !== '') { $where[] = "p.category = ?"; $params[] = $cat; $types .= 's'; }
        $brgy = $_GET['barangay'] ?? '';
        if ($brgy !== '') { $where[] = "p.barangay = ?"; $params[] = $brgy; $types .= 's'; }
        $sql = "SELECT p.id, p.name, p.category, p.unit, p.price, p.stock, p.barangay, p.images, p.description, p.seller_id, u.username AS seller_name FROM products p JOIN users u ON u.id = p.seller_id";
        if ($where) $sql .= " WHERE " . implode(' AND ', $where);
        $sql .= " ORDER BY p.id DESC";
        $s = api_prepare($conn, $sql);
        if ($types) $s->bind_param($types, ...$params);
        $s->execute();
        $rows = $s->get_result()->fetch_all(MYSQLI_ASSOC);
        $s->close();
        foreach ($rows as &$r) {
            $imgs = json_decode($r['images'] ?? '[]', true) ?: [];
            $r['img'] = $imgs[0] ?? 'farm.jpg';
            $r['unit'] = preg_replace('/^per\s+/', '', $r['unit']);
            unset($r['images']);
        }
        unset($r);
        $out = ['products' => $rows];
    }

    elseif ($api === 'admin_delete_product') {
        $require_admin();
        $pid = (int)($_POST['product_id'] ?? 0);
        if ($pid <= 0) { $out = ['error' => 'Invalid product.']; }
        else {
            $s = api_prepare($conn, "SELECT id FROM products WHERE id = ?");
            $s->bind_param("i", $pid); $s->execute();
            $exists = $s->get_result()->num_rows > 0; $s->close();
            if (!$exists) { $out = ['error' => 'Product not found.']; }
            else {
                $s = api_prepare($conn, "DELETE FROM offers WHERE product_id = ?");
                $s->bind_param("i", $pid); $s->execute(); $s->close();
                $s = api_prepare($conn, "DELETE FROM products WHERE id = ?");
                $s->bind_param("i", $pid);
                $out = $s->execute() ? ['ok' => true] : ['error' => 'Could not delete product.']; $s->close();
                admin_log($conn, $me, 'delete_product', $pid);
            }
        }
    }

    elseif ($api === 'admin_offers') {
        $require_admin();
        $status = $_GET['status'] ?? '';
        $where = []; $params = []; $types = '';
        if (in_array($status, ['Pending','Accepted','Declined'], true)) {
            $where[] = "o.status = ?"; $params[] = $status; $types .= 's';
        }
        $sql = "SELECT o.id, o.quantity, o.price, o.status, o.created_at, o.product_id,
                       p.name AS product, p.unit, p.images,
                       b.username AS buyer, s.username AS seller
                FROM offers o
                JOIN products p ON p.id = o.product_id
                JOIN users b ON b.id = o.buyer_id
                JOIN users s ON s.id = o.seller_id";
        if ($where) $sql .= " WHERE " . implode(' AND ', $where);
        $sql .= " ORDER BY o.id DESC";
        $s = api_prepare($conn, $sql);
        if ($types) $s->bind_param($types, ...$params);
        $s->execute();
        $rows = $s->get_result()->fetch_all(MYSQLI_ASSOC);
        $s->close();
        foreach ($rows as &$r) {
            $imgs = json_decode($r['images'] ?? '[]', true) ?: [];
            $r['img'] = $imgs[0] ?? 'farm.jpg';
            $r['unit'] = preg_replace('/^per\s+/', '', $r['unit']);
            unset($r['images']);
        }
        unset($r);
        $out = ['offers' => $rows];
    }

    elseif ($api === 'admin_orders') {
        $require_admin();
        $status = $_GET['status'] ?? '';
        $where = []; $params = []; $types = '';
        if (in_array($status, ['Pending','Confirmed','Shipped','Delivered','Cancelled'], true)) {
            $where[] = "o.status = ?"; $params[] = $status; $types .= 's';
        }
        $sql = "SELECT o.*, b.username AS buyer, s.username AS seller
                FROM orders o
                JOIN users b ON b.id = o.buyer_id
                JOIN users s ON s.id = o.seller_id";
        if ($where) $sql .= " WHERE " . implode(' AND ', $where);
        $sql .= " ORDER BY o.id DESC";
        $s = api_prepare($conn, $sql);
        if ($types) $s->bind_param($types, ...$params);
        $s->execute();
        $orders = $s->get_result()->fetch_all(MYSQLI_ASSOC);
        $s->close();
        if (count($orders) > 0) {
            $ids = array_column($orders, 'id');
            $in = implode(',', array_map('intval', $ids));
            $r = $conn->query("SELECT order_id, product_name, unit, price, quantity, image FROM order_items WHERE order_id IN ($in)");
            $itemsByOrder = [];
            if ($r) { while ($x = $r->fetch_assoc()) { $itemsByOrder[(int)$x['order_id']][] = $x; } }
            $t = $conn->query("SELECT order_id, status, note, created_at FROM order_timeline WHERE order_id IN ($in) ORDER BY id ASC");
            $timelineByOrder = [];
            if ($t) { while ($x = $t->fetch_assoc()) { $timelineByOrder[(int)$x['order_id']][] = $x; } }
            foreach ($orders as &$o) {
                $o['items'] = $itemsByOrder[(int)$o['id']] ?? [];
                $o['timeline'] = $timelineByOrder[(int)$o['id']] ?? [];
            }
            unset($o);
        }
        $out = ['orders' => $orders];
    }

    elseif ($api === 'admin_reports') {
        $require_admin();
        $rep = ['offers_status' => [], 'products_category' => [], 'users_role' => [], 'products_barangay' => [], 'orders_status' => [], 'orders_total' => 0, 'orders_paid_total' => 0, 'orders_fulfillment' => [], 'payment_status' => []];
        $r = $conn->query("SELECT status, COUNT(*) AS c FROM offers GROUP BY status");
        if ($r) while ($x = $r->fetch_assoc()) $rep['offers_status'][] = $x;
        $r = $conn->query("SELECT category, COUNT(*) AS c FROM products GROUP BY category ORDER BY c DESC");
        if ($r) while ($x = $r->fetch_assoc()) $rep['products_category'][] = $x;
        $r = $conn->query("SELECT role, COUNT(*) AS c FROM users GROUP BY role");
        if ($r) while ($x = $r->fetch_assoc()) $rep['users_role'][] = $x;
        $r = $conn->query("SELECT barangay, COUNT(*) AS c FROM products GROUP BY barangay ORDER BY c DESC LIMIT 20");
        if ($r) while ($x = $r->fetch_assoc()) $rep['products_barangay'][] = $x;
        $r = $conn->query("SELECT status, COUNT(*) AS c FROM orders GROUP BY status");
        if ($r) while ($x = $r->fetch_assoc()) $rep['orders_status'][] = $x;
        $r = $conn->query("SELECT COALESCE(SUM(total),0) AS t FROM orders WHERE status IN ('Confirmed','Shipped','Delivered')");
        if ($r) $rep['orders_total'] = (float)$r->fetch_assoc()['t'];
        $r = $conn->query("SELECT COALESCE(SUM(total),0) AS t FROM orders WHERE payment_status = 'Paid'");
        if ($r) $rep['orders_paid_total'] = (float)$r->fetch_assoc()['t'];
        $r = $conn->query("SELECT fulfillment, COUNT(*) AS c FROM orders GROUP BY fulfillment");
        if ($r) while ($x = $r->fetch_assoc()) $rep['orders_fulfillment'][] = $x;
        $r = $conn->query("SELECT payment_status, COUNT(*) AS c FROM orders GROUP BY payment_status");
        if ($r) while ($x = $r->fetch_assoc()) $rep['payment_status'][] = $x;
        $out = ['reports' => $rep];
    }

    echo json_encode($out);
    exit();
}

$auth_error = '';
$auth_success = '';
$show_auth_page = false;

$product_success = $_SESSION['product_msg'] ?? '';
unset($_SESSION['product_msg']);

// --- PROFILE PICTURE UPLOAD LOGIC ---
if (isset($_POST['upload_profile']) && isset($_SESSION['user_id'])) {
    $uid = $_SESSION['user_id'];
    if (!empty($_FILES['profile_pic']['name'])) {
        $dir = __DIR__ . '/uploads/profiles/';
        if (!is_dir($dir)) mkdir($dir, 0755, true);
        $ext = strtolower(pathinfo($_FILES['profile_pic']['name'], PATHINFO_EXTENSION));
        if (in_array($ext, ['jpg', 'jpeg', 'png', 'webp'])) {
            $fn = 'profile_' . $uid . '_' . time() . '.' . $ext;
            if (move_uploaded_file($_FILES['profile_pic']['tmp_name'], $dir . $fn)) {
                $path = 'uploads/profiles/' . $fn;
                $stmt = $conn->prepare("UPDATE users SET profile_pic = ? WHERE id = ?");
                $stmt->bind_param("si", $path, $uid);
                $stmt->execute();
                $stmt->close();
                header("Location: index.php");
                exit();
            }
        }
    }
}

$tayabas_barangays = [
    'Alitao','Alsam Ibaba','Alsam Ilaya','Alupay','Angeles Zone I (Pob.)','Angeles Zone II (Pob.)',
    'Angeles Zone III (Pob.)','Angeles Zone IV (Pob.)','Angustias Zone I (Pob.)','Angustias Zone II (Pob.)',
    'Angustias Zone III (Pob.)','Angustias Zone IV (Pob.)','Anos','Ayaas','Baguio','Banilad','Bukal Ibaba',
    'Bukal Ilaya','Calantas','Calumpang','Camaysa','Dapdap','Domoit Kanluran','Domoit Silangan','Dulong Bayan',
    'Gibanga','Ibas','Ilasan Ibaba','Ilasan Ilaya','Ipilan','Isabang','Katigan Kanluran','Katigan Silangan',
    'Lakawan','Lalo','Lawigue','Lita','Malaoa','Masin','Mate','Mateuna','Mayowe','Nangka Ibaba','Nangka Ilaya',
    'Opias','Palale Ibaba','Palale Ilaya','Palale Silangan','Pandakaki','Pook','Potol','San Diego Zone I (Pob.)',
    'San Diego Zone II (Pob.)','San Diego Zone III (Pob.)','San Diego Zone IV (Pob.)','San Isidro Zone I (Pob.)',
    'San Isidro Zone II (Pob.)','San Isidro Zone III (Pob.)','San Isidro Zone IV (Pob.)','San Roque Zone I (Pob.)',
    'San Roque Zone II (Pob.)','Talolong','Tamlong','Tongko','Valencia','Wakas'
];

if (isset($_GET['verify'])) {
    $show_auth_page = true;
    $th = hash('sha256', (string)$_GET['verify']);
    $stmt = $conn->prepare("UPDATE users SET email_verified = 1, verify_token = NULL, verify_expires = NULL WHERE verify_token = ? AND verify_expires > NOW() AND email_verified = 0");
    if (!$stmt) die("SQL error: " . $conn->error);
    $stmt->bind_param("s", $th);
    $stmt->execute();
    if ($stmt->affected_rows > 0) { $auth_success = "Email verified! You can now log in."; }
    else { $auth_error = "This verification link is invalid or has expired."; }
    $stmt->close();
}

if (isset($_GET['resend'])) {
    $show_auth_page = true;
    $ru = trim((string)$_GET['resend']);
    $stmt = $conn->prepare("SELECT id, email, email_verified FROM users WHERE username = ?");
    if (!$stmt) die("SQL error: " . $conn->error);
    $stmt->bind_param("s", $ru);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if ($row && !(int)$row['email_verified']) {
        $token = bin2hex(random_bytes(32));
        $th = hash('sha256', $token);
        $exp = date('Y-m-d H:i:s', time() + 86400);
        $u = $conn->prepare("UPDATE users SET verify_token = ?, verify_expires = ? WHERE id = ?");
        $u->bind_param("ssi", $th, $exp, $row['id']);
        $u->execute(); $u->close();
        [$sent, $link] = send_verification($row['email'], $ru, $token);
        if (!$sent && in_array($_SERVER['SERVER_NAME'] ?? '', ['localhost', '127.0.0.1'], true)) {
            $auth_success = 'Email sending is not set up on localhost. Dev link: <a class="underline font-semibold" href="' . htmlspecialchars($link) . '">verify now</a>';
        } else {
            $auth_success = "If that account exists and is unverified, a new verification link was sent.";
        }
    } else {
        $auth_success = "If that account exists and is unverified, a new verification link was sent.";
    }
}

if (isset($_POST['signup'])) {
    $show_auth_page = true;
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $role = (($_POST['role'] ?? '') === 'Seller') ? 'Seller' : 'Buyer';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $auth_error = "Please enter a valid email address.";
    } elseif (!preg_match('/^[A-Za-z0-9_.-]{3,30}$/', $username)) {
        $auth_error = "Username must be 3-30 characters (letters, numbers, . _ -).";
    } elseif (strlen($password) < 8) {
        $auth_error = "Password must be at least 8 characters.";
    } elseif ($password !== $confirm_password) {
        $auth_error = "Passwords do not match.";
    } elseif (empty($_POST['agree'])) {
        $auth_error = "You must agree to the Terms & Conditions and Privacy Policy.";
    } else {
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $auth_error = "Username or Email already taken.";
        } else {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $token = bin2hex(random_bytes(32));
            $th = hash('sha256', $token);
            $exp = date('Y-m-d H:i:s', time() + 86400);
            $stmt_insert = $conn->prepare("INSERT INTO users (username, email, password, role, email_verified, verify_token, verify_expires) VALUES (?, ?, ?, ?, 0, ?, ?)");
            if (!$stmt_insert) die("SQL error: " . $conn->error);
            $stmt_insert->bind_param("ssssss", $username, $email, $hashed_password, $role, $th, $exp);

            if ($stmt_insert->execute()) {
                [$sent, $link] = send_verification($email, $username, $token);
                $auth_success = "Account created! We sent a verification link to " . htmlspecialchars($email) . ". Please verify your email before logging in.";
                if (!$sent && in_array($_SERVER['SERVER_NAME'] ?? '', ['localhost', '127.0.0.1'], true)) {
                    $auth_success .= ' (Email sending is not set up on localhost. Dev link: <a class="underline font-semibold" href="' . htmlspecialchars($link) . '">verify now</a>)';
                }
            } else {
                $auth_error = "Something went wrong. Please try again.";
            }
        }
        $stmt->close();
    }
}

if (isset($_POST['login'])) {
    $show_auth_page = true;
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    $stmt = $conn->prepare("SELECT id, username, password, role, email_verified, profile_pic, is_suspended FROM users WHERE username = ?");
    if (!$stmt) die("SQL error: " . $conn->error);
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($id, $db_username, $hashed_password, $role, $verified, $profile_pic, $suspended);
        $stmt->fetch();

        if (password_verify($password, $hashed_password)) {
            if ((int)$suspended) {
                $auth_error = 'This account has been suspended. Please contact support.';
            } elseif (!(int)$verified) {
                $auth_error = 'Please verify your email first. <a class="underline font-semibold" href="?resend=' . urlencode($db_username) . '">Resend verification email</a>';
            } else {
                session_regenerate_id(true);
                $_SESSION['user_id'] = $id;
                $_SESSION['username'] = $db_username;
                $_SESSION['role'] = $role;
                $_SESSION['profile_pic'] = $profile_pic;
                try {
                    $svq = $conn->query("SELECT session_version FROM users WHERE id = " . (int)$id);
                    if ($svq) { $_SESSION['sv'] = (int)$svq->fetch_assoc()['session_version']; }
                } catch (Throwable $e) {}
                header("Location: index.php");
                exit();
            }
        } else {
            $auth_error = "Incorrect username or password.";
        }
    } else {
        $auth_error = "Incorrect username or password.";
    }
    $stmt->close();
}

if (isset($_POST['add_product']) && isset($_SESSION['user_id']) && ($_SESSION['role'] ?? '') === 'Seller') {
    $seller_id = $_SESSION['user_id'];
    $name = trim($_POST['name']);
    $category = $_POST['category'];
    $unit = $_POST['unit'];
    $price = floatval($_POST['price']);
    $stock = intval($_POST['stock']);
    $min_order = intval($_POST['min_order']);
    $description = trim($_POST['description']);
    $city = 'Tayabas City';
    $barangay = $_POST['barangay'] ?? '';
    $street = trim($_POST['street'] ?? '');

    if (!in_array($barangay, $tayabas_barangays, true)) {
        $_SESSION['product_msg'] = "Invalid barangay.";
        header("Location: index.php");
        exit();
    }

    $saved = [];
    if (!empty($_FILES['photos']['name'][0])) {
        $dir = __DIR__ . '/uploads/products/';
        if (!is_dir($dir)) mkdir($dir, 0755, true);
        $allowed = ['jpg', 'jpeg', 'png', 'webp'];
        $count = min(count($_FILES['photos']['name']), 10);
        for ($i = 0; $i < $count; $i++) {
            if ($_FILES['photos']['error'][$i] !== UPLOAD_ERR_OK) continue;
            if ($_FILES['photos']['size'][$i] > 5 * 1024 * 1024) continue;
            $ext = strtolower(pathinfo($_FILES['photos']['name'][$i], PATHINFO_EXTENSION));
            if (!in_array($ext, $allowed, true)) continue;
            if (!@getimagesize($_FILES['photos']['tmp_name'][$i])) continue;
            $fn = bin2hex(random_bytes(10)) . '.' . $ext;
            if (move_uploaded_file($_FILES['photos']['tmp_name'][$i], $dir . $fn)) {
                $saved[] = 'uploads/products/' . $fn;
            }
        }
    }
    $images = json_encode($saved);

    $stmt = $conn->prepare("INSERT INTO products (seller_id, name, category, unit, price, stock, min_order, description, city, barangay, street, images) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    if (!$stmt) { die("SQL error: " . $conn->error); }
    $stmt->bind_param("isssdiisssss", $seller_id, $name, $category, $unit, $price, $stock, $min_order, $description, $city, $barangay, $street, $images);

    $_SESSION['product_msg'] = $stmt->execute() ? "Product added successfully!" : "Error adding product: " . $conn->error;
    $stmt->close();
    header("Location: index.php");
    exit();
}

if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit();
}

if (isset($_GET['action']) && ($_GET['action'] == 'login' || $_GET['action'] == 'signup')) {
    $show_auth_page = true;
}
$start_signup = (($_GET['action'] ?? '') === 'signup') || (isset($_POST['signup']) && $auth_error !== '');

$is_logged_in = isset($_SESSION['user_id']);
$username = $is_logged_in ? $_SESSION['username'] : 'Guest';
$user_role = $is_logged_in ? $_SESSION['role'] : '';
$user_profile_pic = $_SESSION['profile_pic'] ?? null;
$is_admin = ($user_role === 'Admin');

// --- FETCH DYNAMIC SELLERS & BUYERS FOR DISPLAY (Admins excluded) ---
$display_sellers = [];
$sellers_q = $conn->query("SELECT username, profile_pic FROM users WHERE role = 'Seller' LIMIT 3");
if ($sellers_q) { while ($r = $sellers_q->fetch_assoc()) $display_sellers[] = $r; }

$display_buyers = [];
$buyers_q = $conn->query("SELECT username, profile_pic FROM users WHERE role = 'Buyer' LIMIT 3");
if ($buyers_q) { while ($r = $buyers_q->fetch_assoc()) $display_buyers[] = $r; }

// --- DYNAMIC TOTAL USERS & PRODUCTS (Admins excluded from public count) ---
$total_users = 0;
$ur = $conn->query("SELECT COUNT(*) AS c FROM users WHERE role <> 'Admin'");
if ($ur) { $total_users = (int)$ur->fetch_assoc()['c']; }

$db_products = [];
$res = $conn->query("SELECT p.*, u.username AS seller_name, u.profile_pic AS seller_pic FROM products p JOIN users u ON u.id = p.seller_id ORDER BY p.id DESC");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $imgs = json_decode($row['images'] ?? '[]', true) ?: [];
        $db_products[] = [
            'id' => (int)$row['id'],
            'name' => $row['name'],
            'price' => (float)$row['price'],
            'unit' => preg_replace('/^per\s+/', '', $row['unit']),
            'img' => $imgs[0] ?? 'farm.jpg',
            'images' => $imgs,
            'category' => $row['category'],
            'sellerId' => (int)$row['seller_id'],
            'sellerName' => $row['seller_name'],
            'sellerPic' => $row['seller_pic'],
            'barangay' => $row['barangay'],
            'description' => $row['description'] ?? '',
            'rating' => 0,
            'stock' => (int)$row['stock'],
            'sold' => 0
        ];
    }
}
?>

<?php if ($show_auth_page): ?>
    <!-- LOGIN & SIGN UP UI (Unchanged structure) -->
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login / Sign Up - FarmDirect</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=Inter:wght@400;500;600;700&display=swap');
            .font-serif-custom { font-family: 'Playfair Display', serif; }
            body { font-family: 'Inter', sans-serif; }
            .bg-auth { 
                background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 50%, #bbf7d0 100%);
                position: relative;
                overflow: hidden;
            }
            .bg-auth::before {
                content: '';
                position: absolute;
                top: -50%;
                left: -50%;
                width: 200%;
                height: 200%;
                background: radial-gradient(circle at 30% 40%, rgba(34, 197, 94, 0.08) 0%, transparent 50%),
                            radial-gradient(circle at 70% 80%, rgba(21, 128, 61, 0.06) 0%, transparent 50%);
                animation: floatBg 20s ease-in-out infinite;
            }
            @keyframes floatBg {
                0%, 100% { transform: translate(0, 0) rotate(0deg); }
                50% { transform: translate(-2%, -1%) rotate(1deg); }
            }
            .auth-card {
                background: rgba(255, 255, 255, 0.92);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.6);
            }
            .green-panel {
                background: linear-gradient(145deg, #14532d 0%, #166534 40%, #15803d 100%);
                position: relative;
                overflow: hidden;
            }
            .green-panel::after {
                content: '';
                position: absolute;
                top: -30%;
                right: -30%;
                width: 80%;
                height: 80%;
                background: radial-gradient(circle, rgba(74, 222, 128, 0.15) 0%, transparent 70%);
                pointer-events: none;
            }
            .input-glow:focus {
                box-shadow: 0 0 0 3px rgba(22, 163, 74, 0.15);
                border-color: #16a34a;
            }
            .btn-primary {
                background: linear-gradient(135deg, #15803d 0%, #166534 100%);
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            .btn-primary:hover {
                transform: translateY(-1px);
                box-shadow: 0 8px 25px rgba(21, 128, 61, 0.35);
            }
            .btn-primary::after {
                content: '';
                position: absolute;
                top: 0; left: -100%;
                width: 100%; height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent);
                transition: left 0.5s;
            }
            .btn-primary:hover::after { left: 100%; }
            .auth-badge {
                background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%);
                color: #166534;
            }
        </style>
    </head>
    <body class="bg-auth flex items-center justify-center min-h-screen p-4">
        <div class="auth-card rounded-3xl shadow-2xl overflow-hidden flex flex-col md:flex-row w-full max-w-4xl min-h-[600px] relative z-10">
            <div class="hidden md:flex md:w-5/12 green-panel p-10 flex-col justify-between relative overflow-hidden">
                <div class="absolute -top-10 -left-10 w-40 h-40 bg-green-700/30 rounded-full blur-xl"></div>
                <div class="absolute -bottom-20 -right-20 w-60 h-60 bg-green-600/20 rounded-full blur-2xl"></div>
                <div class="relative z-10 text-white">
                    <div class="flex items-center space-x-3 mb-16 cursor-pointer" onclick="window.location.href='index.php'">
                        <div class="w-10 h-10 bg-white/10 backdrop-blur-sm rounded-xl flex items-center justify-center border border-white/20">
                            <i class="fa-solid fa-leaf text-yellow-400 text-xl"></i>
                        </div>
                        <span class="text-2xl font-bold tracking-tight">FarmDirect</span>
                    </div>
                    <h1 class="text-3xl font-bold leading-tight mb-4 font-serif-custom">From the farm,<br>straight to the market.</h1>
                    <p class="text-green-200/90 text-sm leading-relaxed">Join growers and buyers trading directly across the barangay — fair prices, fresh produce, no middlemen.</p>
                </div>
                <div class="relative z-10 text-green-300/70 text-xs">&copy; 2026 FarmDirect</div>
            </div>
            <div class="w-full md:w-7/12 p-8 md:p-12 relative flex flex-col justify-center bg-white/80">
                <a href="index.php" class="absolute top-6 right-6 text-gray-400 hover:text-green-700 text-sm font-semibold transition"><i class="fa-solid fa-arrow-left mr-1"></i> Back to Home</a>
                <?php if($auth_error): ?><div class="bg-red-50 border border-red-200 text-red-700 p-3 rounded-xl mb-4 text-sm"><?= $auth_error ?></div><?php endif; ?>
                <?php if($auth_success): ?><div class="bg-green-50 border border-green-200 text-green-700 p-3 rounded-xl mb-4 text-sm"><?= $auth_success ?></div><?php endif; ?>
                <div id="login-form">
                    <div class="text-center mb-8">
                        <span class="inline-block auth-badge text-xs font-bold tracking-wider uppercase px-4 py-1.5 rounded-full mb-4"><i class="fa-solid fa-leaf mr-1"></i> Welcome Back</span>
                        <h2 class="text-4xl font-serif-custom text-gray-900 mb-2">Login</h2>
                    </div>
                    <form method="POST" action="" class="space-y-4">
                        <div>
                            <label class="block text-sm font-bold text-gray-700 mb-1.5">Username</label>
                            <input type="text" name="username" placeholder="username" required class="w-full border border-gray-200 rounded-xl px-4 py-3 input-glow focus:outline-none transition">
                        </div>
                        <div>
                            <label class="block text-sm font-bold text-gray-700 mb-1.5">Password</label>
                            <input type="password" name="password" placeholder="Password" required class="w-full border border-gray-200 rounded-xl px-4 py-3 input-glow focus:outline-none transition">
                        </div>
                        <button type="submit" name="login" class="w-full btn-primary text-white font-bold py-3.5 rounded-xl transition">Login</button>
                    </form>
                    <div class="text-center mt-6 text-sm text-gray-600">
                        Need an account? <a href="#" onclick="toggleAuth()" class="font-bold text-green-700 hover:text-green-800 hover:underline transition">Sign up</a>
                    </div>
                </div>
                <div id="signup-form" class="hidden">
                    <div class="text-center mb-6">
                        <h2 class="text-3xl font-bold text-gray-900 mb-1">Create your account</h2>
                    </div>
                    <form method="POST" action="" class="space-y-4">
                        <div>
                            <label class="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">I want to</label>
                            <div class="flex bg-gray-100 p-1.5 rounded-xl gap-1">
                                <label class="flex-1 text-center cursor-pointer">
                                    <input type="radio" name="role" value="Buyer" class="peer sr-only" checked>
                                    <div class="py-2.5 rounded-lg text-sm font-semibold text-gray-500 peer-checked:bg-white peer-checked:text-green-700 peer-checked:shadow-sm transition-all"><i class="fa-solid fa-leaf mr-1"></i> Buy</div>
                                </label>
                                <label class="flex-1 text-center cursor-pointer">
                                    <input type="radio" name="role" value="Seller" class="peer sr-only">
                                    <div class="py-2.5 rounded-lg text-sm font-semibold text-gray-500 peer-checked:bg-white peer-checked:text-green-700 peer-checked:shadow-sm transition-all"><i class="fa-solid fa-seedling mr-1"></i> Sell</div>
                                </label>
                            </div>
                        </div>
                        <div>
                            <label class="block text-sm font-bold text-gray-700 mb-1.5">Username</label>
                            <input type="text" name="username" placeholder="Enter username" required class="w-full border border-gray-200 rounded-xl px-4 py-3 input-glow focus:outline-none transition">
                        </div>
                        <div>
                            <label class="block text-sm font-bold text-gray-700 mb-1.5">Email</label>
                            <input type="email" name="email" placeholder="you@example.com" required class="w-full border border-gray-200 rounded-xl px-4 py-3 input-glow focus:outline-none transition">
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-bold text-gray-700 mb-1.5">Password</label>
                                <input type="password" name="password" placeholder="Password" required class="w-full border border-gray-200 rounded-xl px-4 py-3 input-glow focus:outline-none transition">
                            </div>
                            <div>
                                <label class="block text-sm font-bold text-gray-700 mb-1.5">Confirm password</label>
                                <input type="password" name="confirm_password" placeholder="Confirm" required class="w-full border border-gray-200 rounded-xl px-4 py-3 input-glow focus:outline-none transition">
                            </div>
                        </div>
                        <p class="text-xs text-gray-500 bg-gray-50 rounded-lg px-3 py-2"><i class="fa-solid fa-circle-info text-green-600 mr-1"></i> Your account type (Buyer or Seller) can't be changed later.</p>
                        <label class="flex items-start gap-2 text-xs text-gray-600 cursor-pointer">
                            <input type="checkbox" name="agree" value="1" required class="mt-0.5 accent-green-700 w-4 h-4">
                            <span>I agree to the <a href="index.php#terms" target="_blank" class="text-green-700 font-semibold hover:underline">Terms &amp; Conditions</a> and <a href="index.php#privacy" target="_blank" class="text-green-700 font-semibold hover:underline">Privacy Policy</a>.</span>
                        </label>
                        <button type="submit" name="signup" class="w-full btn-primary text-white font-bold py-3.5 rounded-xl transition mt-4">Create account</button>
                    </form>
                    <div class="text-center mt-6 text-sm text-gray-600">
                        Already have an account? <a href="#" onclick="toggleAuth()" class="font-bold text-green-700 hover:text-green-800 hover:underline transition">Log in</a>
                    </div>
                </div>
            </div>
        </div>
        <script>
            function toggleAuth() { document.getElementById('login-form').classList.toggle('hidden'); document.getElementById('signup-form').classList.toggle('hidden'); }
            <?php if ($start_signup): ?>toggleAuth();<?php endif; ?>
        </script>
    </body>
    </html>

<?php else: ?>
    <!-- MAIN WEBSITE -->
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FarmDirect - Fresh from the Farm</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;700;800&family=Inter:wght@400;500;600;700;800&display=swap');
            body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background-color: #fafbf9; }
            .font-serif { font-family: 'Playfair Display', serif; }
            .farm-bg-1 { background-image: url('farm.jpg'); background-size: cover; height: 200px; }
            .farm-bg-2 { background-image: url('farm.jpg'); background-size: cover; height: 200px; }
            .farm-bg-3 { background-image: url('farm.jpg'); background-size: cover; height: 200px; }
            .active-nav { border-bottom: 2px solid #15803d; font-weight: 700; color: #15803d; }
            .no-scrollbar::-webkit-scrollbar { display: none; }
            .no-scrollbar { -ms-overflow-style: none; scrollbar-width: none; }
            details > summary { list-style: none; }
            details > summary::-webkit-details-marker { display: none; }

            /* --- Modern gradient and glass effects --- */
            .glass-nav {
                background: rgba(255, 255, 255, 0.85);
                backdrop-filter: blur(20px) saturate(180%);
                -webkit-backdrop-filter: blur(20px) saturate(180%);
                border-bottom: 1px solid rgba(0,0,0,0.05);
            }
            .hero-gradient {
                background: linear-gradient(135deg, #0f172a 0%, #14532d 40%, #166534 70%, #15803d 100%);
            }
            .hero-overlay {
                background: linear-gradient(105deg, rgba(0,0,0,0.75) 0%, rgba(15,23,42,0.6) 40%, rgba(15,23,42,0.2) 70%, transparent 100%);
            }
            .card-hover {
                transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            }
            .card-hover:hover {
                transform: translateY(-6px);
                box-shadow: 0 20px 40px -12px rgba(21, 128, 61, 0.15), 0 8px 16px -8px rgba(0,0,0,0.06);
            }
            .gradient-text {
                background: linear-gradient(135deg, #15803d 0%, #22c55e 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            .section-divider {
                background: linear-gradient(90deg, transparent, #d1fae5, transparent);
                height: 1px;
            }
            .price-tag {
                background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
                border: 1px solid #bbf7d0;
                color: #166534;
            }
            .badge-premium {
                background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
                color: #92400e;
                border: 1px solid #fcd34d;
            }
            .btn-glow {
                position: relative;
                overflow: hidden;
                transition: all 0.35s ease;
            }
            .btn-glow:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 25px rgba(21, 128, 61, 0.3);
            }
            .btn-glow::after {
                content: '';
                position: absolute;
                top: 0; left: -100%;
                width: 100%; height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
                transition: left 0.5s;
            }
            .btn-glow:hover::after { left: 100%; }
            .product-card-img {
                transition: transform 0.6s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            }
            .product-card:hover .product-card-img {
                transform: scale(1.08);
            }
            .stat-card {
                background: linear-gradient(135deg, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0.05) 100%);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255,255,255,0.15);
                transition: all 0.3s ease;
            }
            .stat-card:hover {
                background: rgba(255,255,255,0.15);
                border-color: rgba(255,255,255,0.25);
            }
            .feature-icon-wrap {
                background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
                transition: all 0.35s ease;
            }
            .group:hover .feature-icon-wrap {
                background: linear-gradient(135deg, #15803d 0%, #166534 100%);
                transform: scale(1.05) rotate(-3deg);
            }
            .group:hover .feature-icon-wrap i { color: white; }
            .step-icon {
                background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
                transition: all 0.35s ease;
            }
            .group:hover .step-icon {
                background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%);
                transform: scale(1.05);
            }
            .seller-card:hover .seller-avatar {
                border-color: #22c55e;
                transform: scale(1.05);
            }
            .seller-avatar { transition: all 0.35s ease; }
            .footer-gradient {
                background: linear-gradient(180deg, #052e16 0%, #14532d 50%, #052e16 100%);
            }
            .scroll-btn {
                transition: all 0.25s ease;
            }
            .scroll-btn:hover {
                background: #15803d;
                color: white;
                border-color: #15803d;
                transform: scale(1.05);
            }
            .category-pill {
                transition: all 0.25s ease;
            }
            .category-pill:hover {
                background: #f0fdf4;
                color: #15803d;
                transform: translateX(3px);
            }
            .offer-modal-glass {
                background: rgba(255, 255, 255, 0.97);
                backdrop-filter: blur(30px);
            }
            .chat-bubble-mine {
                background: linear-gradient(135deg, #15803d 0%, #166534 100%);
            }
            .nav-dropdown {
                opacity: 0;
                visibility: hidden;
                transform: translateY(8px) scale(0.98);
                transition: all 0.25s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            }
            .group:hover .nav-dropdown {
                opacity: 1;
                visibility: visible;
                transform: translateY(0) scale(1);
            }
            .profile-ring {
                background: linear-gradient(135deg, #22c55e 0%, #15803d 100%);
                padding: 2px;
            }
            .message-badge {
                animation: pulseBadge 2s ease-in-out infinite;
            }
            @keyframes pulseBadge {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.15); }
            }
            .gradient-border-card {
                position: relative;
                background: white;
                border-radius: 1rem;
            }
            .gradient-border-card::before {
                content: '';
                position: absolute;
                inset: 0;
                border-radius: 1rem;
                padding: 1px;
                background: linear-gradient(135deg, #d1fae5, #a7f3d0, #d1fae5);
                -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
                mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
                -webkit-mask-composite: xor;
                mask-composite: exclude;
                pointer-events: none;
            }

            /* --- Featured section: elevated, polished --- */
            .featured-wrap {
                background:
                    radial-gradient(ellipse 80% 60% at 50% 0%, rgba(220, 252, 231, 0.55) 0%, transparent 60%),
                    linear-gradient(180deg, #ffffff 0%, #fafbf9 100%);
                position: relative;
            }
            .featured-wrap::before {
                content: '';
                position: absolute;
                inset: 0;
                background-image: radial-gradient(circle at 1px 1px, rgba(21, 128, 61, 0.06) 1px, transparent 0);
                background-size: 22px 22px;
                -webkit-mask-image: radial-gradient(ellipse 70% 60% at 50% 40%, black 30%, transparent 75%);
                mask-image: radial-gradient(ellipse 70% 60% at 50% 40%, black 30%, transparent 75%);
                pointer-events: none;
            }
            .featured-eyebrow {
                background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%);
                border: 1px solid #a7f3d0;
                color: #065f46;
                box-shadow: 0 6px 20px -8px rgba(21, 128, 61, 0.35);
            }
            .featured-title {
                font-family: 'Playfair Display', serif;
                line-height: 1.05;
                letter-spacing: -0.02em;
            }
            .featured-title-accent {
                background: linear-gradient(120deg, #15803d 0%, #16a34a 45%, #4ade80 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                position: relative;
            }
            .featured-underline {
                position: relative;
                display: inline-block;
            }
            .featured-underline::after {
                content: '';
                position: absolute;
                left: 8%;
                right: 8%;
                bottom: -8px;
                height: 10px;
                background: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 300 20'%3E%3Cpath d='M2,15 Q75,2 150,10 T298,12' stroke='%2386efac' stroke-width='5' fill='none' stroke-linecap='round' opacity='0.55'/%3E%3C/svg%3E") no-repeat center;
                background-size: 100% 100%;
                z-index: -1;
            }
            .featured-divider {
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 12px;
                color: #15803d;
            }
            .featured-divider .line {
                height: 1px;
                width: 56px;
                background: linear-gradient(90deg, transparent, #86efac);
            }
            .featured-divider .line.right {
                background: linear-gradient(90deg, #86efac, transparent);
            }
            .featured-carousel {
                position: relative;
            }
            .featured-carousel::before,
            .featured-carousel::after {
                content: '';
                position: absolute;
                top: 0; bottom: 0;
                width: 56px;
                z-index: 5;
                pointer-events: none;
            }
            .featured-carousel::before {
                left: 0;
                background: linear-gradient(90deg, #ffffff 0%, rgba(255,255,255,0) 100%);
            }
            .featured-carousel::after {
                right: 0;
                background: linear-gradient(270deg, #fafbf9 0%, rgba(250,251,249,0) 100%);
            }
            .browse-all-btn {
                background: #ffffff;
                border: 1px solid #e5e7eb;
                box-shadow: 0 4px 14px -6px rgba(0,0,0,0.1);
                transition: all 0.3s ease;
            }
            .browse-all-btn:hover {
                border-color: #86efac;
                background: #f0fdf4;
                color: #15803d;
                transform: translateY(-2px);
                box-shadow: 0 10px 24px -10px rgba(21, 128, 61, 0.3);
            }
            .browse-all-btn i { transition: transform 0.3s ease; }
            .browse-all-btn:hover i { transform: translateX(3px); }

            /* --- Real order system additions --- */
            .ff-radio input:checked + .ff-radio-card {
                border-color: #16a34a;
                background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
                box-shadow: 0 0 0 3px rgba(22, 163, 74, 0.15);
            }
            .ff-radio-card { transition: all 0.2s ease; }
            .timeline-dot { box-shadow: 0 0 0 3px #dcfce7; }
        </style>
    </head>
    <body class="text-gray-800 flex flex-col min-h-screen antialiased">

        <!-- Header -->
        <header class="glass-nav sticky top-0 z-40">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex justify-between items-center h-20">
                <div class="flex items-center space-x-2.5 cursor-pointer" onclick="showPage('home')">
                    <div class="w-10 h-10 bg-gradient-to-br from-green-600 to-green-800 rounded-xl flex items-center justify-center shadow-md shadow-green-200/50">
                        <i class="fa-solid fa-leaf text-yellow-300 text-lg"></i>
                    </div>
                    <span class="text-2xl font-extrabold text-gray-900 tracking-tight">Farm<span class="text-green-700">Direct</span></span>
                </div>
                
                <nav class="hidden md:flex space-x-1 items-center">
                    <a href="#" onclick="showPage('home')" id="nav-home" class="text-gray-600 hover:text-green-700 active-nav pb-1 px-4 py-2 rounded-lg transition-all">Home</a>
                    <a href="#" onclick="showPage('shop')" id="nav-shop" class="text-gray-600 hover:text-green-700 pb-1 px-4 py-2 rounded-lg transition-all">Shop</a>
                    <a href="#" onclick="showPage('about')" id="nav-about" class="text-gray-600 hover:text-green-700 pb-1 px-4 py-2 rounded-lg transition-all">About Us</a>
                </nav>

                <div class="flex items-center space-x-4">
                    
                    <?php if($is_logged_in): ?>
                        <div class="relative group hidden sm:block">
                            <button class="flex items-center space-x-2.5 text-sm font-semibold text-gray-700 hover:text-green-700 focus:outline-none rounded-xl px-2 py-1.5 hover:bg-gray-50 transition-all">
                                <!-- NAVBAR PROFILE PICTURE -->
                                <?php if($user_profile_pic): ?>
                                    <img src="<?= htmlspecialchars($user_profile_pic) ?>" alt="Profile" class="w-10 h-10 rounded-full object-cover ring-2 ring-green-500/30 ring-offset-2 shadow-sm">
                                <?php else: ?>
                                    <div class="w-10 h-10 rounded-full bg-gradient-to-br from-green-100 to-green-200 text-green-800 flex items-center justify-center font-bold border border-green-200 shadow-sm">
                                        <?= strtoupper(substr($username, 0, 1)) ?>
                                    </div>
                                <?php endif; ?>
                                
                                <span class="text-gray-900 hidden lg:block">Welcome, <?= htmlspecialchars($username) ?></span>
                                <?php if(!$is_admin): ?>
                                    <i id="bell-icon" onclick="openMessages()" title="Messages" class="fa-regular fa-bell text-gray-500 p-2 rounded-lg hover:bg-green-50 hover:text-green-600 cursor-pointer transition-all"></i>
                                <?php endif; ?>
                                <div class="bg-gray-50 px-3 py-1.5 rounded-lg flex items-center gap-2 border border-gray-150 ml-1">
                                    <span class="text-xs font-bold"><?= $user_role ?></span> 
                                    <i class="fa-solid fa-chevron-up text-[10px] transition-transform group-hover:rotate-180 text-gray-400"></i>
                                </div>
                            </button>

                            <div class="nav-dropdown absolute right-0 mt-2 w-64 bg-white rounded-2xl shadow-2xl border border-gray-100 z-50 overflow-hidden">
                                <div class="p-3 bg-gradient-to-r from-green-50 to-emerald-50 border-b border-gray-100">
                                    <p class="text-sm font-bold text-gray-900"><?= htmlspecialchars($username) ?></p>
                                    <p class="text-xs text-gray-500"><?= $user_role ?> Account</p>
                                </div>
                                <ul class="py-1.5 text-sm text-gray-800 font-medium">
                                    <?php if($user_role === 'Admin'): ?>
                                        <li><a href="#" onclick="showPage('admin-dashboard')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-gauge-high w-4 text-gray-400"></i> Admin Dashboard</a></li>
                                        <li><a href="#" onclick="showPage('admin-users')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-users w-4 text-gray-400"></i> Manage Users</a></li>
                                        <li><a href="#" onclick="showPage('admin-products')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-box w-4 text-gray-400"></i> Manage Products</a></li>
                                        <li><a href="#" onclick="showPage('admin-orders')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-handshake w-4 text-gray-400"></i> Manage Orders</a></li>
                                        <li><a href="#" onclick="showPage('admin-reports')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-chart-bar w-4 text-gray-400"></i> Reports</a></li>
                                    <?php elseif($user_role === 'Seller'): ?>
                                        <li><a href="#" onclick="showPage('dashboard')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-gauge-high w-4 text-gray-400"></i> Dashboard</a></li>
                                        <li><a href="#" onclick="showPage('manage-products')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-box w-4 text-gray-400"></i> Manage Products</a></li>
                                        <li><a href="#" onclick="showPage('manage-orders')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-clipboard-list w-4 text-gray-400"></i> Manage Orders</a></li>
                                        <li><a href="#" onclick="showPage('report')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-chart-line w-4 text-gray-400"></i> Report</a></li>
                                    <?php else: ?>
                                        <li><a href="#" onclick="showPage('buyer-dashboard')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-gauge-high w-4 text-gray-400"></i> Dashboard</a></li>
                                        <li><a href="#" onclick="showPage('offers')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-handshake w-4 text-gray-400"></i> My Offers</a></li>
                                        <li><a href="#" onclick="showPage('saved')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-regular fa-heart w-4 text-gray-400"></i> Saved Products</a></li>
                                        <li><a href="#" onclick="showPage('purchases')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-bag-shopping w-4 text-gray-400"></i> Purchases</a></li>
                                    <?php endif; ?>
                                    <div class="h-px bg-gray-100 mx-4 my-1"></div>
                                    <li><a href="#" onclick="showPage('profile')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-regular fa-user w-4 text-gray-400"></i> Profile</a></li>
                                    <li><a href="#" onclick="showPage('change-password')" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-lock w-4 text-gray-400"></i> Change Password</a></li>
                                    <li><a href="#" onclick="openSettings()" class="flex items-center gap-3 px-5 py-2.5 hover:bg-green-50 hover:text-green-700 transition"><i class="fa-solid fa-gear w-4 text-gray-400"></i> Account Settings</a></li>
                                    <div class="h-px bg-gray-100 mx-4 my-1"></div>
                                    <li><a href="?logout=1" class="flex items-center gap-3 px-5 py-2.5 hover:bg-red-50 text-red-600 font-bold transition"><i class="fa-solid fa-arrow-right-from-bracket w-4"></i> Logout</a></li>
                                </ul>
                            </div>
                        </div>
                    <?php else: ?>
                        <a href="?action=login" class="border-2 border-green-700 text-green-700 px-5 py-2 rounded-xl hover:bg-green-50 transition hidden sm:block text-center font-bold">Login</a>
                        <a href="?action=signup" class="bg-gradient-to-r from-green-700 to-green-800 text-white px-5 py-2 rounded-xl hover:from-green-800 hover:to-green-900 transition hidden sm:block text-center font-bold shadow-md shadow-green-200 btn-glow">Sign Up</a>
                    <?php endif; ?>
                    
                    <?php if($is_logged_in && $user_role === 'Buyer'): ?>
                        <div class="relative cursor-pointer p-2 rounded-xl hover:bg-green-50 transition-all" onclick="showPage('cart')">
                            <i class="fa-solid fa-cart-shopping text-xl text-gray-700"></i>
                            <span id="cart-badge" class="absolute -top-1 -right-1 bg-gradient-to-r from-red-500 to-rose-600 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center font-bold shadow-sm">0</span>
                        </div>
                    <?php endif; ?>

                    <button class="md:hidden text-gray-700 text-2xl p-2 rounded-xl hover:bg-gray-100 transition" onclick="toggleMobileMenu()">
                        <i class="fa-solid fa-bars"></i>
                    </button>
                </div>
            </div>

            <div id="mobile-menu" class="hidden md:hidden bg-white/95 backdrop-blur-xl border-t px-4 py-4 space-y-1 shadow-xl absolute w-full rounded-b-2xl">
                <a href="#" onclick="showPage('home')" class="block text-gray-600 hover:text-green-700 font-medium px-4 py-2.5 rounded-xl hover:bg-green-50 transition">Home</a>
                <a href="#" onclick="showPage('shop')" class="block text-gray-600 hover:text-green-700 font-medium px-4 py-2.5 rounded-xl hover:bg-green-50 transition">Shop</a>
                <a href="#" onclick="showPage('about')" class="block text-gray-600 hover:text-green-700 font-medium px-4 py-2.5 rounded-xl hover:bg-green-50 transition">About Us</a>
                <div class="h-px bg-gray-100 my-1"></div>
                <?php if(!$is_logged_in): ?>
                    <a href="?action=login" class="block text-green-700 font-bold px-4 py-2.5 rounded-xl hover:bg-green-50 transition">Login</a>
                    <a href="?action=signup" class="block text-green-700 font-bold px-4 py-2.5 rounded-xl hover:bg-green-50 transition">Sign Up</a>
                <?php else: ?>
                    <a href="?logout=1" class="block text-red-500 font-bold px-4 py-2.5 rounded-xl hover:bg-red-50 transition">Logout</a>
                <?php endif; ?>
            </div>
        </header>

        <!-- Main Content Area -->
        <main class="flex-grow">

            <!-- 1. HOME PAGE -->
            <section id="page-home" class="page-section">
                <!-- HERO SECTION -->
                <div class="relative h-[85vh] min-h-[650px] flex items-center justify-center overflow-hidden hero-gradient">
                    <div class="absolute inset-0 bg-[url('farm.jpg')] bg-cover bg-center opacity-40 mix-blend-luminosity"></div>
                    <div class="absolute inset-0 hero-overlay"></div>
                    <div class="absolute inset-0" style="background: radial-gradient(ellipse at 20% 50%, rgba(21, 128, 61, 0.12) 0%, transparent 60%);"></div>
                    
                    <div class="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full pt-16 pb-32">
                        <div class="inline-flex items-center gap-2 bg-white/10 backdrop-blur-md border border-white/20 text-white/90 text-xs font-bold tracking-widest uppercase px-4 py-2 rounded-full mb-8">
                            <span class="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
                            The Future of Local Agriculture
                        </div>
                        <h1 class="text-5xl md:text-7xl font-bold text-white mb-6 leading-[1.08] font-serif">
                            Fresh Produce<br>
                            <span class="text-transparent bg-clip-text bg-gradient-to-r from-green-300 via-emerald-300 to-green-400">From the Farm</span><br>
                            To Your Door
                        </h1>
                        <p class="text-gray-300/90 text-lg md:text-xl max-w-2xl mb-10 leading-relaxed">
                            Buy and sell fresh agricultural products with trusted farmers, suppliers, and buyers. FarmDirect makes local trading faster, simpler, and more reliable across the Philippines.
                        </p>
                        
                        <div class="flex flex-wrap gap-4 mb-14">
                            <?php if($user_role !== 'Buyer' && $user_role !== 'Admin'): ?>
                            <button onclick="<?= $user_role === 'Seller' ? "showPage('manage-products')" : "window.location.href='?action=signup'" ?>" class="bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white font-bold py-3.5 px-8 rounded-xl flex items-center gap-2.5 transition btn-glow shadow-lg shadow-green-500/25">
                                Start Selling <i class="fa-solid fa-arrow-right"></i>
                            </button>
                            <?php endif; ?>
                            <button onclick="showPage('shop')" class="bg-white/10 hover:bg-white/20 backdrop-blur-md border border-white/25 text-white font-semibold py-3.5 px-8 rounded-xl transition-all hover:border-white/40">
                                Browse Marketplace
                            </button>
                        </div>

                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 max-w-3xl">
                            <div class="stat-card p-6 rounded-2xl">
                                <div class="text-4xl font-extrabold text-green-400 mb-1"><?= $total_users ?></div>
                                <div class="text-sm text-white/60 font-medium">Platform users</div>
                            </div>
                            <div class="stat-card p-6 rounded-2xl">
                                <div class="text-4xl font-extrabold text-green-400 mb-1"><?= count($db_products) ?></div>
                                <div class="text-sm text-white/60 font-medium">Products</div>
                            </div>
                            <div class="stat-card p-6 rounded-2xl">
                                <div class="text-4xl font-extrabold text-green-400 mb-1">24/7</div>
                                <div class="text-sm text-white/60 font-medium">Marketplace</div>
                            </div>
                        </div>
                    </div>

                    <div class="absolute bottom-0 left-0 right-0 w-full overflow-hidden leading-none z-20">
                        <svg class="relative block w-full h-[80px] md:h-[120px]" viewBox="0 0 1440 320" preserveAspectRatio="none">
                            <path fill="#fafbf9" fill-opacity="1" d="M0,224L48,213.3C96,203,192,181,288,181.3C384,181,480,203,576,224C672,245,768,267,864,250.7C960,235,1056,181,1152,165.3C1248,149,1344,171,1392,181.3L1440,192L1440,320L1392,320C1344,320,1248,320,1152,320C1056,320,960,320,864,320C768,320,672,320,576,320C480,320,384,320,288,320C192,320,96,320,48,320L0,320Z"></path>
                        </svg>
                    </div>
                </div>
                <!-- END HERO SECTION -->

                <!-- Featured Products — polished & centered -->
                <div class="featured-wrap py-20">
                    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
                        <div class="text-center max-w-2xl mx-auto mb-12">
                            <span class="inline-flex items-center gap-2 featured-eyebrow text-[11px] font-bold tracking-[0.18em] uppercase px-4 py-2 rounded-full mb-6">
                                <i class="fa-solid fa-star text-amber-500 text-[10px]"></i>
                                Featured on FarmDirect
                            </span>
                            <h2 class="featured-title text-4xl md:text-6xl text-gray-900 mb-4">
                                Fresh Picks
                            </h2>
                            <div class="featured-divider mb-4">
                                <span class="line"></span>
                                <i class="fa-solid fa-leaf text-green-500 text-sm"></i>
                                <span class="line right"></span>
                            </div>
                            <p class="featured-title text-2xl md:text-4xl">
                                <span class="featured-title-accent featured-underline">From Local Farms</span>
                            </p>
                            <p class="text-gray-500 mt-8 text-base leading-relaxed max-w-lg mx-auto">
                                A hand-picked selection of listings from trusted sellers across the FarmDirect marketplace.
                            </p>
                        </div>
                        <div class="featured-carousel relative">
                            <button type="button" onclick="scrollFeatured(-1)" title="Previous" class="scroll-btn absolute -left-3 md:-left-4 top-1/2 -translate-y-1/2 z-20 w-11 h-11 rounded-full bg-white border border-gray-200 shadow-lg flex items-center justify-center"><i class="fa-solid fa-chevron-left text-sm"></i></button>
                            <div class="flex gap-6 overflow-x-auto snap-x snap-mandatory scroll-smooth no-scrollbar py-4 px-1" id="featured-products-container">
                                <!-- Products injected via JS -->
                            </div>
                            <button type="button" onclick="scrollFeatured(1)" title="Next" class="scroll-btn absolute -right-3 md:-right-4 top-1/2 -translate-y-1/2 z-20 w-11 h-11 rounded-full bg-white border border-gray-200 shadow-lg flex items-center justify-center"><i class="fa-solid fa-chevron-right text-sm"></i></button>
                        </div>
                        <div class="text-center mt-12">
                            <button type="button" onclick="showPage('shop')" class="browse-all-btn inline-flex items-center gap-2.5 rounded-full px-7 py-3.5 text-sm font-bold text-gray-800">
                                Browse all products <i class="fa-solid fa-arrow-right text-xs"></i>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- WHY CHOOSE FARM DIRECT -->
                <div class="bg-gradient-to-b from-gray-50 to-white py-20">
                    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                        <div class="text-center max-w-3xl mx-auto mb-14">
                            <span class="inline-flex items-center gap-2 badge-premium text-sm font-bold tracking-wider uppercase px-5 py-2 rounded-full mb-5"><i class="fa-solid fa-crown text-amber-600"></i> Why Choose FarmDirect</span>
                            <h2 class="text-3xl md:text-5xl font-bold mb-5 font-serif leading-tight">Everything You Need<br>in One Agriculture Marketplace</h2>
                            <p class="text-gray-500 text-lg">FarmDirect connects farmers, suppliers, and buyers in one trusted platform, making agricultural trading easier, faster, and more accessible for everyone.</p>
                        </div>
                        
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                            <div class="group relative bg-white rounded-2xl p-7 border border-gray-100 hover:border-green-300 card-hover cursor-pointer overflow-hidden shadow-sm">
                                <span class="absolute top-3 right-5 text-7xl font-black text-gray-50 group-hover:text-green-50/80 transition-colors duration-500 select-none">01</span>
                                <div class="w-14 h-14 feature-icon-wrap rounded-2xl flex items-center justify-center mb-6 relative z-10">
                                    <i class="fa-solid fa-handshake text-2xl text-green-600 transition-colors duration-300"></i>
                                </div>
                                <h3 class="text-xl font-bold mb-2.5 relative z-10 text-gray-900">Direct Farm Connection</h3>
                                <p class="text-gray-500 text-sm leading-relaxed relative z-10">Connect directly with local farmers and producers without unnecessary middlemen.</p>
                            </div>
                            <div class="group relative bg-white rounded-2xl p-7 border border-gray-100 hover:border-green-300 card-hover cursor-pointer overflow-hidden shadow-sm">
                                <span class="absolute top-3 right-5 text-7xl font-black text-gray-50 group-hover:text-green-50/80 transition-colors duration-500 select-none">02</span>
                                <div class="w-14 h-14 feature-icon-wrap rounded-2xl flex items-center justify-center mb-6 relative z-10">
                                    <i class="fa-solid fa-store text-2xl text-green-600 transition-colors duration-300"></i>
                                </div>
                                <h3 class="text-xl font-bold mb-2.5 relative z-10 text-gray-900">Agriculture Marketplace</h3>
                                <p class="text-gray-500 text-sm leading-relaxed relative z-10">Buy and sell crops, livestock, poultry, and other agricultural products in one place.</p>
                            </div>
                            <div class="group relative bg-white rounded-2xl p-7 border border-gray-100 hover:border-green-300 card-hover cursor-pointer overflow-hidden shadow-sm">
                                <span class="absolute top-3 right-5 text-7xl font-black text-gray-50 group-hover:text-green-50/80 transition-colors duration-500 select-none">03</span>
                                <div class="w-14 h-14 feature-icon-wrap rounded-2xl flex items-center justify-center mb-6 relative z-10">
                                    <i class="fa-solid fa-shield-halved text-2xl text-green-600 transition-colors duration-300"></i>
                                </div>
                                <h3 class="text-xl font-bold mb-2.5 relative z-10 text-gray-900">Secure Transactions</h3>
                                <p class="text-gray-500 text-sm leading-relaxed relative z-10">Trade confidently through a trusted marketplace built for farmers, suppliers, and buyers.</p>
                            </div>
                            <div class="group relative bg-white rounded-2xl p-7 border border-gray-100 hover:border-green-300 card-hover cursor-pointer overflow-hidden shadow-sm">
                                <span class="absolute top-3 right-5 text-7xl font-black text-gray-50 group-hover:text-green-50/80 transition-colors duration-500 select-none">04</span>
                                <div class="w-14 h-14 feature-icon-wrap rounded-2xl flex items-center justify-center mb-6 relative z-10">
                                    <i class="fa-solid fa-map-location-dot text-2xl text-green-600 transition-colors duration-300"></i>
                                </div>
                                <h3 class="text-xl font-bold mb-2.5 relative z-10 text-gray-900">Local Sellers</h3>
                                <p class="text-gray-500 text-sm leading-relaxed relative z-10">Discover fresh agricultural products from sellers near your location for faster transactions.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- HOW FARM DIRECT WORKS -->
                <div class="bg-white py-20">
                    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                        <div class="text-center max-w-2xl mx-auto mb-14">
                            <h2 class="text-green-700 font-bold tracking-widest uppercase text-sm mb-3">How FarmDirect Works</h2>
                            <h3 class="text-3xl md:text-5xl font-bold text-gray-900 mb-5 font-serif">Simple Steps to Start Trading</h3>
                            <p class="text-gray-500 text-lg">Start buying or selling agricultural products in just a few simple steps.</p>
                        </div>
                        
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                            <div class="group bg-white rounded-2xl border border-gray-100 p-7 hover:border-green-300 card-hover cursor-pointer flex flex-col items-center text-center shadow-sm">
                                <div class="w-full h-44 step-icon rounded-2xl flex items-center justify-center mb-6 overflow-hidden border border-gray-50">
                                    <img src="create.jpg" alt="Create an Account" class="max-h-full object-contain group-hover:scale-110 transition-transform duration-500">
                                </div>
                                <div class="w-8 h-8 bg-gradient-to-br from-green-500 to-green-700 text-white rounded-full flex items-center justify-center text-sm font-bold mb-3 shadow-md shadow-green-200">1</div>
                                <h4 class="text-xl font-bold mb-2 text-gray-900">Create an Account</h4>
                                <p class="text-gray-500 text-sm">Register as a Buyer or Seller.</p>
                            </div>
                            <div class="group bg-white rounded-2xl border border-gray-100 p-7 hover:border-green-300 card-hover cursor-pointer flex flex-col items-center text-center shadow-sm">
                                <div class="w-full h-44 step-icon rounded-2xl flex items-center justify-center mb-6 overflow-hidden border border-gray-50">
                                    <img src="list.jpg" alt="List or Browse Products" class="max-h-full object-contain group-hover:scale-110 transition-transform duration-500">
                                </div>
                                <div class="w-8 h-8 bg-gradient-to-br from-green-500 to-green-700 text-white rounded-full flex items-center justify-center text-sm font-bold mb-3 shadow-md shadow-green-200">2</div>
                                <h4 class="text-xl font-bold mb-2 text-gray-900">List or Browse Products</h4>
                                <p class="text-gray-500 text-sm">Post products for sale or explore available listings.</p>
                            </div>
                            <div class="group bg-white rounded-2xl border border-gray-100 p-7 hover:border-green-300 card-hover cursor-pointer flex flex-col items-center text-center shadow-sm">
                                <div class="w-full h-44 step-icon rounded-2xl flex items-center justify-center mb-6 overflow-hidden border border-gray-50">
                                    <img src="trade.jpg" alt="Connect and Trade" class="max-h-full object-contain group-hover:scale-110 transition-transform duration-500">
                                </div>
                                <div class="w-8 h-8 bg-gradient-to-br from-green-500 to-green-700 text-white rounded-full flex items-center justify-center text-sm font-bold mb-3 shadow-md shadow-green-200">3</div>
                                <h4 class="text-xl font-bold mb-2 text-gray-900">Connect and Trade</h4>
                                <p class="text-gray-500 text-sm">Communicate directly with buyers and sellers and negotiate confidently.</p>
                            </div>
                            <div class="group bg-white rounded-2xl border border-gray-100 p-7 hover:border-green-300 card-hover cursor-pointer flex flex-col items-center text-center shadow-sm">
                                <div class="w-full h-44 step-icon rounded-2xl flex items-center justify-center mb-6 overflow-hidden border border-gray-50">
                                    <img src="grow.jpg" alt="Grow Your Business" class="max-h-full object-contain group-hover:scale-110 transition-transform duration-500">
                                </div>
                                <div class="w-8 h-8 bg-gradient-to-br from-green-500 to-green-700 text-white rounded-full flex items-center justify-center text-sm font-bold mb-3 shadow-md shadow-green-200">4</div>
                                <h4 class="text-xl font-bold mb-2 text-gray-900">Grow Your Business</h4>
                                <p class="text-gray-500 text-sm">Expand your market reach and increase your selling opportunities.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- NEW SECTION: BUILT FOR FARMERS AND BUYERS -->
                <div class="bg-[#f8faf7] py-24">
                    <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
                        <div class="text-center max-w-2xl mx-auto mb-14">
                            <span class="inline-flex items-center gap-2 bg-green-100 text-green-800 text-[11px] font-bold tracking-wider uppercase px-4 py-1.5 rounded-full mb-5">Why Choose FarmDirect</span>
                            <h2 class="text-3xl md:text-5xl font-bold text-gray-900 mb-5 leading-tight font-serif">Built for<br><span class="gradient-text">Farmers and Buyers</span></h2>
                            <p class="text-gray-500 text-lg leading-relaxed">FarmDirect is designed to help farmers sell more efficiently while giving buyers a simple way to discover fresh agricultural products from trusted local sellers.</p>
                        </div>
                        
                        <div class="space-y-10">
                            <!-- Farmers & Sellers Card -->
                            <div class="group bg-gradient-to-br from-[#f0fdf4] to-[#dcfce7] rounded-[2rem] p-8 md:p-14 border border-[#bbf7d0] shadow-sm hover:shadow-2xl hover:-translate-y-1 transition-all duration-500 flex flex-col md:flex-row gap-10 md:gap-14 items-center overflow-hidden">
                                <div class="w-full md:w-5/12 order-1 md:order-1">
                                    <div class="w-full h-[420px] bg-gray-100 rounded-3xl overflow-hidden shadow-inner group-hover:scale-[1.03] transition-transform duration-500 ring-4 ring-white/60">
                                        <img src="farmers.png" alt="Farmer" class="w-full h-full object-cover object-top">
                                    </div>
                                </div>
                                <div class="w-full md:w-7/12 order-2 md:order-2">
                                    <span class="inline-flex items-center gap-1.5 bg-[#bbf7d0] text-[#166534] text-[11px] font-bold tracking-wider uppercase px-4 py-1.5 rounded-full mb-5"><i class="fa-solid fa-seedling"></i> For Farmers & Sellers</span>
                                    <h3 class="text-3xl md:text-4xl font-bold text-[#052e16] mb-5 font-serif">Reach More Customers</h3>
                                    <p class="text-gray-600 text-base leading-relaxed mb-8">Expand your market beyond your local community. Showcase your products, connect directly with interested buyers, and grow your agricultural business without relying on middlemen.</p>
                                    
                                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-y-4 gap-x-6 mb-9">
                                        <div class="flex items-center gap-3 text-sm text-gray-700 font-semibold">
                                            <span class="w-2.5 h-2.5 rounded-full bg-gradient-to-r from-green-400 to-green-600 flex-shrink-0 shadow-sm"></span> Increase product visibility
                                        </div>
                                        <div class="flex items-center gap-3 text-sm text-gray-700 font-semibold">
                                            <span class="w-2.5 h-2.5 rounded-full bg-gradient-to-r from-green-400 to-green-600 flex-shrink-0 shadow-sm"></span> Receive direct buyer inquiries
                                        </div>
                                        <div class="flex items-center gap-3 text-sm text-gray-700 font-semibold">
                                            <span class="w-2.5 h-2.5 rounded-full bg-gradient-to-r from-green-400 to-green-600 flex-shrink-0 shadow-sm"></span> Sell without unnecessary middlemen
                                        </div>
                                        <div class="flex items-center gap-3 text-sm text-gray-700 font-semibold">
                                            <span class="w-2.5 h-2.5 rounded-full bg-gradient-to-r from-green-400 to-green-600 flex-shrink-0 shadow-sm"></span> Build long-term relationships
                                        </div>
                                        <div class="flex items-center gap-3 text-sm text-gray-700 font-semibold sm:col-span-2">
                                            <span class="w-2.5 h-2.5 rounded-full bg-gradient-to-r from-green-400 to-green-600 flex-shrink-0 shadow-sm"></span> Manage your own product listings
                                        </div>
                                    </div>
                                    
                                    <div class="inline-flex items-center gap-2 bg-[#dcfce7] text-[#166534] text-xs font-bold px-6 py-3 rounded-full shadow-sm">
                                        <i class="fa-solid fa-arrow-trend-up"></i> Grow your agricultural business with FarmDirect.
                                    </div>
                                </div>
                            </div>

                            <!-- Buyers Card -->
                            <div class="group bg-gradient-to-br from-[#eff6ff] to-[#dbeafe] rounded-[2rem] p-8 md:p-14 border border-[#bfdbfe] shadow-sm hover:shadow-2xl hover:-translate-y-1 transition-all duration-500 flex flex-col md:flex-row gap-10 md:gap-14 items-center overflow-hidden">
                                <div class="w-full md:w-7/12 order-2 md:order-1">
                                    <span class="inline-flex items-center gap-1.5 bg-[#bfdbfe] text-[#1e40af] text-[11px] font-bold tracking-wider uppercase px-4 py-1.5 rounded-full mb-5"><i class="fa-solid fa-bag-shopping"></i> For Buyers</span>
                                    <h3 class="text-3xl md:text-4xl font-bold text-[#052e16] mb-5 font-serif">Find Fresh Agricultural Products</h3>
                                    <p class="text-gray-600 text-base leading-relaxed mb-8">Discover vegetables, fruits, grains, livestock, seafood, and many other agricultural products from trusted local farmers and suppliers near you.</p>
                                    
                                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-y-4 gap-x-6 mb-9">
                                        <div class="flex items-center gap-3 text-sm text-gray-700 font-semibold">
                                            <span class="w-2.5 h-2.5 rounded-full bg-gradient-to-r from-blue-400 to-blue-600 flex-shrink-0 shadow-sm"></span> Fresh farm products
                                        </div>
                                        <div class="flex items-center gap-3 text-sm text-gray-700 font-semibold">
                                            <span class="w-2.5 h-2.5 rounded-full bg-gradient-to-r from-blue-400 to-blue-600 flex-shrink-0 shadow-sm"></span> Competitive local prices
                                        </div>
                                        <div class="flex items-center gap-3 text-sm text-gray-700 font-semibold">
                                            <span class="w-2.5 h-2.5 rounded-full bg-gradient-to-r from-blue-400 to-blue-600 flex-shrink-0 shadow-sm"></span> Support local farmers
                                        </div>
                                        <div class="flex items-center gap-3 text-sm text-gray-700 font-semibold">
                                            <span class="w-2.5 h-2.5 rounded-full bg-gradient-to-r from-blue-400 to-blue-600 flex-shrink-0 shadow-sm"></span> Discover nearby sellers
                                        </div>
                                        <div class="flex items-center gap-3 text-sm text-gray-700 font-semibold sm:col-span-2">
                                            <span class="w-2.5 h-2.5 rounded-full bg-gradient-to-r from-blue-400 to-blue-600 flex-shrink-0 shadow-sm"></span> Browse products anytime
                                        </div>
                                    </div>
                                    
                                    <div class="inline-flex items-center gap-2 bg-[#dbeafe] text-[#1e40af] text-xs font-bold px-6 py-3 rounded-full shadow-sm">
                                        <i class="fa-solid fa-heart"></i> Buy fresh products directly from trusted farmers.
                                    </div>
                                </div>
                                <div class="w-full md:w-5/12 order-1 md:order-2">
                                    <div class="w-full h-[420px] bg-gray-100 rounded-3xl overflow-hidden shadow-inner group-hover:scale-[1.03] transition-transform duration-500 ring-4 ring-white/60">
                                        <img src="buyer.png" alt="Buyer" class="w-full h-full object-cover object-top">
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- MEET OUR TRUSTED SELLERS (DYNAMIC) -->
                <div class="bg-gradient-to-b from-green-50 to-emerald-50/50 py-20">
                    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                        <div class="text-center mb-12">
                            <span class="inline-flex items-center gap-2 bg-white text-green-800 text-xs font-bold tracking-widest uppercase px-4 py-2 rounded-full mb-4 shadow-sm border border-green-100"><i class="fa-solid fa-handshake text-green-600"></i> Trusted Community</span>
                            <h2 class="text-3xl md:text-4xl font-bold font-serif text-gray-900">Meet Our Trusted Sellers</h2>
                        </div>
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                            <?php foreach ($display_sellers as $s): ?>
                            <div class="seller-card bg-white p-7 rounded-2xl shadow-sm border border-gray-100 text-center group cursor-pointer card-hover">
                                <?php if($s['profile_pic']): ?>
                                    <img src="<?= htmlspecialchars($s['profile_pic']) ?>" class="seller-avatar w-24 h-24 rounded-full mx-auto mb-5 object-cover border-4 border-green-100 shadow-md">
                                <?php else: ?>
                                    <div class="seller-avatar w-24 h-24 bg-gradient-to-br from-green-100 to-emerald-200 rounded-full mx-auto mb-5 flex items-center justify-center text-4xl border-4 border-green-100 shadow-md">👨‍🌾</div>
                                <?php endif; ?>
                                <h3 class="text-xl font-bold capitalize text-gray-900"><?= htmlspecialchars($s['username']) ?></h3>
                                <p class="text-sm text-green-700 font-semibold mb-2">Local Farmer</p>
                                <div class="flex items-center justify-center gap-1 mb-3">
                                    <span class="text-yellow-400">★★★★★</span>
                                    <span class="text-gray-500 text-xs font-semibold">(4.8)</span>
                                </div>
                                <p class="text-gray-500 text-sm leading-relaxed">"We grow fresh vegetables using natural and sustainable methods."</p>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </section>

            <!-- 2. SHOP PAGE -->
            <section id="page-shop" class="page-section hidden">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 flex flex-col md:flex-row gap-8">
                    <aside class="w-full md:w-64 flex-shrink-0">
                        <div class="bg-white rounded-2xl p-5 border border-gray-100 shadow-sm sticky top-24">
                            <h3 class="text-lg font-bold mb-4 hidden md:flex items-center gap-2 text-gray-900"><i class="fa-solid fa-sliders text-green-600"></i> Filters</h3>
                            <ul id="category-list" class="flex flex-row md:flex-col gap-2 md:gap-0 md:space-y-1 overflow-x-auto no-scrollbar pb-2 md:pb-0">
                                <li data-category="All" onclick="filterCategory('All')" class="category-pill cursor-pointer px-4 py-2.5 rounded-xl whitespace-nowrap text-gray-600 hover:bg-green-50 hover:text-green-700 transition font-medium">All</li>
                                <li data-category="Vegetables" onclick="filterCategory('Vegetables')" class="category-pill cursor-pointer px-4 py-2.5 rounded-xl whitespace-nowrap text-gray-600 hover:bg-green-50 hover:text-green-700 transition font-medium flex items-center"><i class="fa-solid fa-leaf w-5 text-green-500 mr-2 text-sm"></i> Vegetables</li>
                                <li data-category="Fruits" onclick="filterCategory('Fruits')" class="category-pill cursor-pointer px-4 py-2.5 rounded-xl whitespace-nowrap text-gray-600 hover:bg-green-50 hover:text-green-700 transition font-medium flex items-center"><i class="fa-brands fa-apple w-5 text-red-400 mr-2 text-sm"></i> Fruits</li>
                                <li data-category="Dairy" onclick="filterCategory('Dairy')" class="category-pill cursor-pointer px-4 py-2.5 rounded-xl whitespace-nowrap text-gray-600 hover:bg-green-50 hover:text-green-700 transition font-medium flex items-center"><i class="fa-solid fa-bottle-water w-5 text-blue-400 mr-2 text-sm"></i> Dairy</li>
                                <li data-category="Grains" onclick="filterCategory('Grains')" class="category-pill cursor-pointer px-4 py-2.5 rounded-xl whitespace-nowrap text-gray-600 hover:bg-green-50 hover:text-green-700 transition font-medium flex items-center"><i class="fa-solid fa-wheat-awn w-5 text-amber-500 mr-2 text-sm"></i> Grains</li>
                            </ul>
                            <div class="h-px bg-gray-100 my-5"></div>
                            <div class="space-y-6">
                                <div>
                                    <h3 class="text-sm font-bold text-gray-900 mb-2.5 flex items-center gap-1.5"><i class="fa-solid fa-location-dot text-gray-400 text-xs"></i> Location</h3>
                                    <select id="filter-barangay" onchange="applyFilters()" class="w-full border border-gray-200 rounded-xl px-3 py-2.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 transition">
                                        <option value="">All barangays</option>
                                        <?php foreach ($tayabas_barangays as $b): ?>
                                            <option value="<?= htmlspecialchars($b) ?>"><?= htmlspecialchars($b) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div>
                                    <h3 class="text-sm font-bold text-gray-900 mb-2.5">Price range (₱)</h3>
                                    <div class="flex items-center gap-2">
                                        <input type="number" id="filter-min" min="0" placeholder="0" oninput="applyFilters()" class="w-full border border-gray-200 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 transition">
                                        <span class="text-gray-300">–</span>
                                        <input type="number" id="filter-max" min="0" placeholder="Max" oninput="applyFilters()" class="w-full border border-gray-200 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 transition">
                                    </div>
                                </div>
                                <div>
                                    <h3 class="text-sm font-bold text-gray-900 mb-2.5">Sort by</h3>
                                    <select id="filter-sort" onchange="applyFilters()" class="w-full border border-gray-200 rounded-xl px-3 py-2.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 transition">
                                        <option value="latest">Latest posts</option>
                                        <option value="price-asc">Price: low to high</option>
                                        <option value="price-desc">Price: high to low</option>
                                        <option value="name">Name: A to Z</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </aside>
                    <div class="flex-grow">
                        <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-8 gap-4">
                            <div>
                                <p class="text-xs font-bold tracking-widest uppercase text-green-700 mb-2 flex items-center gap-2"><span class="w-5 h-px bg-green-400"></span> Marketplace</p>
                                <h2 class="text-4xl md:text-5xl font-serif font-bold text-[#052e16] leading-tight">Find fresh products<br>near you</h2>
                            </div>
                            <div class="relative w-full sm:w-72">
                                <input type="text" id="search-input" oninput="handleSearch()" placeholder="Search products or sellers..." class="border border-gray-200 rounded-xl pl-11 pr-10 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 w-full text-sm shadow-sm transition">
                                <i class="fa-solid fa-magnifying-glass absolute left-4 top-3.5 text-gray-400 text-sm"></i>
                                <button id="clear-search" onclick="clearSearch()" class="absolute right-3 top-3 text-gray-400 hover:text-gray-600 hidden transition">
                                    <i class="fa-solid fa-times"></i>
                                </button>
                            </div>
                        </div>
                        <div class="flex justify-between items-center mb-5">
                            <span id="listing-count" class="text-sm font-semibold text-gray-500 bg-gray-100 px-3 py-1.5 rounded-lg">0 listings</span>
                            <button type="button" onclick="clearFilters()" class="text-sm font-bold text-amber-700 hover:text-green-800 transition flex items-center gap-1"><i class="fa-solid fa-rotate-left text-xs"></i> Clear filters</button>
                        </div>
                        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6" id="shop-products-container">
                            <!-- Products injected via JS -->
                        </div>
                    </div>
                </div>
            </section>

            <!-- 3. ABOUT US PAGE -->
            <section id="page-about" class="page-section hidden">
                <div class="relative bg-gradient-to-br from-green-800 via-green-700 to-emerald-800 py-24 text-center text-white overflow-hidden">
                    <div class="absolute inset-0 opacity-10" style="background-image: radial-gradient(circle at 20% 30%, white 1px, transparent 1px); background-size: 40px 40px;"></div>
                    <div class="relative z-10 max-w-3xl mx-auto px-4">
                        <div class="w-20 h-20 bg-white/10 backdrop-blur-md rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-inner border border-white/20">
                            <i class="fa-solid fa-leaf text-4xl text-yellow-300"></i>
                        </div>
                        <h2 class="text-4xl md:text-5xl font-bold mb-5 font-serif">About FarmDirect</h2>
                        <p class="text-green-100/90 text-lg max-w-2xl mx-auto">FarmDirect is an online agricultural marketplace connecting farmers, sellers, and buyers across the Philippines, making fresh farm products easier to discover, list, and trade.</p>
                    </div>
                </div>

                <div class="bg-gray-50 py-20">
                    <div class="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
                        <div class="bg-white p-10 md:p-16 rounded-3xl shadow-sm border border-gray-100 relative overflow-hidden">
                            <div class="absolute top-0 left-0 w-full h-1.5 bg-gradient-to-r from-green-400 via-emerald-500 to-green-600"></div>
                            <div class="w-12 h-12 bg-green-50 rounded-2xl flex items-center justify-center mb-6">
                                <i class="fa-solid fa-bullseye text-2xl text-green-700"></i>
                            </div>
                            <h3 class="text-3xl font-bold mb-6 text-gray-900 font-serif">Our Mission</h3>
                            <p class="text-gray-600 text-lg leading-relaxed">
                                Agriculture is the backbone of countless communities across the Philippines, yet many farmers still struggle to reach wider markets and fair prices. FarmDirect was built to bridge that gap. We strive to empower local farmers and producers by providing a direct, reliable, and accessible digital marketplace where they can showcase their harvests to a nationwide audience. By connecting them directly with buyers and businesses, we aim to foster sustainable agricultural practices, strengthen local economies, and ensure that every Filipino has access to fresh, high-quality farm products.
                            </p>
                        </div>
                    </div>
                </div>

                <div class="bg-white py-20">
                    <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
                        <div class="text-center mb-14">
                            <span class="inline-flex items-center gap-2 bg-green-100 text-green-800 text-sm font-bold tracking-wider uppercase px-5 py-2 rounded-full mb-5"><i class="fa-solid fa-heart text-green-600"></i> What We Stand For</span>
                            <h2 class="text-3xl md:text-5xl font-bold text-gray-900 font-serif">Our Values</h2>
                        </div>
                        
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                            <div class="bg-white p-8 rounded-2xl border border-gray-100 hover:border-green-300 hover:shadow-xl transition-all duration-300 group card-hover">
                                <div class="w-14 h-14 bg-gradient-to-br from-green-50 to-green-100 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                                    <i class="fa-solid fa-handshake text-2xl text-green-600"></i>
                                </div>
                                <h3 class="text-xl font-bold mb-3 text-gray-900">Direct Connections</h3>
                                <p class="text-gray-500 text-sm leading-relaxed">We cut out unnecessary middlemen so farmers and buyers can deal with each other directly, building relationships that last beyond a single sale.</p>
                            </div>
                            <div class="bg-white p-8 rounded-2xl border border-gray-100 hover:border-green-300 hover:shadow-xl transition-all duration-300 group card-hover">
                                <div class="w-14 h-14 bg-gradient-to-br from-green-50 to-green-100 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                                    <i class="fa-solid fa-shield-halved text-2xl text-green-600"></i>
                                </div>
                                <h3 class="text-xl font-bold mb-3 text-gray-900">Trust & Transparency</h3>
                                <p class="text-gray-500 text-sm leading-relaxed">Every listing, price, and conversation happens in the open, giving buyers and sellers the confidence to trade with people they've never met in person.</p>
                            </div>
                            <div class="bg-white p-8 rounded-2xl border border-gray-100 hover:border-green-300 hover:shadow-xl transition-all duration-300 group card-hover">
                                <div class="w-14 h-14 bg-gradient-to-br from-green-50 to-green-100 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                                    <i class="fa-solid fa-map-location-dot text-2xl text-green-600"></i>
                                </div>
                                <h3 class="text-xl font-bold mb-3 text-gray-900">Community First</h3>
                                <p class="text-gray-500 text-sm leading-relaxed">FarmDirect is built around local communities across the Philippines, ensuring that economic growth stays within the regions where our food is grown.</p>
                            </div>
                            <div class="bg-white p-8 rounded-2xl border border-gray-100 hover:border-green-300 hover:shadow-xl transition-all duration-300 group card-hover">
                                <div class="w-14 h-14 bg-gradient-to-br from-green-50 to-green-100 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                                    <i class="fa-solid fa-seedling text-2xl text-green-600"></i>
                                </div>
                                <h3 class="text-xl font-bold mb-3 text-gray-900">Growth for Farmers</h3>
                                <p class="text-gray-500 text-sm leading-relaxed">We give small and independent farmers the same digital reach as larger enterprises, helping them scale their operations and secure fairer prices.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- MEET YOUR FARMERS (DYNAMIC) -->
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 text-center">
                    <h2 class="text-4xl md:text-5xl font-bold mb-4 font-serif text-gray-900">Meet Your Farmers.</h2>
                    <div class="flex items-center justify-center gap-2 mb-12">
                        <span class="w-8 h-px bg-green-300"></span>
                        <i class="fa-solid fa-leaf text-green-600 text-2xl"></i>
                        <span class="w-8 h-px bg-green-300"></span>
                    </div>
                    <p class="text-gray-500 max-w-2xl mx-auto mb-14 text-lg">We connect you directly with local farmers to ensure you get the freshest produce while supporting sustainable agriculture.</p>
                    
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-8 text-left">
                        <?php foreach ($display_sellers as $s): ?>
                        <div class="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden group card-hover">
                            <?php if($s['profile_pic']): ?>
                                <div class="h-[300px] w-full bg-gray-50 relative flex items-center justify-center overflow-hidden">
                                    <img src="<?= htmlspecialchars($s['profile_pic']) ?>" class="w-full h-full object-contain object-center group-hover:scale-105 transition-transform duration-500" alt="<?= htmlspecialchars($s['username']) ?>">
                                </div>
                            <?php else: ?>
                                <div class="h-[300px] farm-bg-1 group-hover:scale-105 transition-transform duration-500 relative">
                                    <div class="absolute inset-0 bg-gradient-to-t from-black/40 to-transparent"></div>
                                </div>
                            <?php endif; ?>
                            <div class="p-6">
                                <h3 class="text-xl font-bold mb-2 capitalize text-gray-900"><?= htmlspecialchars($s['username']) ?></h3>
                                <p class="text-gray-500 text-sm leading-relaxed">A dedicated farmer from Tayabas City committed to providing fresh, high-quality produce using sustainable and natural farming methods.</p>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </section>

            <!-- 4. CART PAGE -->
            <section id="page-cart" class="page-section hidden">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <div class="flex items-center gap-3 mb-8">
                        <div class="w-12 h-12 bg-green-50 rounded-2xl flex items-center justify-center">
                            <i class="fa-solid fa-cart-shopping text-xl text-green-700"></i>
                        </div>
                        <div>
                            <h2 class="text-3xl font-bold text-gray-900">Your Cart</h2>
                            <p class="text-sm text-gray-500">Review your items before checkout</p>
                        </div>
                    </div>
                    <div class="flex flex-col lg:flex-row gap-8">
                        <div class="w-full lg:w-2/3 bg-white rounded-2xl shadow-sm border border-gray-100 overflow-x-auto">
                            <table class="w-full text-left min-w-[600px]">
                                <thead class="bg-gray-50/80 border-b border-gray-100">
                                    <tr>
                                        <th class="p-4 font-bold text-gray-600 text-xs uppercase tracking-wider">Item</th>
                                        <th class="p-4 font-bold text-gray-600 text-xs uppercase tracking-wider text-center">Quantity</th>
                                        <th class="p-4 font-bold text-gray-600 text-xs uppercase tracking-wider">Price</th>
                                        <th class="p-4 font-bold text-gray-600 text-xs uppercase tracking-wider">Total</th>
                                        <th class="p-4"></th>
                                    </tr>
                                </thead>
                                <tbody id="cart-table-body">
                                    <!-- Cart items injected via JS -->
                                </tbody>
                            </table>
                            <div id="empty-cart-message" class="p-12 text-center text-gray-500 hidden">
                                <div class="w-16 h-16 bg-gray-50 rounded-2xl flex items-center justify-center mx-auto mb-4">
                                    <i class="fa-solid fa-cart-shopping text-2xl text-gray-300"></i>
                                </div>
                                Your cart is currently empty. <a href="#" onclick="showPage('shop')" class="text-green-600 font-bold underline hover:text-green-800 transition">Go shopping</a>.
                            </div>
                        </div>

                        <div class="w-full lg:w-1/3">
                            <div class="bg-white rounded-2xl p-6 shadow-sm border border-gray-100 sticky top-24">
                                <h3 class="text-xl font-bold mb-5 text-gray-900 flex items-center gap-2"><i class="fa-solid fa-receipt text-green-600"></i> Order Summary</h3>
                                <div class="flex justify-between mb-3 text-gray-500 text-sm">
                                    <span>Subtotal</span>
                                    <span id="cart-subtotal" class="font-semibold text-gray-900">₱0.00</span>
                                </div>
                                <div class="flex justify-between mb-5 text-gray-500 text-sm">
                                    <span>Shipping</span>
                                    <span class="text-green-600 font-semibold">Free</span>
                                </div>
                                <div class="flex justify-between mb-5 text-gray-500 text-sm">
                                    <span>Payment</span>
                                    <span class="text-green-600 font-semibold"><i class="fa-solid fa-money-bill-wave mr-1"></i> Pickup / COD</span>
                                </div>
                                <div class="border-t border-gray-100 pt-5 flex justify-between font-bold text-lg mb-6">
                                    <span class="text-gray-900">Total</span>
                                    <span id="cart-total" class="text-green-700">₱0.00</span>
                                </div>
                                <button onclick="checkout()" class="w-full bg-gradient-to-r from-green-700 to-green-800 text-white py-3.5 rounded-xl hover:from-green-800 hover:to-green-900 transition font-bold btn-glow shadow-md">Checkout <i class="fa-solid fa-arrow-right ml-1 text-xs"></i></button>
                                <p class="text-center text-xs text-gray-400 mt-4"><i class="fa-solid fa-lock mr-1"></i> Secure checkout</p>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- CHECKOUT PAGE (Real order system: Pickup or COD) -->
            <section id="page-checkout" class="page-section hidden bg-[#f8faf7] min-h-screen">
                <div class="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <a href="#" onclick="showPage('cart')" class="text-sm text-gray-500 hover:text-green-700 inline-flex items-center gap-2 mb-5 transition font-medium"><i class="fa-solid fa-arrow-left text-xs"></i> Back to Cart</a>

                    <h2 class="text-4xl md:text-5xl font-serif font-bold text-[#052e16] mt-5 mb-8">Checkout</h2>

                    <div id="checkout-msg" class="hidden text-sm rounded-xl px-4 py-3 mb-5"></div>

                    <div class="flex flex-col lg:flex-row gap-6">
                        <div class="w-full lg:w-2/3 bg-white rounded-2xl shadow-sm border border-gray-100 p-6 md:p-8">

                            <!-- FULFILLMENT METHOD (Pickup / COD) -->
                            <h3 class="text-lg font-bold text-gray-900 mb-4 font-serif">How would you like to receive your order?</h3>
                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-7">
                                <label class="ff-radio cursor-pointer">
                                    <input type="radio" name="fulfillment" value="COD" class="sr-only" checked onchange="onFulfillmentChange('COD')">
                                    <div class="ff-radio-card border-2 border-gray-200 rounded-2xl p-5 flex items-start gap-3">
                                        <div class="w-10 h-10 rounded-xl bg-blue-50 flex items-center justify-center flex-shrink-0"><i class="fa-solid fa-truck-fast text-blue-600"></i></div>
                                        <div>
                                            <p class="font-bold text-gray-900 text-sm">Cash on Delivery</p>
                                            <p class="text-xs text-gray-500 mt-0.5">Deliver to my address. Pay cash to the rider.</p>
                                        </div>
                                    </div>
                                </label>
                                <label class="ff-radio cursor-pointer">
                                    <input type="radio" name="fulfillment" value="PICKUP" class="sr-only" onchange="onFulfillmentChange('PICKUP')">
                                    <div class="ff-radio-card border-2 border-gray-200 rounded-2xl p-5 flex items-start gap-3">
                                        <div class="w-10 h-10 rounded-xl bg-green-50 flex items-center justify-center flex-shrink-0"><i class="fa-solid fa-store text-green-700"></i></div>
                                        <div>
                                            <p class="font-bold text-gray-900 text-sm">Pickup at Seller</p>
                                            <p class="text-xs text-gray-500 mt-0.5">Collect from the farm. Pay cash on pickup.</p>
                                        </div>
                                    </div>
                                </label>
                            </div>

                            <h3 class="text-lg font-bold text-gray-900 mb-5 font-serif">Contact Information</h3>
                            <div class="space-y-4">
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-sm font-bold text-gray-700 mb-1.5">Full name</label>
                                        <input type="text" id="co-name" placeholder="Your full name" class="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 transition">
                                    </div>
                                    <div>
                                        <label class="block text-sm font-bold text-gray-700 mb-1.5">Phone number</label>
                                        <input type="tel" id="co-phone" placeholder="09xxxxxxxxx" class="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 transition">
                                    </div>
                                </div>

                                <!-- DELIVERY ADDRESS (shown for COD) -->
                                <div id="cod-address-block" class="space-y-4">
                                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <label class="block text-sm font-bold text-gray-700 mb-1.5">City/Municipality</label>
                                            <input type="text" value="Tayabas City" readonly class="w-full border border-gray-200 rounded-xl px-4 py-3 bg-gray-50 text-gray-500 text-sm">
                                        </div>
                                        <div>
                                            <label class="block text-sm font-bold text-gray-700 mb-1.5">Barangay</label>
                                            <select id="co-barangay" class="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 transition">
                                                <option value="">Select barangay</option>
                                                <?php foreach ($tayabas_barangays as $b): ?>
                                                    <option value="<?= htmlspecialchars($b) ?>"><?= htmlspecialchars($b) ?></option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                    </div>
                                    <div>
                                        <label class="block text-sm font-bold text-gray-700 mb-1.5">House # / Street / Purok</label>
                                        <input type="text" id="co-street" placeholder="e.g. Purok 3, Mahanika Street" class="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 transition">
                                    </div>
                                    <div>
                                        <label class="block text-sm font-bold text-gray-700 mb-1.5">Delivery notes (optional)</label>
                                        <input type="text" id="co-notes" placeholder="Landmark, gate color, preferred time, etc." class="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 transition">
                                    </div>
                                </div>

                                <!-- PICKUP INFO (shown for Pickup) -->
                                <div id="pickup-block" class="hidden space-y-4">
                                    <div class="bg-green-50 border border-green-100 rounded-xl p-4 flex gap-3">
                                        <div class="w-10 h-10 bg-white rounded-xl flex items-center justify-center flex-shrink-0 shadow-sm"><i class="fa-solid fa-store text-green-700"></i></div>
                                        <div>
                                            <p class="font-bold text-gray-900 text-sm">Pickup at the seller's farm</p>
                                            <p class="text-xs text-gray-600 mt-0.5">The seller's registered pickup address will be shown on your order confirmation. Bring your order reference and pay cash on pickup.</p>
                                        </div>
                                    </div>
                                    <div>
                                        <label class="block text-sm font-bold text-gray-700 mb-1.5">Pickup notes (optional)</label>
                                        <input type="text" id="co-pickup-notes" placeholder="e.g. Preferred pickup time, vehicle, etc." class="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 transition">
                                    </div>
                                </div>

                                <!-- PAYMENT SUMMARY -->
                                <div class="bg-green-50 border border-green-100 rounded-xl p-4 flex gap-3">
                                    <div class="w-10 h-10 bg-white rounded-xl flex items-center justify-center flex-shrink-0 shadow-sm"><i class="fa-solid fa-money-bill-wave text-green-700"></i></div>
                                    <div>
                                        <p class="font-bold text-gray-900 text-sm" id="payment-title">Cash on Delivery (COD)</p>
                                        <p class="text-xs text-gray-600 mt-0.5" id="payment-desc">Pay in cash when your order is delivered. Please prepare the exact amount.</p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="w-full lg:w-1/3">
                            <div class="bg-white rounded-2xl p-6 shadow-sm border border-gray-100 sticky top-24">
                                <h3 class="text-lg font-bold text-gray-900 mb-4 font-serif">Order Summary</h3>
                                <div id="checkout-items" class="space-y-2 mb-4 max-h-72 overflow-y-auto"></div>
                                <div class="border-t border-gray-100 pt-4 flex justify-between text-sm mb-2">
                                    <span class="text-gray-500">Subtotal</span>
                                    <span id="checkout-subtotal" class="font-semibold text-gray-900">₱0.00</span>
                                </div>
                                <div class="flex justify-between text-sm mb-2">
                                    <span class="text-gray-500">Shipping</span>
                                    <span id="checkout-shipping" class="text-green-600 font-semibold">Free</span>
                                </div>
                                <div class="flex justify-between text-sm mb-4">
                                    <span class="text-gray-500">Payment</span>
                                    <span id="checkout-payment" class="text-green-600 font-semibold">Cash on Delivery</span>
                                </div>
                                <div class="border-t border-gray-100 pt-4 flex justify-between font-bold text-lg mb-5">
                                    <span class="text-gray-900">Total</span>
                                    <span id="checkout-total" class="text-green-700">₱0.00</span>
                                </div>
                                <button onclick="placeOrder()" class="w-full bg-gradient-to-r from-green-700 to-green-800 text-white py-3.5 rounded-xl hover:from-green-800 hover:to-green-900 transition font-bold btn-glow shadow-md">Place Order</button>
                                <p class="text-center text-xs text-gray-400 mt-4"><i class="fa-solid fa-shield-halved mr-1"></i> Cash payment on pickup or delivery</p>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- BUYER: DASHBOARD -->
            <section id="page-buyer-dashboard" class="page-section hidden bg-[#f8faf7] min-h-screen">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <span class="inline-flex items-center gap-2 bg-white border border-green-200 text-green-800 text-xs font-bold tracking-widest uppercase px-4 py-1.5 rounded-full shadow-sm"><i class="fa-solid fa-chart-pie text-green-600"></i> Dashboard</span>
                    <h2 class="text-4xl md:text-5xl font-serif font-bold text-[#052e16] mt-5 mb-10">Welcome back, <span class="gradient-text"><?= htmlspecialchars($username) ?></span></h2>

                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
                        <div onclick="showPage('saved')" class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 cursor-pointer hover:border-green-300 card-hover group">
                            <div class="w-11 h-11 bg-gradient-to-br from-green-50 to-green-100 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform"><i class="fa-regular fa-heart text-green-700"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Saved products</p>
                            <h3 id="buyer-stat-saved" class="text-3xl font-extrabold text-gray-900">0</h3>
                        </div>
                        <div onclick="showPage('cart')" class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 cursor-pointer hover:border-green-300 card-hover group">
                            <div class="w-11 h-11 bg-gradient-to-br from-green-50 to-green-100 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform"><i class="fa-solid fa-cart-shopping text-green-700"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Items in cart</p>
                            <h3 id="buyer-stat-cart" class="text-3xl font-extrabold text-gray-900">0</h3>
                        </div>
                        <div onclick="showPage('offers')" class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 cursor-pointer hover:border-green-300 card-hover group">
                            <div class="w-11 h-11 bg-gradient-to-br from-green-50 to-green-100 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform"><i class="fa-solid fa-handshake text-green-700"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Active offers</p>
                            <h3 id="buyer-stat-offers" class="text-3xl font-extrabold text-gray-900">0</h3>
                        </div>
                        <div onclick="showPage('purchases')" class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 cursor-pointer hover:border-green-300 card-hover group">
                            <div class="w-11 h-11 bg-gradient-to-br from-green-50 to-green-100 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform"><i class="fa-solid fa-bag-shopping text-green-700"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Purchases</p>
                            <h3 id="buyer-stat-purchases" class="text-3xl font-extrabold text-gray-900">0</h3>
                        </div>
                    </div>

                    <div class="flex justify-between items-center mb-6">
                        <h3 class="text-2xl font-bold text-gray-900 font-serif">Fresh in Tayabas</h3>
                        <a href="#" onclick="showPage('shop')" class="text-green-700 text-sm font-bold hover:text-green-800 hover:underline transition flex items-center gap-1">Browse all <i class="fa-solid fa-arrow-right text-xs"></i></a>
                    </div>
                    <div id="buyer-latest-products" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6"></div>
                </div>
            </section>

            <!-- BUYER: MY OFFERS -->
            <section id="page-offers" class="page-section hidden bg-[#f8faf7] min-h-screen">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <span class="inline-flex items-center gap-2 bg-white border border-green-200 text-green-800 text-xs font-bold tracking-widest uppercase px-4 py-1.5 rounded-full shadow-sm"><i class="fa-solid fa-handshake text-green-600"></i> My Offers</span>
                    <h2 class="text-4xl md:text-5xl font-serif font-bold text-[#052e16] mt-5 mb-10">Offers you've made</h2>
                    <div id="offers-list" class="space-y-4 mb-6"></div>
                    <div id="offers-empty" class="bg-white border border-dashed border-gray-200 rounded-2xl shadow-sm py-20 px-6 flex flex-col items-center text-center">
                        <div class="w-16 h-16 bg-green-50 rounded-2xl flex items-center justify-center mb-5"><i class="fa-solid fa-seedling text-2xl text-green-800"></i></div>
                        <h3 class="text-lg font-bold text-[#052e16] mb-1">No offers yet</h3>
                        <p class="text-gray-500 text-sm mb-7">Offers you send to sellers will show up here.</p>
                        <a href="#" onclick="showPage('shop')" class="bg-green-700 text-white px-7 py-2.5 rounded-xl text-sm font-bold hover:bg-green-800 transition btn-glow">Browse Marketplace</a>
                    </div>
                </div>
            </section>

            <!-- BUYER: SAVED PRODUCTS -->
            <section id="page-saved" class="page-section hidden bg-[#f8faf7] min-h-screen">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <span class="inline-flex items-center gap-2 bg-white border border-green-200 text-green-800 text-xs font-bold tracking-widest uppercase px-4 py-1.5 rounded-full shadow-sm"><i class="fa-regular fa-heart text-green-600"></i> Saved Products</span>
                    <h2 class="text-4xl md:text-5xl font-serif font-bold text-[#052e16] mt-5 mb-10">Products you've saved</h2>
                    <div id="saved-products-grid" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6"></div>
                    <div id="saved-empty" class="bg-white border border-dashed border-gray-200 rounded-2xl shadow-sm py-20 px-6 flex flex-col items-center text-center">
                        <div class="w-16 h-16 bg-green-50 rounded-2xl flex items-center justify-center mb-5"><i class="fa-solid fa-seedling text-2xl text-green-800"></i></div>
                        <h3 class="text-lg font-bold text-[#052e16] mb-1">No saved products yet</h3>
                        <p class="text-gray-500 text-sm mb-7">Tap the heart icon on any product to save it here for later.</p>
                        <a href="#" onclick="showPage('shop')" class="bg-green-700 text-white px-7 py-2.5 rounded-xl text-sm font-bold hover:bg-green-800 transition btn-glow">Browse Marketplace</a>
                    </div>
                </div>
            </section>

            <!-- BUYER: PURCHASES (real orders) -->
            <section id="page-purchases" class="page-section hidden bg-[#f8faf7] min-h-screen">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <span class="inline-flex items-center gap-2 bg-white border border-green-200 text-green-800 text-xs font-bold tracking-widest uppercase px-4 py-1.5 rounded-full shadow-sm"><i class="fa-solid fa-bag-shopping text-green-600"></i> Purchases</span>
                    <h2 class="text-4xl md:text-5xl font-serif font-bold text-[#052e16] mt-5 mb-10">Your orders</h2>
                    <div id="buyer-orders-list" class="space-y-4"></div>
                    <div id="buyer-orders-empty" class="bg-white border border-dashed border-gray-200 rounded-2xl shadow-sm py-20 px-6 flex flex-col items-center text-center">
                        <div class="w-16 h-16 bg-green-50 rounded-2xl flex items-center justify-center mb-5"><i class="fa-solid fa-seedling text-2xl text-green-800"></i></div>
                        <h3 class="text-lg font-bold text-[#052e16] mb-1">No purchases yet</h3>
                        <p class="text-gray-500 text-sm mb-7">Products you order will be listed here.</p>
                        <a href="#" onclick="showPage('shop')" class="bg-green-700 text-white px-7 py-2.5 rounded-xl text-sm font-bold hover:bg-green-800 transition btn-glow">Start shopping</a>
                    </div>
                </div>
            </section>

            <!-- 5. ORDERS PAGE (Buyer) -->
            <section id="page-orders" class="page-section hidden">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <h2 class="text-3xl font-bold mb-8">My Orders</h2>
                    <div id="orders-list" class="space-y-6">
                        <!-- Orders injected via JS -->
                    </div>
                    <div id="empty-orders-message" class="text-center text-gray-500 py-16 hidden">
                        You haven't placed any orders yet. <a href="#" onclick="showPage('shop')" class="text-green-600 underline">Start shopping</a>.
                    </div>
                </div>
            </section>

            <!-- ========================================== -->
            <!-- SELLER SECTIONS (LALABAS KAPAG SELLER)     -->
            <!-- ========================================== -->
            
            <!-- 6. SELLER: DASHBOARD -->
            <section id="page-dashboard" class="page-section hidden bg-[#f4f7f4] min-h-screen">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 hover:border-green-200 transition card-hover">
                            <div class="w-11 h-11 bg-gradient-to-br from-green-50 to-green-100 rounded-xl flex items-center justify-center mb-4"><i class="fa-solid fa-box text-green-600"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Listed products</p>
                            <h3 class="text-3xl font-extrabold text-gray-900">0</h3>
                            <p class="text-xs text-gray-400 mt-1.5"><i class="fa-solid fa-arrow-up-right-from-square mr-1 text-green-500"></i> 0% vs last month</p>
                        </div>
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 hover:border-green-200 transition card-hover">
                            <div class="w-11 h-11 bg-gradient-to-br from-green-50 to-green-100 rounded-xl flex items-center justify-center mb-4"><i class="fa-solid fa-bag-shopping text-green-600"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Total sold</p>
                            <h3 class="text-3xl font-extrabold text-gray-900">0</h3>
                            <p class="text-xs text-gray-400 mt-1.5"><i class="fa-solid fa-arrow-up-right-from-square mr-1 text-green-500"></i> 0% vs last month</p>
                        </div>
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 hover:border-green-200 transition card-hover">
                            <div class="w-11 h-11 bg-gradient-to-br from-green-50 to-green-100 rounded-xl flex items-center justify-center mb-4"><i class="fa-solid fa-wallet text-green-600"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Total revenue</p>
                            <h3 class="text-3xl font-extrabold text-gray-900">₱0</h3>
                            <p class="text-xs text-gray-400 mt-1.5"><i class="fa-solid fa-arrow-up-right-from-square mr-1 text-green-500"></i> 0% vs last month</p>
                        </div>
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 hover:border-red-200 transition card-hover">
                            <div class="w-11 h-11 bg-red-50 rounded-xl flex items-center justify-center mb-4"><i class="fa-solid fa-triangle-exclamation text-red-500"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Low stock items</p>
                            <h3 class="text-3xl font-extrabold text-gray-900">0</h3>
                            <p class="text-xs text-red-400 mt-1.5"><i class="fa-solid fa-triangle-exclamation mr-1"></i> Needs restock</p>
                        </div>
                    </div>

                    <div class="flex flex-col lg:flex-row gap-6 mb-10">
                        <div class="w-full lg:w-2/3 bg-white rounded-2xl shadow-sm border border-gray-100 p-6 flex flex-col justify-between h-96">
                            <div class="flex justify-between items-center">
                                <h3 class="text-xl font-bold text-gray-900">Sales this month</h3>
                                <div class="w-9 h-9 bg-green-50 rounded-lg flex items-center justify-center"><i class="fa-solid fa-chart-line text-green-600"></i></div>
                            </div>
                            <div class="flex-grow flex items-center justify-center text-gray-400">
                                <div class="text-center">
                                    <i class="fa-solid fa-chart-simple text-4xl text-gray-200 mb-3 block"></i>
                                    <p class="text-sm">No sales yet this month.</p>
                                </div>
                            </div>
                        </div>
                        <div class="w-full lg:w-1/3 bg-white rounded-2xl shadow-sm border border-gray-100 p-6 h-96 flex flex-col">
                            <div class="flex justify-between items-center mb-5">
                                <h3 class="text-xl font-bold text-gray-900">Low stock</h3>
                                <span class="bg-red-50 text-red-600 text-xs px-3 py-1.5 rounded-full font-bold">0 items</span>
                            </div>
                            <div class="text-gray-400 text-sm text-center mt-10">
                                <i class="fa-solid fa-box-open text-3xl text-gray-200 mb-3 block"></i>
                                Nothing low on stock right now.
                            </div>
                        </div>
                    </div>

                    <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-6">
                        <div class="flex justify-between items-center mb-4">
                            <h3 class="text-xl font-bold text-gray-900">Recent orders</h3>
                            <i class="fa-solid fa-ellipsis text-gray-300 text-lg"></i>
                        </div>
                        <p class="text-sm text-gray-400">No recent orders to show.</p>
                    </div>
                </div>
            </section>

            <!-- 7. SELLER: MANAGE PRODUCTS -->
            <section id="page-manage-products" class="page-section hidden bg-[#f8faf7] min-h-screen">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <div class="text-sm text-gray-500 mb-3 flex items-center gap-2"><i class="fa-solid fa-leaf text-green-700"></i> FarmDirect · Seller dashboard</div>
                    <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-10 gap-4">
                        <h2 class="text-4xl font-serif text-gray-900">Product management</h2>
                        <button onclick="toggleAddProductForm()" class="bg-gradient-to-r from-orange-500 to-amber-600 text-white px-6 py-3 rounded-xl font-bold hover:from-orange-600 hover:to-amber-700 transition flex items-center gap-2 text-sm shadow-lg shadow-orange-200/50 btn-glow">
                            <i class="fa-solid fa-plus"></i> Add product
                        </button>
                    </div>

                    <!-- MAIN EMPTY STATE -->
                    <div id="product-empty-state">
                        <?php if($product_success): ?>
                            <div class="bg-green-50 border border-green-200 text-green-700 p-4 rounded-xl mb-6 text-sm font-medium"><i class="fa-solid fa-circle-check mr-2"></i><?= htmlspecialchars($product_success) ?></div>
                        <?php endif; ?>
                        <div class="flex flex-col md:flex-row gap-4 mb-8 items-center">
                            <div class="relative w-full md:w-1/2">
                                <i class="fa-solid fa-magnifying-glass absolute left-4 top-3.5 text-gray-400 text-sm"></i>
                                <input type="text" placeholder="Search your products" class="w-full bg-white border border-gray-200 rounded-xl pl-11 pr-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 shadow-sm transition">
                            </div>
                            <div class="w-full md:w-1/4">
                                <select class="w-full bg-white border border-gray-200 rounded-xl px-4 py-3 text-gray-700 focus:outline-none focus:ring-2 focus:ring-green-500 shadow-sm appearance-none transition">
                                    <option>All categories</option>
                                </select>
                            </div>
                            <div id="product-count" class="text-sm text-gray-500 whitespace-nowrap font-medium">0 of 0 products</div>
                        </div>

                        <div id="my-products-list" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mb-6"></div>

                        <div id="product-empty-box" class="bg-[#fdfdfc] border-2 border-dashed border-gray-200 rounded-3xl p-16 flex flex-col items-center justify-center text-center mt-4">
                            <div class="w-20 h-20 bg-gray-50 rounded-2xl flex items-center justify-center mb-5">
                                <i class="fa-regular fa-image text-4xl text-gray-300"></i>
                            </div>
                            <h3 class="text-xl font-bold text-gray-900 mb-2">No products match yet</h3>
                            <p class="text-gray-500 mb-7 text-sm">Try a different search, or list something new.</p>
                            <button onclick="toggleAddProductForm()" class="bg-[#1e4620] text-white px-7 py-3 rounded-xl font-bold hover:bg-green-800 transition text-sm btn-glow shadow-md">
                                Add your first product
                            </button>
                        </div>
                    </div>

                    <!-- ADD PRODUCT FORM -->
                    <div id="add-product-form" class="hidden bg-white rounded-2xl shadow-sm border border-gray-100 p-8">
                        <div class="flex items-center gap-3 mb-8 text-gray-900 font-bold text-xl font-serif">
                            <button onclick="toggleAddProductForm()" class="w-9 h-9 rounded-lg bg-gray-50 hover:bg-gray-100 flex items-center justify-center transition"><i class="fa-solid fa-arrow-left text-sm"></i></button>
                            Add a new product
                        </div>

                        <form method="POST" action="" enctype="multipart/form-data" class="space-y-7">
                            <!-- Photos -->
                            <div>
                                <label class="block text-sm font-bold text-gray-700 mb-3">Photos & Video</label>
                                <div onclick="document.getElementById('product-photos').click()" class="border-2 border-dashed border-gray-200 rounded-2xl p-8 flex flex-col items-center justify-center text-center cursor-pointer hover:bg-green-50/30 hover:border-green-300 transition-all">
                                    <input type="file" id="product-photos" name="photos[]" accept="image/jpeg,image/png,image/webp" multiple class="hidden" onclick="event.stopPropagation()" onchange="previewPhotos(this)">
                                    <div class="w-12 h-12 bg-green-50 rounded-xl flex items-center justify-center mb-3">
                                        <i class="fa-solid fa-arrow-up-from-bracket text-xl text-green-600"></i>
                                    </div>
                                    <span class="text-sm font-bold text-gray-700">Add Photo or Video</span>
                                    <span class="text-xs text-gray-400 mt-1">JPG, PNG, WEBP, MP4, MOV</span>
                                </div>
                                <div id="photo-preview" class="grid grid-cols-5 gap-2 mt-4"></div>
                                <p class="text-xs text-gray-400 mt-2"><i class="fa-solid fa-circle-info mr-1"></i> Upload up to 10 photos and 1 video (up to 60 seconds). The first photo is the product cover.</p>
                            </div>

                            <!-- Name -->
                            <div>
                                <label class="block text-sm font-bold text-gray-700 mb-2">Product name</label>
                                <input type="text" name="name" placeholder="e.g. Sinandomeng Rice" required class="w-full border border-gray-200 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 text-sm transition">
                            </div>

                            <!-- Category & Unit -->
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                                <div>
                                    <label class="block text-sm font-bold text-gray-700 mb-2">Category</label>
                                    <select name="category" required class="w-full border border-gray-200 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 text-sm appearance-none transition">
                                        <option value="">Select a category</option>
                                        <option value="Vegetables">Vegetables</option>
                                        <option value="Fruits">Fruits</option>
                                        <option value="Dairy">Dairy</option>
                                        <option value="Grains">Grains</option>
                                    </select>
                                </div>
                                <div>
                                    <label class="block text-sm font-bold text-gray-700 mb-2">Unit</label>
                                    <select name="unit" required class="w-full border border-gray-200 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 text-sm appearance-none transition">
                                        <option value="per kg">per kg</option>
                                        <option value="per bunch">per bunch</option>
                                        <option value="per liter">per liter</option>
                                        <option value="per pc">per pc</option>
                                        <option value="per dozen">per dozen</option>
                                    </select>
                                </div>
                            </div>

                            <!-- Price & Stock -->
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                                <div>
                                    <label class="block text-sm font-bold text-gray-700 mb-2">Price (₱)</label>
                                    <input type="number" step="0.01" name="price" placeholder="0.00" required class="w-full border border-gray-200 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 text-sm transition">
                                </div>
                                <div>
                                    <label class="block text-sm font-bold text-gray-700 mb-2">Stock quantity</label>
                                    <input type="number" name="stock" placeholder="0" required class="w-full border border-gray-200 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 text-sm transition">
                                </div>
                            </div>

                            <!-- Minimum Order -->
                            <div>
                                <label class="block text-sm font-bold text-gray-700 mb-2">Minimum order (per kg)</label>
                                <input type="number" name="min_order" placeholder="1" required class="w-full border border-gray-200 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 text-sm transition">
                            </div>

                            <!-- Description -->
                            <div>
                                <label class="block text-sm font-bold text-gray-700 mb-2">Description</label>
                                <textarea name="description" rows="4" placeholder="Tell buyers what makes this product good" class="w-full border border-gray-200 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 text-sm resize-none transition"></textarea>
                            </div>

                            <!-- Location -->
                            <div class="pt-5 border-t border-gray-100">
                                <label class="block text-sm font-bold text-gray-700 mb-3"><i class="fa-solid fa-location-dot text-gray-400 mr-1.5"></i> Pickup location</label>
                                <div class="flex items-center gap-2.5 mb-5 bg-green-50/50 rounded-xl px-4 py-3">
                                    <input type="checkbox" checked class="w-4 h-4 text-green-600 rounded accent-green-700">
                                    <span class="text-sm text-gray-700 font-medium">Use my registered address as pickup location</span>
                                </div>

                                <div class="grid grid-cols-1 md:grid-cols-2 gap-5 mb-5">
                                    <div>
                                        <label class="block text-xs font-bold text-gray-700 mb-1.5">City/Municipality</label>
                                        <input type="text" value="Tayabas City" readonly class="w-full border border-gray-200 rounded-xl px-4 py-3 bg-gray-50 text-gray-500 text-sm">
                                    </div>
                                    <div>
                                        <label class="block text-xs font-bold text-gray-700 mb-1.5">Barangay</label>
                                        <select name="barangay" required class="w-full border border-gray-200 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 text-sm appearance-none transition">
                                            <option value="">Barangay</option>
                                            <?php foreach ($tayabas_barangays as $b): ?>
                                                <option value="<?= htmlspecialchars($b) ?>"><?= htmlspecialchars($b) ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                </div>

                                <div>
                                    <label class="block text-xs font-bold text-gray-700 mb-1.5">House # / Street / Purok</label>
                                    <input type="text" name="street" placeholder="e.g. Purok 3, Mahanika Street" class="w-full border border-gray-200 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 text-sm transition">
                                </div>
                            </div>

                            <div class="pt-6 flex items-center gap-4">
                                <button type="submit" name="add_product" class="bg-[#1e4620] text-white px-8 py-3 rounded-xl font-bold hover:bg-green-800 transition text-sm btn-glow shadow-md">
                                    <i class="fa-solid fa-plus mr-1.5"></i> Publish product
                                </button>
                                <button type="button" onclick="toggleAddProductForm()" class="text-sm text-gray-500 hover:text-gray-800 font-semibold px-4 py-2 rounded-xl hover:bg-gray-50 transition">Cancel</button>
                            </div>
                        </form>
                    </div>

                </div>
            </section>

            <!-- 8. SELLER: MANAGE ORDERS -->
            <section id="page-manage-orders" class="page-section hidden">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <h2 class="text-3xl font-bold mb-8">Manage Orders</h2>
                    <div class="bg-white p-8 rounded-2xl shadow-sm border border-gray-100 mb-8">
                        <h3 class="text-lg font-bold text-gray-900 mb-5 flex items-center gap-2"><i class="fa-solid fa-handshake text-green-600"></i> Offers received</h3>
                        <div id="seller-offers-list" class="space-y-4"><p class="text-gray-500 text-sm">No offers yet.</p></div>
                    </div>
                    <div class="bg-white p-8 rounded-2xl shadow-sm border border-gray-100">
                        <h3 class="text-lg font-bold text-gray-900 mb-5 flex items-center gap-2"><i class="fa-solid fa-box text-green-600"></i> Real orders (Pickup / COD)</h3>
                        <div id="seller-orders-list" class="space-y-4"><p class="text-gray-500 text-sm">No orders yet.</p></div>
                    </div>
                </div>
            </section>

            <!-- 9. SELLER: REPORT -->
            <section id="page-report" class="page-section hidden">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <h2 class="text-3xl font-bold mb-8">Report</h2>
                    <div class="bg-white p-8 rounded-2xl shadow-sm border border-gray-100">
                        <div class="text-center py-16 text-gray-400">
                            <i class="fa-solid fa-chart-pie text-5xl text-gray-200 mb-4 block"></i>
                            <p class="text-sm">Sales report charts go here...</p>
                        </div>
                    </div>
                </div>
            </section>

            <!-- 10. SELLER/BUYER: PROFILE -->
            <section id="page-profile" class="page-section hidden bg-[#fcfcfc] min-h-screen">
                <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                    <!-- Cover Banner -->
                    <div class="w-full h-64 bg-gradient-to-r from-green-700 via-emerald-600 to-green-800 rounded-3xl relative mb-16 overflow-hidden">
                        <div class="absolute inset-0 opacity-10" style="background-image: radial-gradient(circle at 30% 50%, white 2px, transparent 2px); background-size: 50px 50px;"></div>
                    </div>
                    
                    <!-- Profile Info -->
                    <div class="flex flex-col md:flex-row justify-between items-start md:items-end -mt-24 px-4 sm:px-8 mb-10 relative z-10">
                        <div class="flex items-end gap-6">
                            <?php if($user_profile_pic): ?>
                                <img src="<?= htmlspecialchars($user_profile_pic) ?>" class="w-32 h-32 rounded-full border-4 border-white object-cover shadow-xl bg-white ring-4 ring-green-100">
                            <?php else: ?>
                                <div class="w-32 h-32 bg-gradient-to-br from-green-100 to-green-200 rounded-full border-4 border-white flex items-center justify-center text-4xl text-green-700 font-extrabold shadow-xl ring-4 ring-green-100">
                                    <?= strtoupper(substr($username, 0, 2)) ?>
                                </div>
                            <?php endif; ?>
                            <div class="mb-2">
                                <h2 class="text-4xl font-bold text-gray-900 capitalize"><?= htmlspecialchars($username) ?></h2>
                                <div class="flex flex-wrap items-center gap-4 text-sm text-gray-500 mt-2">
                                    <span><i class="fa-solid fa-location-dot mr-1.5 text-green-600"></i> Tayabas City, Quezon</span>
                                    <span><i class="fa-regular fa-calendar mr-1.5 text-green-600"></i> Joined <?= date('F d, Y') ?></span>
                                    <span><i class="fa-solid fa-box mr-1.5 text-green-600"></i> 0 Products</span>
                                </div>
                            </div>
                        </div>
                        <div class="flex gap-3 mt-4 md:mt-0">
                            <?php if($user_role === 'Seller'): ?>
                                <a href="#" onclick="showPage('manage-products')" class="bg-green-700 text-white px-5 py-2.5 rounded-xl text-sm font-bold hover:bg-green-800 transition btn-glow shadow-sm">Manage Products</a>
                                <a href="#" onclick="showPage('dashboard')" class="bg-white border border-gray-200 text-gray-700 px-5 py-2.5 rounded-xl text-sm font-bold hover:bg-gray-50 transition shadow-sm">Dashboard</a>
                            <?php elseif($user_role === 'Admin'): ?>
                                <a href="#" onclick="showPage('admin-dashboard')" class="bg-green-700 text-white px-5 py-2.5 rounded-xl text-sm font-bold hover:bg-green-800 transition btn-glow shadow-sm">Admin Dashboard</a>
                            <?php endif; ?>
                            <form method="POST" action="" enctype="multipart/form-data" class="relative">
                                <input type="file" name="profile_pic" onchange="this.form.submit()" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer" title="Upload Profile Picture">
                                <button type="button" class="bg-white border border-gray-200 text-gray-700 px-5 py-2.5 rounded-xl text-sm font-bold hover:bg-gray-50 transition shadow-sm pointer-events-none"><i class="fa-solid fa-camera mr-1.5 text-gray-400"></i> Upload Photo</button>
                                <input type="hidden" name="upload_profile" value="1">
                            </form>
                        </div>
                    </div>

                    <!-- Body -->
                    <div class="flex flex-col lg:flex-row gap-8">
                        <!-- Sidebar -->
                        <div class="w-full lg:w-1/3">
                            <div class="bg-white border border-gray-100 rounded-2xl p-7 shadow-sm">
                                <h4 class="text-xs font-bold text-gray-400 uppercase tracking-widest mb-5 flex items-center gap-2"><i class="fa-solid fa-circle-info text-green-500"></i> Account Details</h4>
                                <ul class="space-y-4 text-sm text-gray-700">
                                    <li class="flex items-center gap-3"><div class="w-8 h-8 bg-green-50 rounded-lg flex items-center justify-center"><i class="fa-solid fa-location-dot text-green-600 text-xs"></i></div> Tayabas City, Quezon</li>
                                    <li class="flex items-center gap-3"><div class="w-8 h-8 bg-green-50 rounded-lg flex items-center justify-center"><i class="fa-regular fa-calendar text-green-600 text-xs"></i></div> Member since <?= date('F d, Y') ?></li>
                                    <li class="flex items-center gap-3"><div class="w-8 h-8 bg-green-50 rounded-lg flex items-center justify-center"><i class="fa-solid fa-user-tag text-green-600 text-xs"></i></div> <?= $user_role ?> Account</li>
                                </ul>
                            </div>
                        </div>

                        <!-- Main Area -->
                        <div class="w-full lg:w-2/3">
                            <h3 class="text-xl font-bold text-gray-900 mb-4 font-serif">Products</h3>
                            <div class="bg-white border-2 border-dashed border-gray-200 rounded-2xl p-14 flex flex-col items-center justify-center text-center">
                                <div class="w-16 h-16 bg-green-50 rounded-2xl flex items-center justify-center mb-5">
                                    <i class="fa-solid fa-seedling text-2xl text-green-600"></i>
                                </div>
                                <h4 class="text-lg font-bold text-gray-900 mb-1">No Products Yet</h4>
                                <p class="text-gray-500 text-sm mb-7">This seller hasn't listed any products yet.</p>
                                <a href="#" onclick="showPage('shop')" class="bg-green-700 text-white px-7 py-2.5 rounded-xl text-sm font-bold hover:bg-green-800 transition btn-glow">Browse Marketplace</a>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- 11. FAQ PAGE -->
            <section id="page-faq" class="page-section hidden">
                <div class="relative bg-gradient-to-br from-green-800 to-emerald-800 py-20 text-center text-white overflow-hidden">
                    <div class="absolute inset-0 opacity-10" style="background-image: radial-gradient(circle at 70% 40%, white 1.5px, transparent 1.5px); background-size: 35px 35px;"></div>
                    <div class="relative z-10">
                        <div class="w-20 h-20 bg-white/10 backdrop-blur-md rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-inner border border-white/20">
                            <i class="fa-regular fa-circle-question text-4xl text-yellow-300"></i>
                        </div>
                        <h2 class="text-4xl md:text-5xl font-bold mb-4 font-serif">Frequently Asked Questions</h2>
                        <p class="text-green-100/90 max-w-xl mx-auto">Answers to common questions about buying, selling, and using FarmDirect.</p>
                    </div>
                </div>

                <div class="bg-gray-50 py-20 min-h-screen">
                    <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
                        <div id="faq-container" class="space-y-10">
                            <!-- Categories and Accordions will be injected here via JS -->
                        </div>

                        <div class="bg-gradient-to-br from-green-50 to-emerald-50 rounded-3xl p-10 md:p-14 text-center mt-14 border border-green-100 shadow-sm max-w-3xl mx-auto relative overflow-hidden">
                            <div class="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-green-300 via-emerald-400 to-green-500"></div>
                            <h3 class="text-2xl font-bold text-green-800 mb-3 font-serif">Still Have Questions?</h3>
                            <p class="text-gray-600 mb-8">Our support team is here to help with anything not covered above.</p>
                            <div class="flex flex-col sm:flex-row justify-center gap-4">
                                <a href="mailto:support@farmdirect.com" class="bg-gray-900 text-white px-7 py-3 rounded-xl font-bold hover:bg-gray-800 transition shadow-sm btn-glow">
                                    <i class="fa-solid fa-envelope mr-2"></i> Email Support
                                </a>
                                <button onclick="showPage('shop')" class="bg-white text-gray-900 border border-gray-200 px-7 py-3 rounded-xl font-bold hover:bg-gray-50 transition shadow-sm">
                                    Browse Marketplace
                                </button>
                            </div>
                        </div>

                        <div class="text-center mt-14">
                            <button onclick="showPage('home')" class="text-green-700 hover:text-green-800 font-semibold transition flex items-center justify-center mx-auto gap-2 group">
                                <i class="fa-solid fa-arrow-left text-sm group-hover:-translate-x-1 transition-transform"></i> Back to Home
                            </button>
                        </div>
                    </div>
                </div>
            </section>

            <!-- 12. TERMS & CONDITIONS PAGE -->
            <section id="page-terms" class="page-section hidden">
                <div class="relative bg-gradient-to-br from-green-800 to-emerald-800 py-20 text-center text-white overflow-hidden">
                    <div class="absolute inset-0 opacity-10" style="background-image: radial-gradient(circle at 25% 60%, white 1px, transparent 1px); background-size: 45px 45px;"></div>
                    <div class="relative z-10">
                        <div class="w-20 h-20 bg-white/10 backdrop-blur-md rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-inner border border-white/20">
                            <i class="fa-regular fa-file-lines text-4xl text-yellow-300"></i>
                        </div>
                        <h2 class="text-4xl md:text-5xl font-bold mb-4 font-serif">Terms & Conditions</h2>
                        <p class="text-green-100/90 max-w-2xl mx-auto mb-6">These Terms and Conditions govern the use of FarmDirect, an online agricultural marketplace connecting buyers and sellers throughout the Philippines. Please read them carefully before using our services.</p>
                        <span class="inline-block bg-white/10 backdrop-blur-sm text-white/90 px-5 py-2 rounded-full text-sm font-medium border border-white/15">Last Updated: July 26, 2026</span>
                    </div>
                </div>

                <div class="bg-gray-50 py-20 min-h-screen">
                    <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
                        <div class="flex flex-col lg:flex-row gap-8">
                            <div class="w-full lg:w-1/3">
                                <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 sticky top-24">
                                    <h3 class="text-lg font-bold mb-4 text-gray-900 border-b border-gray-100 pb-3 font-serif">Table of Contents</h3>
                                    <ul class="space-y-2.5 text-sm text-gray-500">
                                    <li><a href="#term-1" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>1. Acceptance of Terms</a></li>
                                    <li><a href="#term-2" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>2. Applicable Philippine Laws</a></li>
                                    <li><a href="#term-3" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>3. Eligibility</a></li>
                                    <li><a href="#term-4" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>4. About FarmDirect</a></li>
                                    <li><a href="#term-5" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>5. User Accounts</a></li>
                                    <li><a href="#term-6" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>6. Seller Responsibilities</a></li>
                                    <li><a href="#term-7" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>7. Buyer Responsibilities</a></li>
                                    <li><a href="#term-8" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>8. Marketplace Transactions</a></li>
                                    <li><a href="#term-9" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>9. Product Listings</a></li>
                                    <li><a href="#term-10" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>10. Prohibited Activities</a></li>
                                    <li><a href="#term-11" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>11. Intellectual Property</a></li>
                                    <li><a href="#term-12" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>12. Privacy</a></li>
                                    <li><a href="#term-13" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>13. Account Suspension</a></li>
                                    <li><a href="#term-14" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>14. Disclaimer</a></li>
                                    <li><a href="#term-15" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>15. Limitation of Liability</a></li>
                                    <li><a href="#term-16" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>16. Governing Law</a></li>
                                    <li><a href="#term-17" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>17. Changes to Terms</a></li>
                                    <li><a href="#term-18" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>18. Contact Us</a></li>
                                    </ul>
                                </div>
                            </div>

                            <div class="w-full lg:w-2/3">
                                <div class="bg-white p-8 md:p-10 rounded-2xl shadow-sm border border-gray-100 space-y-10">
                                <div id="term-1" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">1. Acceptance of Terms</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">By accessing or using the FarmDirect platform, you agree to be bound by these Terms and Conditions. If you do not agree with any part of these terms, you must not use our services.</p>
                                </div>
                                <div id="term-2" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">2. Applicable Philippine Laws</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">These terms shall be governed by and construed in accordance with the laws of the Republic of the Philippines, including but not limited to the Electronic Commerce Act of 2000 and the Consumer Act of the Philippines.</p>
                                </div>
                                <div id="term-3" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">3. Eligibility</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">To use our services, you must be at least 18 years of age and possess the legal authority to enter into binding contracts. By registering, you represent and warrant that you meet these eligibility requirements.</p>
                                </div>
                                <div id="term-4" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">4. About FarmDirect</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">FarmDirect operates as an online agricultural marketplace. We provide a platform for farmers, sellers, and buyers to connect, communicate, and transact. We are not a party to any transaction between users.</p>
                                </div>
                                <div id="term-5" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">5. User Accounts</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">You are responsible for maintaining the confidentiality of your account credentials and for all activities that occur under your account. You agree to provide accurate, current, and complete information during registration.</p>
                                </div>
                                <div id="term-6" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">6. Seller Responsibilities</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">Sellers are solely responsible for the accuracy of their listings, the quality of their products, and compliance with all applicable agricultural and food safety regulations. Sellers must fulfill orders promptly and professionally.</p>
                                </div>
                                <div id="term-7" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">7. Buyer Responsibilities</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">Buyers are responsible for providing accurate delivery information and for making prompt payments as agreed upon during the transaction. Buyers should communicate clearly with sellers regarding their orders.</p>
                                </div>
                                <div id="term-8" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">8. Marketplace Transactions</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">All transactions are directly between the buyer and the seller. FarmDirect is not responsible for the quality, safety, or legality of the items advertised, nor for the accuracy of the listings. We do not guarantee that any transaction will be completed.</p>
                                </div>
                                <div id="term-9" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">9. Product Listings</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">All product listings must be accurate, clear, and not misleading. Sellers must include relevant details such as price, quantity, and condition. FarmDirect reserves the right to remove any listing that violates these terms.</p>
                                </div>
                                <div id="term-10" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">10. Prohibited Activities</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">Users are prohibited from engaging in any illegal activities, including but not limited to fraud, money laundering, and the sale of prohibited items. Any violation may result in immediate account termination.</p>
                                </div>
                                <div id="term-11" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">11. Intellectual Property</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">All content on the FarmDirect platform, including logos, text, graphics, and software, is the property of FarmDirect or its licensors and is protected by intellectual property laws.</p>
                                </div>
                                <div id="term-12" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">12. Privacy</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">Your privacy is important to us. Please refer to our Privacy Policy for information on how we collect, use, and protect your personal data.</p>
                                </div>
                                <div id="term-13" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">13. Account Suspension</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">We reserve the right to suspend or terminate your account at any time, without notice, for conduct that we believe violates these terms or is harmful to other users or our business.</p>
                                </div>
                                <div id="term-14" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">14. Disclaimer</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">The FarmDirect platform is provided "as is" and "as available" without any warranties of any kind, either express or implied. We do not warrant that the service will be uninterrupted or error-free.</p>
                                </div>
                                <div id="term-15" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">15. Limitation of Liability</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">In no event shall FarmDirect be liable for any indirect, incidental, special, consequential, or punitive damages arising out of or related to your use of the platform.</p>
                                </div>
                                <div id="term-16" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">16. Governing Law</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">These terms shall be governed by and construed in accordance with the laws of the Philippines. Any disputes arising from these terms shall be subject to the exclusive jurisdiction of the courts of the Philippines.</p>
                                </div>
                                <div id="term-17" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">17. Changes to Terms</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">We reserve the right to modify these terms at any time. Your continued use of the platform after any changes constitutes acceptance of the new terms. It is your responsibility to review these terms periodically for updates.</p>
                                </div>
                                <div id="term-18" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-regular fa-file-lines text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">18. Contact Us</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">If you have any questions about these Terms and Conditions, please contact us at support@farmdirect.com or call +63 912 345 6789.</p>
                                </div>
                                </div>
                            </div>
                        </div>

                        <div class="text-center mt-14">
                            <button onclick="showPage('home')" class="bg-green-700 text-white px-8 py-3 rounded-xl font-bold hover:bg-green-800 transition shadow-sm btn-glow">Back to Home</button>
                        </div>
                    </div>
                </div>
            </section>

            <!-- 13. PRIVACY POLICY PAGE -->
            <section id="page-privacy" class="page-section hidden">
                <div class="relative bg-gradient-to-br from-green-800 to-emerald-800 py-20 text-center text-white overflow-hidden">
                    <div class="absolute inset-0 opacity-10" style="background-image: radial-gradient(circle at 60% 30%, white 1.5px, transparent 1.5px); background-size: 50px 50px;"></div>
                    <div class="relative z-10">
                        <div class="w-20 h-20 bg-white/10 backdrop-blur-md rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-inner border border-white/20">
                            <i class="fa-solid fa-shield-halved text-4xl text-yellow-300"></i>
                        </div>
                        <h2 class="text-4xl md:text-5xl font-bold mb-4 font-serif">Privacy Policy</h2>
                        <p class="text-green-100/90 max-w-2xl mx-auto mb-6">FarmDirect is committed to protecting your privacy and handling your personal information responsibly in accordance with the Data Privacy Act of 2012 (Republic Act No. 10173) and other applicable Philippine laws.</p>
                        <span class="inline-block bg-white/10 backdrop-blur-sm text-white/90 px-5 py-2 rounded-full text-sm font-medium border border-white/15">Effective Date: July 26, 2026</span>
                    </div>
                </div>

                <div class="bg-gray-50 py-20 min-h-screen">
                    <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
                        <div class="flex flex-col lg:flex-row gap-8">
                            <div class="w-full lg:w-1/3">
                                <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 sticky top-24">
                                    <h3 class="text-lg font-bold mb-4 text-gray-900 border-b border-gray-100 pb-3 font-serif">Table of Contents</h3>
                                    <ul class="space-y-2.5 text-sm text-gray-500">
                                    <li><a href="#priv-1" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>1. Introduction</a></li>
                                    <li><a href="#priv-2" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>2. Scope of this Privacy Policy</a></li>
                                    <li><a href="#priv-3" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>3. Personal Information We Collect</a></li>
                                    <li><a href="#priv-4" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>4. Sensitive Personal Information</a></li>
                                    <li><a href="#priv-5" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>5. How We Collect Information</a></li>
                                    <li><a href="#priv-6" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>6. Legal Basis for Processing</a></li>
                                    <li><a href="#priv-7" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>7. How We Use Your Information</a></li>
                                    <li><a href="#priv-8" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>8. Sharing and Disclosure of Information</a></li>
                                    <li><a href="#priv-9" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>9. Data Retention</a></li>
                                    <li><a href="#priv-10" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>10. Security Measures</a></li>
                                    <li><a href="#priv-11" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>11. Cookies and Similar Technologies</a></li>
                                    <li><a href="#priv-12" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>12. Your Rights Under the Data Privacy Act</a></li>
                                    <li><a href="#priv-13" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>13. Third-Party Services</a></li>
                                    <li><a href="#priv-14" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>14. Children's Privacy</a></li>
                                    <li><a href="#priv-15" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>15. Cross-Border Data Transfers</a></li>
                                    <li><a href="#priv-16" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>16. Changes to this Privacy Policy</a></li>
                                    <li><a href="#priv-17" class="hover:text-green-700 transition flex items-center gap-2 group"><span class="w-1.5 h-1.5 bg-gray-200 rounded-full group-hover:bg-green-500 transition-colors"></span>17. Contact Information</a></li>
                                    </ul>
                                </div>
                            </div>

                            <div class="w-full lg:w-2/3">
                                <div class="bg-white p-8 md:p-10 rounded-2xl shadow-sm border border-gray-100 space-y-10">
                                <div id="priv-1" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">1. Introduction</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">FarmDirect values and respects your privacy. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use our platform.</p>
                                </div>
                                <div id="priv-2" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">2. Scope of this Privacy Policy</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">This policy applies to all users of the FarmDirect platform, including buyers, sellers, and visitors. It covers all personal data collected through our website and services.</p>
                                </div>
                                <div id="priv-3" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">3. Personal Information We Collect</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">We collect personal information you provide directly to us, such as your name, email address, phone number, and delivery address when you create an account or place an order.</p>
                                </div>
                                <div id="priv-4" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">4. Sensitive Personal Information</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">We may collect sensitive personal information, such as valid government-issued IDs for seller verification. We process this data only when necessary and with your explicit consent.</p>
                                </div>
                                <div id="priv-5" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">5. How We Collect Information</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">We collect information when you register an account, place an order, communicate with sellers, respond to surveys, or browse our platform. We also use cookies and similar technologies.</p>
                                </div>
                                <div id="priv-6" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">6. Legal Basis for Processing</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">We process your personal data based on your consent, the performance of a contract (such as fulfilling an order), compliance with legal obligations, and our legitimate business interests.</p>
                                </div>
                                <div id="priv-7" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">7. How We Use Your Information</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">We use your information to process transactions, communicate with you about your orders, respond to inquiries, and improve our platform's services and user experience.</p>
                                </div>
                                <div id="priv-8" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">8. Sharing and Disclosure of Information</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">We do not sell your personal information to third parties. We may share your information with sellers to facilitate order fulfillment and delivery, and with service providers who assist us in operating the platform.</p>
                                </div>
                                <div id="priv-9" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">9. Data Retention</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">We retain your personal information only for as long as necessary to fulfill the purposes outlined in this policy, unless a longer retention period is required or permitted by law.</p>
                                </div>
                                <div id="priv-10" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">10. Security Measures</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">We implement appropriate technical and organizational measures to protect the security of your personal information against unauthorized access, alteration, disclosure, or destruction.</p>
                                </div>
                                <div id="priv-11" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">11. Cookies and Similar Technologies</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">We use cookies to enhance your browsing experience, analyze site traffic, and personalize content. You can manage your cookie preferences through your browser settings.</p>
                                </div>
                                <div id="priv-12" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">12. Your Rights Under the Data Privacy Act</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">Under the Data Privacy Act of 2012, you have the right to access, correct, or delete your personal information. You may also object to the processing of your data or file a complaint with the National Privacy Commission.</p>
                                </div>
                                <div id="priv-13" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">13. Third-Party Services</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">Our platform may contain links to third-party websites or services. We are not responsible for the privacy practices of these third parties, and we encourage you to review their policies.</p>
                                </div>
                                <div id="priv-14" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">14. Children's Privacy</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">Our services are not intended for individuals under the age of 18. We do not knowingly collect personal information from children. If we become aware of such collection, we will take steps to delete it.</p>
                                </div>
                                <div id="priv-15" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">15. Cross-Border Data Transfers</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">Your information may be transferred to and processed in countries other than the Philippines. We ensure that such transfers comply with applicable data protection laws and that your data remains protected.</p>
                                </div>
                                <div id="priv-16" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">16. Changes to this Privacy Policy</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">We may update this Privacy Policy from time to time. We will notify you of any significant changes by posting the new policy on our platform and updating the effective date.</p>
                                </div>
                                <div id="priv-17" class="scroll-mt-24">
                                    <div class="flex items-center gap-3 mb-4">
                                        <div class="w-10 h-10 bg-green-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                            <i class="fa-solid fa-shield-halved text-green-600"></i>
                                        </div>
                                        <h3 class="text-xl font-bold text-gray-900 font-serif">17. Contact Information</h3>
                                    </div>
                                    <p class="text-gray-500 text-sm leading-relaxed pl-13">If you have any questions or concerns about this Privacy Policy, please contact our Data Protection Officer at privacy@farmdirect.com or call +63 912 345 6789.</p>
                                </div>
                                </div>
                            </div>
                        </div>

                        <div class="text-center mt-14">
                            <button onclick="showPage('home')" class="bg-green-700 text-white px-8 py-3 rounded-xl font-bold hover:bg-green-800 transition shadow-sm btn-glow">Back to Home</button>
                        </div>
                    </div>
                </div>
            </section>

            <!-- ================================================ -->
            <!-- ADMIN: DASHBOARD                                  -->
            <!-- ================================================ -->
            <section id="page-admin-dashboard" class="page-section hidden bg-[#f8faf7] min-h-screen">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <span class="inline-flex items-center gap-2 bg-white border border-green-200 text-green-800 text-xs font-bold tracking-widest uppercase px-4 py-1.5 rounded-full shadow-sm"><i class="fa-solid fa-shield-halved text-green-600"></i> Administrator</span>
                    <h2 class="text-4xl md:text-5xl font-serif font-bold text-[#052e16] mt-5 mb-2">Admin Dashboard</h2>
                    <p class="text-gray-500 mb-10">System overview and recent activity.</p>

                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mb-12">
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 card-hover">
                            <div class="w-11 h-11 bg-gradient-to-br from-green-50 to-green-100 rounded-xl flex items-center justify-center mb-4"><i class="fa-solid fa-users text-green-700"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Total Users</p>
                            <h3 id="stat-users" class="text-3xl font-extrabold text-gray-900">–</h3>
                        </div>
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 card-hover">
                            <div class="w-11 h-11 bg-gradient-to-br from-green-50 to-green-100 rounded-xl flex items-center justify-center mb-4"><i class="fa-solid fa-seedling text-green-700"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Total Sellers</p>
                            <h3 id="stat-sellers" class="text-3xl font-extrabold text-gray-900">–</h3>
                        </div>
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 card-hover">
                            <div class="w-11 h-11 bg-gradient-to-br from-green-50 to-green-100 rounded-xl flex items-center justify-center mb-4"><i class="fa-solid fa-bag-shopping text-green-700"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Total Buyers</p>
                            <h3 id="stat-buyers" class="text-3xl font-extrabold text-gray-900">–</h3>
                        </div>
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 card-hover">
                            <div class="w-11 h-11 bg-gradient-to-br from-green-50 to-green-100 rounded-xl flex items-center justify-center mb-4"><i class="fa-solid fa-box text-green-700"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Total Products</p>
                            <h3 id="stat-products" class="text-3xl font-extrabold text-gray-900">–</h3>
                        </div>
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 card-hover">
                            <div class="w-11 h-11 bg-gradient-to-br from-amber-50 to-amber-100 rounded-xl flex items-center justify-center mb-4"><i class="fa-solid fa-hourglass-half text-amber-600"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Pending Offers</p>
                            <h3 id="stat-pending" class="text-3xl font-extrabold text-gray-900">–</h3>
                        </div>
                        <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 card-hover">
                            <div class="w-11 h-11 bg-gradient-to-br from-green-50 to-green-100 rounded-xl flex items-center justify-center mb-4"><i class="fa-solid fa-handshake text-green-700"></i></div>
                            <p class="text-gray-500 text-sm mb-1 font-medium">Total Transactions</p>
                            <h3 id="stat-transactions" class="text-3xl font-extrabold text-gray-900">–</h3>
                        </div>
                    </div>

                    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        <div class="lg:col-span-2 bg-white rounded-2xl shadow-sm border border-gray-100 p-7">
                            <h3 class="text-xl font-bold text-gray-900 mb-5 font-serif">Recent Activity</h3>
                            <div id="admin-activity" class="space-y-3 text-sm text-gray-600">Loading…</div>
                        </div>
                        <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-7">
                            <h3 class="text-xl font-bold text-gray-900 mb-5 font-serif">Quick Links</h3>
                            <div class="space-y-2.5">
                                <button onclick="showPage('admin-users')" class="w-full text-left px-5 py-3.5 rounded-xl bg-gradient-to-r from-green-50 to-emerald-50 hover:from-green-100 hover:to-emerald-100 text-green-800 font-bold flex items-center gap-3 transition-all group border border-green-100"><i class="fa-solid fa-users group-hover:scale-110 transition-transform"></i> Manage Users</button>
                                <button onclick="showPage('admin-products')" class="w-full text-left px-5 py-3.5 rounded-xl bg-gradient-to-r from-green-50 to-emerald-50 hover:from-green-100 hover:to-emerald-100 text-green-800 font-bold flex items-center gap-3 transition-all group border border-green-100"><i class="fa-solid fa-box group-hover:scale-110 transition-transform"></i> Manage Products</button>
                                <button onclick="showPage('admin-orders')" class="w-full text-left px-5 py-3.5 rounded-xl bg-gradient-to-r from-green-50 to-emerald-50 hover:from-green-100 hover:to-emerald-100 text-green-800 font-bold flex items-center gap-3 transition-all group border border-green-100"><i class="fa-solid fa-handshake group-hover:scale-110 transition-transform"></i> Manage Orders</button>
                                <button onclick="showPage('admin-reports')" class="w-full text-left px-5 py-3.5 rounded-xl bg-gradient-to-r from-green-50 to-emerald-50 hover:from-green-100 hover:to-emerald-100 text-green-800 font-bold flex items-center gap-3 transition-all group border border-green-100"><i class="fa-solid fa-chart-bar group-hover:scale-110 transition-transform"></i> Reports</button>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- ADMIN: USERS -->
            <section id="page-admin-users" class="page-section hidden bg-[#f8faf7] min-h-screen">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <span class="inline-flex items-center gap-2 bg-white border border-green-200 text-green-800 text-xs font-bold tracking-widest uppercase px-4 py-1.5 rounded-full shadow-sm"><i class="fa-solid fa-users text-green-600"></i> Manage Users</span>
                    <h2 class="text-4xl md:text-5xl font-serif font-bold text-[#052e16] mt-5 mb-10">User accounts</h2>

                    <div class="flex flex-col md:flex-row gap-4 mb-8">
                        <div class="relative w-full md:w-1/2">
                            <i class="fa-solid fa-magnifying-glass absolute left-4 top-3.5 text-gray-400 text-sm"></i>
                            <input id="admin-user-search" oninput="loadAdminUsers()" type="text" placeholder="Search by username or email" class="w-full bg-white border border-gray-200 rounded-xl pl-11 pr-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 shadow-sm text-sm transition">
                        </div>
                        <select id="admin-user-filter" onchange="loadAdminUsers()" class="w-full md:w-48 bg-white border border-gray-200 rounded-xl px-4 py-3 text-gray-700 focus:outline-none focus:ring-2 focus:ring-green-500 shadow-sm text-sm transition">
                            <option value="All">All roles</option>
                            <option value="Buyer">Buyer</option>
                            <option value="Seller">Seller</option>
                            <option value="Admin">Admin</option>
                        </select>
                    </div>

                    <div class="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-x-auto">
                        <table class="w-full text-sm min-w-[800px]">
                            <thead class="bg-gray-50/80 text-gray-500 text-xs uppercase tracking-widest">
                                <tr>
                                    <th class="text-left px-5 py-4 font-bold">ID</th>
                                    <th class="text-left px-5 py-4 font-bold">User</th>
                                    <th class="text-left px-5 py-4 font-bold">Email</th>
                                    <th class="text-left px-5 py-4 font-bold">Role</th>
                                    <th class="text-left px-5 py-4 font-bold">Verified</th>
                                    <th class="text-left px-5 py-4 font-bold">Status</th>
                                    <th class="text-left px-5 py-4 font-bold">Joined</th>
                                    <th class="text-left px-5 py-4 font-bold">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="admin-users-tbody">
                                <tr><td colspan="8" class="p-8 text-center text-gray-400">Loading…</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            <!-- ADMIN: PRODUCTS -->
            <section id="page-admin-products" class="page-section hidden bg-[#f8faf7] min-h-screen">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <span class="inline-flex items-center gap-2 bg-white border border-green-200 text-green-800 text-xs font-bold tracking-widest uppercase px-4 py-1.5 rounded-full shadow-sm"><i class="fa-solid fa-box text-green-600"></i> Manage Products</span>
                    <h2 class="text-4xl md:text-5xl font-serif font-bold text-[#052e16] mt-5 mb-10">All marketplace products</h2>

                    <div class="flex flex-col md:flex-row gap-4 mb-8">
                        <div class="relative w-full md:w-1/2">
                            <i class="fa-solid fa-magnifying-glass absolute left-4 top-3.5 text-gray-400 text-sm"></i>
                            <input id="admin-prod-search" oninput="loadAdminProducts()" type="text" placeholder="Search by product or seller" class="w-full bg-white border border-gray-200 rounded-xl pl-11 pr-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 shadow-sm text-sm transition">
                        </div>
                        <select id="admin-prod-category" onchange="loadAdminProducts()" class="w-full md:w-48 bg-white border border-gray-200 rounded-xl px-4 py-3 text-gray-700 focus:outline-none focus:ring-2 focus:ring-green-500 shadow-sm text-sm transition">
                            <option value="">All categories</option>
                            <option value="Vegetables">Vegetables</option>
                            <option value="Fruits">Fruits</option>
                            <option value="Dairy">Dairy</option>
                            <option value="Grains">Grains</option>
                        </select>
                    </div>

                    <div id="admin-products-list" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
                        <p class="text-gray-400 col-span-full text-center py-10">Loading…</p>
                    </div>
                </div>
            </section>

            <!-- ADMIN: ORDERS (offers + real orders) -->
            <section id="page-admin-orders" class="page-section hidden bg-[#f8faf7] min-h-screen">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <span class="inline-flex items-center gap-2 bg-white border border-green-200 text-green-800 text-xs font-bold tracking-widest uppercase px-4 py-1.5 rounded-full shadow-sm"><i class="fa-solid fa-handshake text-green-600"></i> Manage Orders</span>
                    <h2 class="text-4xl md:text-5xl font-serif font-bold text-[#052e16] mt-5 mb-10">All offers & transactions</h2>

                    <div class="mb-8">
                        <select id="admin-offer-filter" onchange="loadAdminOffers()" class="w-full md:w-48 bg-white border border-gray-200 rounded-xl px-4 py-3 text-gray-700 focus:outline-none focus:ring-2 focus:ring-green-500 shadow-sm text-sm transition">
                            <option value="">All statuses</option>
                            <option value="Pending">Pending</option>
                            <option value="Accepted">Accepted</option>
                            <option value="Declined">Declined</option>
                        </select>
                    </div>

                    <div class="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-x-auto mb-10">
                        <table class="w-full text-sm min-w-[800px]">
                            <thead class="bg-gray-50/80 text-gray-500 text-xs uppercase tracking-widest">
                                <tr>
                                    <th class="text-left px-5 py-4 font-bold">Offer ID</th>
                                    <th class="text-left px-5 py-4 font-bold">Product</th>
                                    <th class="text-left px-5 py-4 font-bold">Buyer</th>
                                    <th class="text-left px-5 py-4 font-bold">Seller</th>
                                    <th class="text-left px-5 py-4 font-bold">Qty</th>
                                    <th class="text-left px-5 py-4 font-bold">Price</th>
                                    <th class="text-left px-5 py-4 font-bold">Total</th>
                                    <th class="text-left px-5 py-4 font-bold">Status</th>
                                    <th class="text-left px-5 py-4 font-bold">Created</th>
                                </tr>
                            </thead>
                            <tbody id="admin-offers-tbody">
                                <tr><td colspan="9" class="p-8 text-center text-gray-400">Loading…</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-2xl font-bold text-gray-900 font-serif mb-4">Real Orders (Pickup / COD)</h3>
                    <div class="mb-5">
                        <select id="admin-orders-filter" onchange="loadAdminOrders()" class="w-full md:w-48 bg-white border border-gray-200 rounded-xl px-4 py-3 text-gray-700 focus:outline-none focus:ring-2 focus:ring-green-500 shadow-sm text-sm transition">
                            <option value="">All statuses</option>
                            <option value="Pending">Pending</option>
                            <option value="Confirmed">Confirmed</option>
                            <option value="Shipped">Shipped</option>
                            <option value="Delivered">Delivered</option>
                            <option value="Cancelled">Cancelled</option>
                        </select>
                    </div>
                    <div id="admin-orders-list" class="space-y-4">
                        <p class="text-gray-400 text-center py-10">Loading…</p>
                    </div>
                </div>
            </section>

            <!-- ADMIN: REPORTS -->
            <section id="page-admin-reports" class="page-section hidden bg-[#f8faf7] min-h-screen">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
                    <span class="inline-flex items-center gap-2 bg-white border border-green-200 text-green-800 text-xs font-bold tracking-widest uppercase px-4 py-1.5 rounded-full shadow-sm"><i class="fa-solid fa-chart-bar text-green-600"></i> Reports</span>
                    <h2 class="text-4xl md:text-5xl font-serif font-bold text-[#052e16] mt-5 mb-10">Platform reports</h2>

                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-7">
                            <h3 class="text-xl font-bold text-gray-900 mb-5 font-serif flex items-center gap-2"><i class="fa-solid fa-handshake text-green-600"></i> Offers per Status</h3>
                            <div id="report-offers-status" class="space-y-2 text-sm">Loading…</div>
                        </div>
                        <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-7">
                            <h3 class="text-xl font-bold text-gray-900 mb-5 font-serif flex items-center gap-2"><i class="fa-solid fa-users text-green-600"></i> Users per Role</h3>
                            <div id="report-users-role" class="space-y-2 text-sm">Loading…</div>
                        </div>
                        <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-7">
                            <h3 class="text-xl font-bold text-gray-900 mb-5 font-serif flex items-center gap-2"><i class="fa-solid fa-box text-green-600"></i> Products per Category</h3>
                            <div id="report-products-cat" class="space-y-2 text-sm">Loading…</div>
                        </div>
                        <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-7">
                            <h3 class="text-xl font-bold text-gray-900 mb-5 font-serif flex items-center gap-2"><i class="fa-solid fa-location-dot text-green-600"></i> Products per Barangay</h3>
                            <div id="report-products-brgy" class="space-y-2 text-sm">Loading…</div>
                        </div>
                        <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-7">
                            <h3 class="text-xl font-bold text-gray-900 mb-5 font-serif flex items-center gap-2"><i class="fa-solid fa-money-bill-wave text-green-600"></i> Orders per Status</h3>
                            <div id="report-orders-status" class="space-y-2 text-sm">Loading…</div>
                        </div>
                        <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-7">
                            <h3 class="text-xl font-bold text-gray-900 mb-5 font-serif flex items-center gap-2"><i class="fa-solid fa-sack-dollar text-green-600"></i> Order Revenue</h3>
                            <div class="text-xs text-gray-400 uppercase font-bold tracking-widest mb-1">Total (Confirmed+Shipped+Delivered)</div>
                            <div id="report-orders-total" class="text-3xl font-extrabold text-green-800 py-2">–</div>
                            <div class="text-xs text-gray-400 uppercase font-bold tracking-widest mb-1 mt-4">Collected (Paid)</div>
                            <div id="report-orders-paid" class="text-2xl font-extrabold text-emerald-700 py-1">–</div>
                        </div>
                        <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-7">
                            <h3 class="text-xl font-bold text-gray-900 mb-5 font-serif flex items-center gap-2"><i class="fa-solid fa-truck-fast text-green-600"></i> Fulfillment Mix</h3>
                            <div id="report-fulfillment" class="space-y-2 text-sm">Loading…</div>
                        </div>
                        <div class="bg-white rounded-2xl shadow-sm border border-gray-100 p-7">
                            <h3 class="text-xl font-bold text-gray-900 mb-5 font-serif flex items-center gap-2"><i class="fa-solid fa-circle-dollar-to-slot text-green-600"></i> Payment Status</h3>
                            <div id="report-payment-status" class="space-y-2 text-sm">Loading…</div>
                        </div>
                    </div>
                </div>
            </section>

        <!-- CHANGE PASSWORD -->
            <section id="page-change-password" class="page-section hidden bg-[#f4f6f1] min-h-screen flex items-center">
                <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-10 w-full">
                    <div class="bg-white border border-gray-100 rounded-3xl shadow-lg p-10 w-full max-w-md mx-auto relative overflow-hidden">
                        <div class="absolute top-0 left-0 w-full h-1.5 bg-gradient-to-r from-green-400 via-emerald-500 to-green-600"></div>
                        <div class="w-14 h-14 rounded-2xl bg-gradient-to-br from-green-50 to-green-100 flex items-center justify-center mb-8 shadow-sm"><i class="fa-solid fa-lock text-green-800 text-xl"></i></div>
                        <h2 class="text-4xl font-bold text-[#052e16] leading-tight mb-3 font-serif">Change password</h2>
                        <p class="text-gray-500 text-sm mb-7">Choose something you haven't used before.</p>
                        <div id="pw-msg" class="hidden text-sm rounded-xl px-4 py-3 mb-4"></div>
                        <div class="space-y-5">
                            <div>
                                <label class="block text-sm font-bold text-[#052e16] mb-2">Current password</label>
                                <input type="password" id="pw-current" placeholder="Enter current password" class="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-green-600 focus:border-green-500 transition">
                            </div>
                            <div>
                                <label class="block text-sm font-bold text-[#052e16] mb-2">New password</label>
                                <div class="relative">
                                    <input type="password" id="pw-new" placeholder="At least 8 characters" class="w-full border border-gray-200 rounded-xl px-4 py-3 pr-11 text-sm focus:outline-none focus:ring-2 focus:ring-green-600 focus:border-green-500 transition">
                                    <button type="button" onclick="togglePwVisibility()" class="absolute right-4 top-3.5 text-gray-400 hover:text-gray-600 transition"><i id="pw-eye" class="fa-regular fa-eye"></i></button>
                                </div>
                            </div>
                            <div>
                                <label class="block text-sm font-bold text-[#052e16] mb-2">Confirm new password</label>
                                <input type="password" id="pw-confirm" placeholder="Re-enter new password" class="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-green-600 focus:border-green-500 transition">
                            </div>
                            <button type="button" onclick="changePassword()" class="w-full bg-gradient-to-r from-green-800 to-green-900 hover:from-green-900 hover:to-green-950 text-white font-bold py-3.5 rounded-xl transition btn-glow shadow-md">Update password</button>
                        </div>
                    </div>
                </div>
            </section>

            <!-- ACCOUNT SETTINGS -->
            <section id="page-settings" class="page-section hidden bg-[#f4f6f1] min-h-screen">
                <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                    <a href="#" onclick="showPage('home')" class="text-sm font-semibold text-gray-600 hover:text-green-700 inline-flex items-center gap-2 mb-5 transition group"><i class="fa-solid fa-arrow-left text-xs group-hover:-translate-x-1 transition-transform"></i> Back</a>
                    <div><span class="inline-flex items-center gap-2 bg-green-50 border border-green-200 text-green-800 text-xs font-bold tracking-widest uppercase px-4 py-1.5 rounded-full shadow-sm"><i class="fa-solid fa-shield-halved"></i> Preferences</span></div>
                    <h2 class="text-5xl md:text-6xl font-serif font-bold text-[#052e16] mt-5 mb-3">Settings</h2>
                    <p class="text-gray-500 mb-10">Manage your account, notifications, and security.</p>

                    <div class="flex flex-col md:flex-row gap-10">
                        <div class="md:w-56 flex md:flex-col gap-2">
                            <button id="stab-account" onclick="showSettingsTab('account')" class="text-left px-5 py-3 rounded-2xl text-sm font-bold transition-all">Account</button>
                            <button id="stab-notifications" onclick="showSettingsTab('notifications')" class="text-left px-5 py-3 rounded-2xl text-sm font-bold transition-all">Notifications</button>
                            <button id="stab-danger" onclick="showSettingsTab('danger')" class="text-left px-5 py-3 rounded-2xl text-sm font-bold transition-all">Danger Zone</button>
                        </div>
                        <div class="flex-1 max-w-3xl">
                            <div id="settings-account" class="space-y-6">
                                <div class="bg-white border border-gray-100 rounded-3xl shadow-sm p-8">
                                    <h3 class="text-lg font-bold text-[#052e16] mb-1 font-serif">Connected accounts</h3>
                                    <p class="text-sm text-gray-500 mb-6">Connect your Google or Facebook account for faster sign-in.</p>
                                    <div class="flex flex-col items-center gap-3">
                                        <button onclick="connectSocial('Google')" class="w-full max-w-sm border border-gray-200 rounded-xl py-3 text-sm text-gray-700 hover:bg-gray-50 flex items-center justify-center gap-3 transition font-medium"><i class="fa-brands fa-google text-red-500"></i> Connect Google account</button>
                                        <button onclick="connectSocial('Facebook')" class="w-full max-w-sm bg-[#1877f2] hover:bg-[#1468d8] text-white rounded-xl py-3 text-sm font-bold flex items-center justify-center gap-2.5 transition shadow-sm"><i class="fa-brands fa-facebook"></i> Connect Facebook account</button>
                                    </div>
                                </div>
                                <div class="bg-white border border-gray-100 rounded-3xl shadow-sm p-8">
                                    <h3 class="text-lg font-bold text-[#052e16] mb-4 font-serif">Signed-in devices</h3>
                                    <div class="flex flex-col sm:flex-row sm:items-center gap-4 justify-between">
                                        <div class="flex gap-3">
                                            <div class="w-10 h-10 bg-gray-50 rounded-xl flex items-center justify-center flex-shrink-0"><i class="fa-solid fa-laptop text-gray-500"></i></div>
                                            <div>
                                                <p class="font-bold text-gray-900 text-sm">Log out of all devices</p>
                                                <p class="text-xs text-gray-500 max-w-md mt-1">Signs you out everywhere you're logged in, including this device. Use it if you lost a phone or signed in on a shared computer.</p>
                                            </div>
                                        </div>
                                        <button onclick="logoutEverywhere()" class="border border-gray-200 rounded-xl px-5 py-2.5 text-sm font-bold hover:bg-gray-50 transition whitespace-nowrap shadow-sm">Log out everywhere</button>
                                    </div>
                                </div>
                            </div>

                            <div id="settings-notifications" class="hidden bg-white border border-gray-100 rounded-3xl shadow-sm p-8">
                                <h3 class="text-lg font-bold text-[#052e16] mb-5 font-serif">Notifications</h3>
                                <div id="notif-msg" class="hidden text-sm rounded-xl px-4 py-3 mb-4"></div>
                                <label class="flex items-center justify-between py-4 border-b border-gray-100 cursor-pointer group">
                                    <span><span class="block font-bold text-sm text-gray-900">New offers</span><span class="text-xs text-gray-500 mt-0.5">Tell me when someone makes or answers an offer.</span></span>
                                    <input type="checkbox" id="notify-offers" class="w-5 h-5 accent-green-700 rounded">
                                </label>
                                <label class="flex items-center justify-between py-4 cursor-pointer group">
                                    <span><span class="block font-bold text-sm text-gray-900">New messages</span><span class="text-xs text-gray-500 mt-0.5">Tell me when I receive a message.</span></span>
                                    <input type="checkbox" id="notify-messages" class="w-5 h-5 accent-green-700 rounded">
                                </label>
                                <button onclick="saveNotifications()" class="mt-5 bg-[#1a4731] hover:bg-[#143a28] text-white font-bold px-7 py-3 rounded-xl text-sm transition btn-glow shadow-md">Save preferences</button>
                            </div>

                            <div id="settings-danger" class="hidden bg-white border border-red-200 rounded-3xl shadow-sm p-8">
                                <h3 class="text-lg font-bold text-red-600 mb-2 font-serif">Danger zone</h3>
                                <p class="text-sm text-gray-600 mb-5">Deleting your account permanently removes your profile, products, offers, and messages. This can't be undone.</p>
                                <div id="delete-msg" class="hidden text-sm rounded-xl px-4 py-3 mb-4"></div>
                                <input type="password" id="delete-password" placeholder="Enter your password to confirm" class="w-full max-w-sm border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-red-400 focus:border-red-400 transition mb-4">
                                <div><button onclick="deleteAccount()" class="bg-red-600 hover:bg-red-700 text-white font-bold px-7 py-3 rounded-xl text-sm transition shadow-md">Delete my account</button></div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

        <!-- MESSAGES (BUYER <-> SELLER) -->
            <section id="page-messages" class="page-section hidden bg-[#f8faf7] min-h-screen">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                    <a href="#" onclick="showPage('shop')" class="text-sm text-gray-500 hover:text-green-700 inline-flex items-center gap-2 mb-4 transition font-medium"><i class="fa-solid fa-arrow-left text-xs"></i> Back to Marketplace</a>
                    <div class="bg-white border border-gray-100 rounded-2xl shadow-sm overflow-hidden grid grid-cols-1 md:grid-cols-[320px_1fr] xl:grid-cols-[320px_1fr_340px] h-[75vh]">
                        <div class="border-r border-gray-100 flex flex-col min-h-0">
                            <div class="p-6">
                                <h2 class="text-3xl font-bold text-gray-900 mb-5 font-serif">Messages</h2>
                                <div class="relative">
                                    <i class="fa-solid fa-magnifying-glass absolute left-4 top-3.5 text-gray-400 text-sm"></i>
                                    <input type="text" id="conv-search" oninput="renderConversations()" placeholder="Search conversations..." class="w-full border border-gray-200 rounded-xl pl-10 pr-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 transition">
                                </div>
                            </div>
                            <div id="conv-list" class="flex-1 overflow-y-auto px-3 pb-3"></div>
                        </div>
                        <div class="flex flex-col min-h-0 bg-gray-50/60">
                            <div id="chat-header" class="px-5 py-3 bg-white border-b border-gray-100 flex items-center gap-3 min-h-[64px]"></div>
                            <div id="chat-messages" class="flex-1 overflow-y-auto p-5 space-y-2">
                                <div class="text-center mt-16">
                                    <div class="w-16 h-16 bg-gray-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
                                        <i class="fa-regular fa-comment text-2xl text-gray-300"></i>
                                    </div>
                                    <p class="text-gray-400 text-sm">Select a conversation, or tap the chat icon on a product to message its seller.</p>
                                </div>
                            </div>
                            <div class="p-4 bg-white border-t border-gray-100 flex items-center gap-3">
                                <input type="text" id="chat-input" onkeydown="if(event.key==='Enter'){sendChat();}" placeholder="Type your message..." class="flex-1 border border-gray-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 transition">
                                <button type="button" onclick="sendChat()" class="w-11 h-11 rounded-xl bg-gradient-to-r from-green-500 to-green-600 hover:from-green-600 hover:to-green-700 text-white flex items-center justify-center transition shadow-sm btn-glow"><i class="fa-regular fa-paper-plane"></i></button>
                            </div>
                        </div>
                        <div id="chat-details" class="hidden xl:block border-l border-gray-100 p-5 overflow-y-auto"></div>
                    </div>
                </div>
            </section>

        </main>

        <!-- MAKE OFFER MODAL -->
        <div id="offerModal" class="fixed inset-0 z-[100] hidden items-center justify-center bg-black/50 backdrop-blur-sm p-4">
            <div class="offer-modal-glass rounded-3xl shadow-2xl w-full max-w-md p-7 border border-gray-100 relative overflow-hidden">
                <div class="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-orange-400 via-amber-500 to-orange-400"></div>
                <div class="flex justify-between items-center mb-5">
                    <h3 class="text-xl font-bold text-gray-900 font-serif">Make an Offer</h3>
                    <button type="button" onclick="closeOfferModal()" class="w-8 h-8 rounded-lg bg-gray-50 hover:bg-gray-100 flex items-center justify-center transition"><i class="fa-solid fa-xmark text-gray-500"></i></button>
                </div>
                <p id="offer-product-name" class="text-sm text-gray-500 mb-5 font-medium"></p>
                <div class="grid grid-cols-2 gap-4 mb-5">
                    <div>
                        <label id="offer-qty-label" class="block text-xs font-bold text-gray-500 mb-2">Quantity</label>
                        <input type="number" id="offer-qty" min="1" value="1" oninput="updateOfferTotal()" class="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 transition">
                    </div>
                    <div>
                        <label id="offer-price-label" class="block text-xs font-bold text-gray-500 mb-2">Offer price</label>
                        <input type="number" id="offer-price" min="0" step="0.01" oninput="updateOfferTotal()" class="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 transition">
                    </div>
                </div>
                <div class="bg-gradient-to-r from-green-50 to-emerald-50 rounded-xl px-5 py-4 flex justify-between text-sm mb-6 border border-green-100">
                    <span class="text-gray-600 font-medium">Total</span>
                    <span id="offer-total" class="font-extrabold text-green-800 text-lg">₱0</span>
                </div>
                <button type="button" onclick="submitOffer()" class="w-full bg-gradient-to-r from-green-600 to-emerald-700 hover:from-green-700 hover:to-emerald-800 text-white font-bold py-3.5 rounded-xl transition btn-glow shadow-md">Send Offer</button>
            </div>
        </div>

        <!-- Footer -->
        <footer class="footer-gradient text-white mt-auto relative overflow-hidden">
            <div class="absolute inset-0 opacity-5" style="background-image: radial-gradient(circle at 10% 50%, white 1px, transparent 1px); background-size: 40px 40px;"></div>
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 relative z-10">
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-12 gap-10">
                    <div class="lg:col-span-4">
                        <div class="flex items-center space-x-2.5 mb-5">
                            <div class="w-10 h-10 bg-white/10 backdrop-blur-sm rounded-xl flex items-center justify-center border border-white/15">
                                <i class="fa-solid fa-leaf text-yellow-300 text-lg"></i>
                            </div>
                            <span class="text-2xl font-extrabold tracking-tight">Farm<span class="text-green-400">Direct</span></span>
                        </div>
                        <p class="text-green-200/70 text-sm leading-relaxed max-w-md">
                            FarmDirect is an online agricultural marketplace connecting farmers, sellers, and buyers across the Philippines, making fresh farm products easier to discover and purchase.
                        </p>
                        <div class="flex gap-3 mt-6">
                            <a href="#" class="w-9 h-9 bg-white/10 rounded-xl flex items-center justify-center hover:bg-white/20 transition border border-white/10"><i class="fa-brands fa-facebook text-sm"></i></a>
                            <a href="#" class="w-9 h-9 bg-white/10 rounded-xl flex items-center justify-center hover:bg-white/20 transition border border-white/10"><i class="fa-brands fa-instagram text-sm"></i></a>
                            <a href="#" class="w-9 h-9 bg-white/10 rounded-xl flex items-center justify-center hover:bg-white/20 transition border border-white/10"><i class="fa-brands fa-youtube text-sm"></i></a>
                        </div>
                    </div>

                    <div class="lg:col-span-3">
                        <h4 class="font-bold text-base mb-5 text-white/90 tracking-wide">Contact Us</h4>
                        <ul class="space-y-3 text-sm text-green-200/70">
                            <li class="flex items-center gap-3"><div class="w-8 h-8 bg-white/5 rounded-lg flex items-center justify-center border border-white/10"><i class="fa-solid fa-phone text-xs text-green-400"></i></div> 6399 567 8639</li>
                            <li class="flex items-center gap-3"><div class="w-8 h-8 bg-white/5 rounded-lg flex items-center justify-center border border-white/10"><i class="fa-solid fa-envelope text-xs text-green-400"></i></div> farmdirect@gmail.com</li>
                            <li class="flex items-start gap-3"><div class="w-8 h-8 bg-white/5 rounded-lg flex items-center justify-center border border-white/10 mt-0.5"><i class="fa-solid fa-location-dot text-xs text-green-400"></i></div> <span>Tayabas, City</span></li>
                        </ul>
                    </div>

                    <div class="lg:col-span-2">
                        <h4 class="font-bold text-base mb-5 text-white/90 tracking-wide">Help & Legal</h4>
                        <ul class="space-y-3 text-sm text-green-200/70">
                            <li><a href="#" onclick="showPage('faq')" class="hover:text-white transition">FAQ</a></li>
                            <li><a href="#" onclick="showPage('terms')" class="hover:text-white transition">Terms & Conditions</a></li>
                            <li><a href="#" onclick="showPage('privacy')" class="hover:text-white transition">Privacy Policy</a></li>
                        </ul>
                    </div>

                    <div class="lg:col-span-3">
                        <h4 class="font-bold text-base mb-5 text-white/90 tracking-wide">Follow Us</h4>
                        <ul class="space-y-3 text-sm text-green-200/70">
                            <li>
                                <a href="#" class="flex items-center hover:text-white transition group">
                                    <span class="w-8 h-8 bg-white/5 rounded-lg flex items-center justify-center mr-3 group-hover:bg-white/15 transition border border-white/10">
                                        <i class="fa-brands fa-facebook text-sm"></i>
                                    </span>
                                    Facebook
                                </a>
                            </li>
                            <li>
                                <a href="#" class="flex items-center hover:text-white transition group">
                                    <span class="w-8 h-8 bg-white/5 rounded-lg flex items-center justify-center mr-3 group-hover:bg-white/15 transition border border-white/10">
                                        <i class="fa-brands fa-instagram text-sm"></i>
                                    </span>
                                    Instagram
                                </a>
                            </li>
                            <li>
                                <a href="#" class="flex items-center hover:text-white transition group">
                                    <span class="w-8 h-8 bg-white/5 rounded-lg flex items-center justify-center mr-3 group-hover:bg-white/15 transition border border-white/10">
                                        <i class="fa-brands fa-youtube text-sm"></i>
                                    </span>
                                    YouTube
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="border-t border-white/10">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col md:flex-row justify-between items-center text-xs text-green-300/60 gap-3">
                    <p>&copy; 2025 FarmDirect. All rights reserved.</p>
                    <div class="flex space-x-6">
                        <a href="#" onclick="showPage('privacy')" class="hover:text-white transition">Privacy Policy</a>
                        <a href="#" onclick="showPage('terms')" class="hover:text-white transition">Terms of Service</a>
                    </div>
                </div>
            </div>
        </footer>

        <!-- JavaScript for Interactions and Cart Logic -->
        <script>
            // --- ADD PRODUCT FORM TOGGLE ---
            function toggleAddProductForm() {
                const emptyState = document.getElementById('product-empty-state');
                const form = document.getElementById('add-product-form');
                
                if (form.classList.contains('hidden')) {
                    emptyState.classList.add('hidden');
                    form.classList.remove('hidden');
                } else {
                    emptyState.classList.remove('hidden');
                    form.classList.add('hidden');
                }
                window.scrollTo(0, 0);
            }

            // --- PHOTO PREVIEW (max 10) ---
            function previewPhotos(input) {
                const box = document.getElementById('photo-preview');
                box.innerHTML = '';
                const files = Array.from(input.files).slice(0, 10);
                if (input.files.length > 10) alert('Maximum of 10 photos only. The first 10 will be uploaded.');
                files.forEach((f, i) => {
                    const url = URL.createObjectURL(f);
                    box.innerHTML += `<div class="relative"><img src="${url}" class="w-full h-20 object-contain rounded-lg border">${i === 0 ? '<span class="absolute bottom-1 left-1 bg-green-700 text-white text-[10px] px-1.5 rounded">Cover</span>' : ''}</div>`;
                });
            }

            
            // --- Data (galing sa database) ---
            const products = <?= json_encode($db_products, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>;
            const currentUserId = <?= (int)($_SESSION['user_id'] ?? 0) ?>;

            const sellers = {
                1: { name: "Juan Dela Cruz", farm: "Bulacan Fresh Farms", location: "San Jose, Bulacan" },
                2: { name: "Maria Santos", farm: "Santos Fruit Orchard", location: "Baguio City" },
                3: { name: "Ramon Reyes", farm: "Reyes Dairy Farm", location: "Laguna" }
            };

            // --- BUYER: SAVED PRODUCTS (naka-save sa browser, per user) ---
            const isBuyer = <?= (!$is_logged_in || $user_role === 'Buyer') ? 'true' : 'false' ?>;
            const isAdminRole = <?= $is_admin ? 'true' : 'false' ?>;
            const savedKey = 'fd_saved_' + currentUserId;

            function getSaved() {
                try { return JSON.parse(localStorage.getItem(savedKey) || '[]'); } catch (e) { return []; }
            }
            function setSaved(list) {
                try { localStorage.setItem(savedKey, JSON.stringify(list)); } catch (e) {}
            }

            function heartButton(id) {
                const saved = getSaved().includes(id);
                return `<button type="button" onclick="toggleSave(${id})" title="${saved ? 'Remove from saved' : 'Save product'}"
                            class="absolute top-3 right-3 w-10 h-10 rounded-full bg-white/95 hover:bg-white shadow-md flex items-center justify-center transition-all hover:scale-110 backdrop-blur-sm">
                            <i class="${saved ? 'fa-solid text-red-500' : 'fa-regular text-gray-500'} fa-heart"></i>
                        </button>`;
            }

            function toggleSave(id) {
                if (!currentUserId) { window.location.href = '?action=login'; return; }
                let list = getSaved();
                list = list.includes(id) ? list.filter(x => x !== id) : [...list, id];
                setSaved(list);
                renderProducts();
                renderSaved();
                updateBuyerStats();
            }

            function renderSaved() {
                const grid = document.getElementById('saved-products-grid');
                const empty = document.getElementById('saved-empty');
                if (!grid) return;
                if (isAdminRole) return;
                const ids = getSaved();
                const items = products.filter(p => ids.includes(p.id));
                grid.innerHTML = items.map(p => createProductCard(p)).join('');
                if (empty) empty.classList.toggle('hidden', items.length > 0);
            }

            function updateBuyerStats() {
                if (isAdminRole) return;
                const ids = getSaved();
                const savedCount = products.filter(p => ids.includes(p.id)).length;
                const s = document.getElementById('buyer-stat-saved');
                const c = document.getElementById('buyer-stat-cart');
                const latest = document.getElementById('buyer-latest-products');
                if (s) s.innerText = savedCount;
                if (c) c.innerText = cart.reduce((sum, item) => sum + item.quantity, 0);
                if (latest) {
                    latest.innerHTML = products.length === 0
                        ? `<p class="text-gray-500 col-span-full text-center py-10">No products listed yet.</p>`
                        : products.slice(0, 3).map(p => createProductCard(p)).join('');
                }
            }

            // --- CART (naka-save sa browser kada user, id + quantity lang) ---
            const cartKey = 'fd_cart_' + currentUserId;
            let cart = (() => {
                try { return JSON.parse(localStorage.getItem(cartKey) || '[]'); } catch (e) { return []; }
            })();
            function saveCart() {
                try { localStorage.setItem(cartKey, JSON.stringify(cart)); } catch (e) {}
            }

            function cartItems() {
                return cart
                    .map(c => ({ p: products.find(p => p.id === c.id), qty: c.quantity }))
                    .filter(x => x.p);
            }

            function renderCart() {
                if (isAdminRole) return;
                const body = document.getElementById('cart-table-body');
                const empty = document.getElementById('empty-cart-message');
                const subtotalEl = document.getElementById('cart-subtotal');
                const totalEl = document.getElementById('cart-total');
                const badge = document.getElementById('cart-badge');

                const items = cartItems();
                cart = items.map(x => ({ id: x.p.id, quantity: x.qty })); // tanggalin ang mga product na wala na
                saveCart();

                const total = items.reduce((sum, x) => sum + x.p.price * x.qty, 0);
                if (badge) badge.innerText = items.reduce((sum, x) => sum + x.qty, 0);
                if (subtotalEl) subtotalEl.innerText = '₱' + total.toFixed(2);
                if (totalEl) totalEl.innerText = '₱' + total.toFixed(2);
                if (empty) empty.classList.toggle('hidden', items.length > 0);

                if (body) {
                    body.innerHTML = items.map(({ p, qty }) => `
                        <tr class="border-b border-gray-50 hover:bg-gray-50/50 transition-colors">
                            <td class="p-4">
                                <div class="flex items-center gap-4">
                                    <img src="${p.img}" alt="${escapeHtml(p.name)}" class="w-16 h-16 rounded-xl object-contain bg-gray-50 border border-gray-100">
                                    <div>
                                        <p class="font-bold text-gray-900">${escapeHtml(p.name)}</p>
                                        <p class="text-xs text-gray-500 mt-0.5">${escapeHtml(p.sellerName || '')}</p>
                                    </div>
                                </div>
                            </td>
                            <td class="p-4 text-center">
                                <div class="inline-flex items-center border border-gray-200 rounded-xl overflow-hidden bg-white shadow-sm">
                                    <button onclick="changeQty(${p.id}, -1)" class="px-3.5 py-2 hover:bg-gray-50 transition text-gray-600 font-bold">−</button>
                                    <span class="px-3.5 py-2 text-sm font-bold border-x border-gray-100 min-w-[40px] text-center">${qty}</span>
                                    <button onclick="changeQty(${p.id}, 1)" class="px-3.5 py-2 hover:bg-gray-50 transition text-gray-600 font-bold">+</button>
                                </div>
                            </td>
                            <td class="p-4 text-gray-600 font-medium">₱${p.price.toFixed(2)}</td>
                            <td class="p-4 font-bold text-gray-900">₱${(p.price * qty).toFixed(2)}</td>
                            <td class="p-4"><button onclick="removeFromCart(${p.id})" class="w-8 h-8 rounded-lg bg-red-50 text-red-500 hover:bg-red-100 flex items-center justify-center transition" title="Remove"><i class="fa-solid fa-trash text-xs"></i></button></td>
                        </tr>`).join('');
                }
                updateBuyerStats();
            }

            function changeQty(productId, delta) {
                const item = cart.find(c => c.id === productId);
                const product = products.find(p => p.id === productId);
                if (!item || !product) return;
                const newQty = item.quantity + delta;
                if (newQty < 1) { removeFromCart(productId); return; }
                if (newQty > product.stock) { alert('Only ' + product.stock + ' in stock.'); return; }
                item.quantity = newQty;
                renderCart();
            }

            function removeFromCart(productId) {
                cart = cart.filter(c => c.id !== productId);
                renderCart();
            }

            // --- CHECKOUT (Pickup or COD, real order system) ---
            let currentFulfillment = 'COD';
            function onFulfillmentChange(val) {
                currentFulfillment = val;
                const isPickup = val === 'PICKUP';
                const codBlock = document.getElementById('cod-address-block');
                const pickupBlock = document.getElementById('pickup-block');
                const payTitle = document.getElementById('payment-title');
                const payDesc = document.getElementById('payment-desc');
                const coPay = document.getElementById('checkout-payment');
                if (codBlock) codBlock.classList.toggle('hidden', isPickup);
                if (pickupBlock) pickupBlock.classList.toggle('hidden', !isPickup);
                if (payTitle) payTitle.innerText = isPickup ? 'Cash on Pickup' : 'Cash on Delivery (COD)';
                if (payDesc) payDesc.innerText = isPickup
                    ? 'Pay in cash when you pick up your order from the seller.'
                    : 'Pay in cash when your order is delivered. Please prepare the exact amount.';
                if (coPay) coPay.innerText = isPickup ? 'Cash on Pickup' : 'Cash on Delivery';
            }

            function checkout() {
                if (isAdminRole) { alert('Administrators cannot place orders.'); return; }
                if (cartItems().length === 0) { alert('Your cart is empty.'); return; }
                if (!currentUserId) { window.location.href = '?action=login'; return; }
                renderCheckoutSummary();
                showPage('checkout');
            }

            function renderCheckoutSummary() {
                const items = cartItems();
                const box = document.getElementById('checkout-items');
                const sub = document.getElementById('checkout-subtotal');
                const tot = document.getElementById('checkout-total');
                if (!box) return;
                let total = 0;
                box.innerHTML = items.map(({ p, qty }) => {
                    total += p.price * qty;
                    return `<div class="flex items-center gap-3 py-2 border-b border-gray-50 last:border-0">
                        <img src="${p.img}" class="w-12 h-12 rounded-lg object-contain bg-gray-50 border border-gray-100">
                        <div class="flex-1 min-w-0">
                            <p class="text-sm font-bold text-gray-800 truncate">${escapeHtml(p.name)}</p>
                            <p class="text-xs text-gray-400">${qty} × ₱${p.price.toFixed(2)}</p>
                        </div>
                        <span class="text-sm font-bold text-gray-900">₱${(p.price * qty).toFixed(2)}</span>
                    </div>`;
                }).join('') || '<p class="text-gray-400 text-sm">Your cart is empty.</p>';
                if (sub) sub.innerText = '₱' + total.toFixed(2);
                if (tot) tot.innerText = '₱' + total.toFixed(2);
            }

            async function placeOrder() {
                if (isAdminRole) { alert('Administrators cannot place orders.'); return; }
                const items = cartItems();
                if (items.length === 0) { alert('Your cart is empty.'); return; }
                const name = document.getElementById('co-name').value.trim();
                const phone = document.getElementById('co-phone').value.trim();
                const brgy = document.getElementById('co-barangay').value;
                const street = document.getElementById('co-street').value.trim();
                const notes = document.getElementById('co-notes').value.trim();
                const pickupNotes = document.getElementById('co-pickup-notes')?.value.trim() || '';
                const msg = document.getElementById('checkout-msg');
                msg.classList.add('hidden');

                if (!name || !phone) {
                    msg.className = 'text-sm rounded-xl px-4 py-3 mb-5 bg-red-50 border border-red-200 text-red-700';
                    msg.innerText = 'Please enter your full name and phone number.';
                    msg.classList.remove('hidden');
                    return;
                }
                if (currentFulfillment === 'COD' && (!brgy || !street)) {
                    msg.className = 'text-sm rounded-xl px-4 py-3 mb-5 bg-red-50 border border-red-200 text-red-700';
                    msg.innerText = 'Please complete the delivery address (barangay and street).';
                    msg.classList.remove('hidden');
                    return;
                }

                const payloadItems = items.map(x => ({ id: x.p.id, quantity: x.qty }));
                try {
                    const r = await api('place_order', {
                        fulfillment: currentFulfillment,
                        delivery_name: name,
                        delivery_phone: phone,
                        delivery_barangay: brgy,
                        delivery_street: street,
                        delivery_notes: notes,
                        pickup_notes: pickupNotes,
                        items: JSON.stringify(payloadItems)
                    }, true);
                    if (r.ok) {
                        cart = [];
                        saveCart();
                        renderCart();
                        const refs = (r.order_refs || []).join(', ');
                        msg.className = 'text-sm rounded-xl px-4 py-3 mb-5 bg-green-50 border border-green-200 text-green-700';
                        msg.innerHTML = `<i class="fa-solid fa-circle-check mr-1"></i> Order placed! Reference: <b>${refs}</b>. Payment method: <b>${escapeHtml(r.payment_method || '')}</b>. Please prepare cash for ${r.fulfillment === 'PICKUP' ? 'pickup' : 'delivery'}.`;
                        msg.classList.remove('hidden');
                        loadBuyerOrders();
                        setTimeout(() => { showPage('purchases'); }, 1400);
                    } else {
                        msg.className = 'text-sm rounded-xl px-4 py-3 mb-5 bg-red-50 border border-red-200 text-red-700';
                        msg.innerText = r.error || 'Could not place your order.';
                        msg.classList.remove('hidden');
                    }
                } catch (e) {
                    msg.className = 'text-sm rounded-xl px-4 py-3 mb-5 bg-red-50 border border-red-200 text-red-700';
                    msg.innerText = 'Something went wrong. Please try again.';
                    msg.classList.remove('hidden');
                }
            }

            const orderStatusPill = (s) => {
                const map = {
                    Pending: 'bg-amber-50 text-amber-700 border border-amber-100',
                    Confirmed: 'bg-blue-50 text-blue-700 border border-blue-100',
                    Shipped: 'bg-purple-50 text-purple-700 border border-purple-100',
                    Delivered: 'bg-green-50 text-green-700 border border-green-100',
                    Cancelled: 'bg-red-50 text-red-600 border border-red-100',
                };
                return map[s] || 'bg-gray-100 text-gray-700';
            };
            const paymentStatusPill = (s) => {
                const map = {
                    Unpaid: 'bg-amber-50 text-amber-700 border border-amber-100',
                    Paid: 'bg-green-50 text-green-700 border border-green-100',
                    Refunded: 'bg-red-50 text-red-600 border border-red-100',
                };
                return map[s] || 'bg-gray-100 text-gray-700';
            };
            const fulfillmentLabel = (f) => f === 'PICKUP' ? 'Pickup' : 'COD Delivery';

            function renderOrderCard(o, opts) {
                const itemsHtml = (o.items || []).map(it => `
                    <div class="flex items-center gap-3 py-2 border-b border-gray-50 last:border-0">
                        <img src="${escapeHtml(it.image || 'farm.jpg')}" class="w-12 h-12 rounded-lg object-contain bg-gray-50 border border-gray-100">
                        <div class="flex-1 min-w-0">
                            <p class="text-sm font-bold text-gray-800 truncate">${escapeHtml(it.product_name)}</p>
                            <p class="text-xs text-gray-400">${it.quantity} × ₱${parseFloat(it.price).toFixed(2)} / ${escapeHtml(it.unit)}</p>
                        </div>
                        <span class="text-sm font-bold text-gray-900">₱${(parseFloat(it.price) * parseInt(it.quantity)).toFixed(2)}</span>
                    </div>`).join('') || '<p class="text-gray-400 text-sm">No items.</p>';

                const timelineHtml = (o.timeline || []).length ? `
                    <div class="mt-3 pt-3 border-t border-gray-100">
                        <p class="text-[11px] font-bold uppercase tracking-widest text-gray-400 mb-2">Order Timeline</p>
                        <ul class="space-y-1.5">
                            ${o.timeline.map(t => `
                                <li class="flex items-start gap-2 text-xs text-gray-500">
                                    <span class="w-2 h-2 rounded-full bg-green-400 timeline-dot mt-1 flex-shrink-0"></span>
                                    <span><b class="text-gray-700">${escapeHtml(t.status)}</b> — ${escapeHtml(t.note || '')} <span class="text-gray-400">(${new Date((t.created_at||'').replace(' ','T')).toLocaleString()})</span></span>
                                </li>`).join('')}
                        </ul>
                    </div>` : '';

                const actions = [];
                const isPaid = (o.payment_status || 'Unpaid') === 'Paid';
                if (opts && opts.seller && ['Pending','Confirmed'].includes(o.status)) {
                    if (o.status === 'Pending') actions.push(`<button onclick="updateOrderStatus(${o.id}, 'Confirmed')" class="bg-green-600 hover:bg-green-700 text-white text-xs font-bold px-4 py-2 rounded-lg transition">Confirm</button>`);
                    if (o.status === 'Confirmed' && o.fulfillment !== 'PICKUP') actions.push(`<button onclick="updateOrderStatus(${o.id}, 'Shipped')" class="bg-purple-600 hover:bg-purple-700 text-white text-xs font-bold px-4 py-2 rounded-lg transition">Mark Shipped</button>`);
                    if (o.status === 'Confirmed' && o.fulfillment === 'PICKUP') actions.push(`<button onclick="updateOrderStatus(${o.id}, 'Delivered')" class="bg-green-700 hover:bg-green-800 text-white text-xs font-bold px-4 py-2 rounded-lg transition">Mark Picked Up</button>`);
                    actions.push(`<button onclick="updateOrderStatus(${o.id}, 'Cancelled')" class="border border-red-200 text-red-600 hover:bg-red-50 text-xs font-bold px-4 py-2 rounded-lg transition">Cancel</button>`);
                }
                if (opts && opts.seller && o.status === 'Shipped') {
                    actions.push(`<button onclick="updateOrderStatus(${o.id}, 'Delivered')" class="bg-green-700 hover:bg-green-800 text-white text-xs font-bold px-4 py-2 rounded-lg transition">Mark Delivered</button>`);
                }
                if (opts && opts.buyer && ['Pending','Confirmed'].includes(o.status) && !isPaid) {
                    actions.push(`<button onclick="cancelOrder(${o.id})" class="border border-red-200 text-red-600 hover:bg-red-50 text-xs font-bold px-4 py-2 rounded-lg transition">Cancel Order</button>`);
                }
                // Mark as paid: buyer after pickup/delivery confirmed, OR seller anytime after confirmed
                if (!isPaid && ['Confirmed','Shipped','Delivered'].includes(o.status)) {
                    if (opts && (opts.buyer || opts.seller)) {
                        actions.push(`<button onclick="markOrderPaid(${o.id})" class="bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold px-4 py-2 rounded-lg transition"><i class="fa-solid fa-money-bill-wave mr-1"></i> Mark as Paid</button>`);
                    }
                }
                if (opts && opts.seller && isPaid) {
                    actions.push(`<button onclick="refundOrder(${o.id})" class="border border-amber-200 text-amber-700 hover:bg-amber-50 text-xs font-bold px-4 py-2 rounded-lg transition">Refund</button>`);
                }

                const pickupBlock = o.fulfillment === 'PICKUP' ? `
                    <div class="bg-green-50 border border-green-100 rounded-xl p-3 text-xs text-green-800 mt-2">
                        <p><b><i class="fa-solid fa-store mr-1"></i> Pickup at:</b> ${escapeHtml(o.pickup_location || 'Seller address on file')}</p>
                        ${o.pickup_notes ? '<p class="mt-1 italic">Notes: ' + escapeHtml(o.pickup_notes) + '</p>' : ''}
                    </div>` : '';

                const paymentBlock = `
                    <div class="flex flex-wrap items-center gap-2 mt-2 text-xs">
                        <span class="font-bold px-2.5 py-1 rounded-full ${paymentStatusPill(o.payment_status || 'Unpaid')}">
                            <i class="fa-solid fa-circle-dollar-to-slot mr-1"></i>${escapeHtml(o.payment_status || 'Unpaid')}
                        </span>
                        <span class="text-gray-500">${escapeHtml(o.payment_method || 'Cash')}${o.paid_at ? ' · Paid ' + new Date(o.paid_at.replace(' ','T')).toLocaleString() : ''}</span>
                    </div>`;

                return `<div class="bg-white border border-gray-100 rounded-2xl p-5 shadow-sm">
                    <div class="flex flex-wrap justify-between items-start gap-3 mb-3">
                        <div>
                            <p class="text-xs text-gray-400 font-mono">${escapeHtml(o.order_ref || ('Order #' + o.id))}</p>
                            <p class="font-bold text-gray-900 text-lg">₱${parseFloat(o.total).toFixed(2)} <span class="text-xs font-medium text-green-700 ml-1"><i class="fa-solid fa-money-bill-wave"></i> ${escapeHtml(o.payment_method || 'COD')}</span></p>
                            <p class="text-xs text-gray-500 mt-1">${opts && opts.seller ? 'Buyer: ' + escapeHtml(o.buyer_name || '') : 'Seller: ' + escapeHtml(o.seller_name || '')} · ${new Date((o.created_at||'').replace(' ','T')).toLocaleString()}</p>
                            <p class="text-xs text-gray-500 mt-1"><i class="fa-solid fa-truck-fast text-gray-400 mr-1"></i>${fulfillmentLabel(o.fulfillment)}</p>
                        </div>
                        <div class="flex flex-col items-end gap-1.5">
                            <span class="text-xs font-bold px-3 py-1.5 rounded-full ${orderStatusPill(o.status)}">${escapeHtml(o.status)}</span>
                        </div>
                    </div>
                    <div class="mb-3">${itemsHtml}</div>
                    <div class="bg-gray-50 rounded-xl p-3 text-xs text-gray-600">
                        <p><b>Contact:</b> ${escapeHtml(o.delivery_name || '')} · ${escapeHtml(o.delivery_phone || '')}</p>
                        ${o.fulfillment === 'PICKUP'
                            ? pickupBlock
                            : `<p>${escapeHtml(o.delivery_street || '')}, ${escapeHtml(o.delivery_barangay || '')}, Tayabas City</p>${o.delivery_notes ? '<p class="mt-1 italic text-gray-500">Notes: ' + escapeHtml(o.delivery_notes) + '</p>' : ''}`}
                    </div>
                    ${paymentBlock}
                    ${timelineHtml}
                    ${actions.length ? `<div class="flex gap-2 flex-wrap mt-3">${actions.join('')}</div>` : ''}
                </div>`;
            }

            async function markOrderPaid(orderId) {
                if (!confirm('Confirm that cash payment was received for this order?')) return;
                try {
                    const r = await api('mark_paid', { order_id: orderId }, true);
                    if (!r.ok) alert(r.error || 'Could not record payment.');
                    else { loadBuyerOrders(); loadSellerOrders(); loadAdminOrders(); }
                } catch (e) { alert('Could not record payment.'); }
            }

            async function refundOrder(orderId) {
                if (!confirm('Mark this order as refunded to the buyer?')) return;
                try {
                    const r = await api('refund_order', { order_id: orderId }, true);
                    if (!r.ok) alert(r.error || 'Could not refund.');
                    else { loadSellerOrders(); loadBuyerOrders(); loadAdminOrders(); }
                } catch (e) { alert('Could not refund.'); }
            }

            async function loadBuyerOrders() {
                if (isAdminRole) return;
                const box = document.getElementById('buyer-orders-list');
                const empty = document.getElementById('buyer-orders-empty');
                const stat = document.getElementById('buyer-stat-purchases');
                if (!box) return;
                try {
                    const r = await api('my_orders');
                    if (!r.orders) return;
                    if (stat) stat.innerText = r.orders.length;
                    if (empty) empty.classList.toggle('hidden', r.orders.length > 0);
                    box.innerHTML = r.orders.map(o => renderOrderCard(o, { buyer: true })).join('');
                } catch (e) {}
            }

            async function loadSellerOrders() {
                if (isAdminRole) return;
                const box = document.getElementById('seller-orders-list');
                if (!box) return;
                try {
                    const r = await api('seller_orders');
                    if (!r.orders) return;
                    if (r.orders.length === 0) { box.innerHTML = '<p class="text-gray-500 text-sm">No orders yet.</p>'; return; }
                    box.innerHTML = r.orders.map(o => renderOrderCard(o, { seller: true })).join('');
                } catch (e) {}
            }

            async function updateOrderStatus(orderId, status) {
                if (isAdminRole) return;
                if (status === 'Cancelled' && !confirm('Cancel this order? Stock will be restored.')) return;
                try {
                    const r = await api('update_order_status', { order_id: orderId, status }, true);
                    if (!r.ok) alert(r.error || 'Could not update order.');
                    else { loadSellerOrders(); loadBuyerOrders(); }
                } catch (e) { alert('Could not update order.'); }
            }

            async function cancelOrder(orderId) {
                if (isAdminRole) return;
                if (!confirm('Cancel this order?')) return;
                try {
                    const r = await api('cancel_order', { order_id: orderId }, true);
                    if (!r.ok) alert(r.error || 'Could not cancel order.');
                    else loadBuyerOrders();
                } catch (e) { alert('Could not cancel order.'); }
            }

            async function loadAdminOrders() {
                if (!isAdminRole) return;
                const box = document.getElementById('admin-orders-list');
                if (!box) return;
                const status = document.getElementById('admin-orders-filter')?.value || '';
                try {
                    const r = await api('admin_orders', { status });
                    if (!r.orders) return;
                    if (r.orders.length === 0) { box.innerHTML = '<p class="text-gray-400 text-center py-10">No orders yet.</p>'; return; }
                    box.innerHTML = r.orders.map(o => {
                        const itemsHtml = (o.items || []).map(it => `
                            <div class="flex items-center gap-3 py-2 border-b border-gray-50 last:border-0">
                                <img src="${escapeHtml(it.image || 'farm.jpg')}" class="w-10 h-10 rounded-lg object-contain bg-gray-50 border border-gray-100">
                                <div class="flex-1 min-w-0"><p class="text-sm font-bold text-gray-800 truncate">${escapeHtml(it.product_name)}</p><p class="text-xs text-gray-400">${it.quantity} × ₱${parseFloat(it.price).toFixed(2)}</p></div>
                            </div>`).join('');
                        return `<div class="bg-white border border-gray-100 rounded-2xl p-5 shadow-sm">
                            <div class="flex flex-wrap justify-between items-start gap-3 mb-3">
                                <div>
                                    <p class="text-xs text-gray-400 font-mono">${escapeHtml(o.order_ref || ('Order #' + o.id))}</p>
                                    <p class="font-bold text-gray-900 text-lg">₱${parseFloat(o.total).toFixed(2)} <span class="text-xs font-medium text-green-700 ml-1"><i class="fa-solid fa-money-bill-wave"></i> ${escapeHtml(o.payment_method || 'COD')}</span></p>
                                    <p class="text-xs text-gray-500 mt-1">Buyer: <b>${escapeHtml(o.buyer)}</b> · Seller: <b>${escapeHtml(o.seller)}</b></p>
                                    <p class="text-xs text-gray-500">${fulfillmentLabel(o.fulfillment)} · ${new Date((o.created_at||'').replace(' ','T')).toLocaleString()}</p>
                                </div>
                                <div class="flex flex-col items-end gap-1.5">
                                    <span class="text-xs font-bold px-3 py-1.5 rounded-full ${orderStatusPill(o.status)}">${escapeHtml(o.status)}</span>
                                    <span class="text-xs font-bold px-2.5 py-1 rounded-full ${paymentStatusPill(o.payment_status || 'Unpaid')}">${escapeHtml(o.payment_status || 'Unpaid')}</span>
                                </div>
                            </div>
                            <div class="mb-3">${itemsHtml}</div>
                            <div class="bg-gray-50 rounded-xl p-3 text-xs text-gray-600">
                                <b>Contact:</b> ${escapeHtml(o.delivery_name)} · ${escapeHtml(o.delivery_phone)}<br>
                                ${o.fulfillment === 'PICKUP'
                                    ? '<b>Pickup at:</b> ' + escapeHtml(o.pickup_location || 'Seller address on file')
                                    : escapeHtml(o.delivery_street) + ', ' + escapeHtml(o.delivery_barangay) + ', Tayabas City'}
                            </div>
                        </div>`;
                    }).join('');
                } catch (e) {}
            }
            let currentCategory = 'All';
            let currentSearchQuery = '';

            function escapeHtml(str) {
                if (!str) return '';
                return String(str).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
            }

            function showPage(pageId) {
                document.querySelectorAll('.page-section').forEach(section => {
                    section.classList.add('hidden');
                });
                
                const targetPage = document.getElementById(`page-${pageId}`);
                if(targetPage) {
                    targetPage.classList.remove('hidden');
                }
                
                document.querySelectorAll('nav a').forEach(link => {
                    link.classList.remove('active-nav', 'text-green-700');
                    link.classList.add('text-gray-600');
                });
                const activeNav = document.getElementById(`nav-${pageId}`);
                if(activeNav) {
                    activeNav.classList.add('active-nav', 'text-green-700');
                    activeNav.classList.remove('text-gray-600');
                }
                document.getElementById('mobile-menu').classList.add('hidden');
                window.scrollTo(0, 0);
                // Lazy loaders
                if (pageId === 'purchases') loadBuyerOrders();
                if (pageId === 'manage-orders') { loadOffers(); loadSellerOrders(); }
                if (pageId === 'admin-orders') { loadAdminOffers(); loadAdminOrders(); }
                if (pageId === 'admin-reports') loadAdminReports();
            }

            function toggleMobileMenu() {
                const menu = document.getElementById('mobile-menu');
                menu.classList.toggle('hidden');
            }

            function createProductCard(product) {
                const seller = sellers[product.sellerId];
                const sellerName = escapeHtml(product.sellerName || (seller ? seller.name : 'Seller'));
                const sellerPic = product.sellerPic ? `<img src="${product.sellerPic}" class="w-5 h-5 rounded-full object-cover inline-block mr-1.5 border border-gray-100">` : `<i class="fa-regular fa-user text-gray-400 mr-1.5 text-xs"></i>`;
                const isOutOfStock = product.stock <= 0;
                const desc = escapeHtml(product.description || '');

                // Admin sees the card with no transaction actions
                const actions = isAdminRole ? '<div class="mt-auto"></div>' : (isBuyer ? `
                    <div class="flex items-center gap-2 mt-auto pt-4">
                        <button onclick="makeOffer(${product.id})" class="flex-1 bg-gradient-to-r from-orange-500 to-amber-600 hover:from-orange-600 hover:to-amber-700 text-white font-bold text-sm py-3 rounded-xl transition btn-glow shadow-sm">Make Offer</button>
                        <button onclick="addToCart(${product.id})" ${isOutOfStock ? 'disabled' : ''} title="Add to cart"
                            class="w-11 h-11 rounded-xl border border-gray-200 flex items-center justify-center transition ${isOutOfStock ? 'text-gray-300 cursor-not-allowed bg-gray-50' : 'text-green-700 hover:bg-green-50 hover:border-green-200'}">
                            <i class="fa-solid fa-cart-shopping text-sm"></i>
                        </button>
                        <button onclick="chatSeller(${product.id})" title="Message seller" class="w-11 h-11 rounded-xl border border-gray-200 flex items-center justify-center text-gray-500 hover:bg-gray-50 hover:border-gray-300 transition">
                            <i class="fa-regular fa-comment text-sm"></i>
                        </button>
                    </div>` : '<div class="mt-auto"></div>');

                return `
                    <div class="product-card bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden hover:shadow-xl transition-all duration-400 flex flex-col card-hover group">
                        <div class="h-56 bg-gray-50 relative overflow-hidden">
                            <img src="${product.img}" alt="${escapeHtml(product.name)}" class="product-card-img w-full h-full object-contain bg-gray-50">
                            <span class="absolute top-3 left-3 bg-white/95 backdrop-blur-sm text-[#1e3a1f] text-[11px] font-bold px-3 py-1.5 rounded-full shadow-sm border border-gray-100">${escapeHtml(product.category)}</span>
                            ${isBuyer && !isAdminRole ? heartButton(product.id) : ''}
                        </div>
                        <div class="p-5 flex flex-col flex-grow">
                            <h3 class="text-2xl font-serif font-bold text-[#1e3a1f] leading-tight group-hover:text-green-700 transition-colors">${escapeHtml(product.name)}</h3>
                            <p class="text-sm text-gray-400 mt-2 line-clamp-2 min-h-[2.5rem]">${desc}</p>
                            <div class="mt-3 flex items-baseline gap-1">
                                <span class="text-xl font-extrabold text-[#1e4620]">₱${product.price.toFixed(2)}</span>
                                <span class="text-sm text-gray-400 font-medium">/per ${escapeHtml(product.unit)}</span>
                            </div>
                            <p class="text-sm text-gray-500 font-medium mt-2.5 flex items-center gap-2"><i class="fa-solid fa-location-dot text-gray-300 text-xs"></i> ${escapeHtml(product.barangay || '')}, Tayabas City</p>
                            <p class="text-sm text-gray-500 font-medium mt-1.5 flex items-center gap-2">${sellerPic} ${sellerName}</p>
                            <div class="mt-3">
                                <span class="inline-block text-[11px] font-bold px-3 py-1.5 rounded-full ${isOutOfStock ? 'bg-red-50 text-red-600 border border-red-100' : 'bg-green-50 text-green-700 border border-green-100'}">${isOutOfStock ? 'Out of stock' : 'Available'}</span>
                            </div>
                            ${actions}
                        </div>
                    </div>
                `;
            }

            // --- SHOP FILTERS (search, category, barangay, price, sort) ---
            function getFilteredProducts() {
                const val = id => { const el = document.getElementById(id); return el ? el.value : ''; };
                const brgy = val('filter-barangay');
                const minV = parseFloat(val('filter-min'));
                const maxV = parseFloat(val('filter-max'));
                const sort = val('filter-sort') || 'latest';

                const list = products.filter(p => {
                    const matchesCategory = currentCategory === 'All' || p.category === currentCategory;
                    const matchesSearch = !currentSearchQuery
                        || p.name.toLowerCase().includes(currentSearchQuery)
                        || (p.sellerName || '').toLowerCase().includes(currentSearchQuery);
                    const matchesBrgy = !brgy || p.barangay === brgy;
                    const matchesMin = isNaN(minV) || p.price >= minV;
                    const matchesMax = isNaN(maxV) || p.price <= maxV;
                    return matchesCategory && matchesSearch && matchesBrgy && matchesMin && matchesMax;
                });

                if (sort === 'price-asc') list.sort((a, b) => a.price - b.price);
                else if (sort === 'price-desc') list.sort((a, b) => b.price - a.price);
                else if (sort === 'name') list.sort((a, b) => a.name.localeCompare(b.name));
                return list;
            }

            function applyFilters() { renderProducts(); }

            function clearFilters() {
                document.getElementById('search-input').value = '';
                currentSearchQuery = '';
                document.getElementById('clear-search').classList.add('hidden');
                document.getElementById('filter-barangay').value = '';
                document.getElementById('filter-min').value = '';
                document.getElementById('filter-max').value = '';
                document.getElementById('filter-sort').value = 'latest';
                filterCategory('All');
            }

            function renderProducts() {
                const featuredContainer = document.getElementById('featured-products-container');
                const shopContainer = document.getElementById('shop-products-container');
                const countEl = document.getElementById('listing-count');

                if(featuredContainer) {
                    featuredContainer.innerHTML = products.length === 0
                        ? `<p class="text-gray-500 w-full text-center py-10">No products listed yet.</p>`
                        : products.slice(0, 10).map(p => '<div class="w-[290px] flex-shrink-0 snap-start flex [&>div]:w-full">' + createProductCard(p) + '</div>').join('');
                }

                if(shopContainer) {
                    const filteredProducts = getFilteredProducts();
                    if (countEl) countEl.innerText = filteredProducts.length + (filteredProducts.length === 1 ? ' listing' : ' listings');

                    if (filteredProducts.length === 0) {
                        shopContainer.innerHTML = `<div class="col-span-full text-center py-16"><div class="w-16 h-16 bg-gray-50 rounded-2xl flex items-center justify-center mx-auto mb-4"><i class="fa-solid fa-magnifying-glass text-2xl text-gray-300"></i></div><p class="text-gray-400">No products found matching your criteria.</p><button onclick="clearFilters()" class="mt-4 text-green-700 font-bold text-sm hover:underline">Clear all filters</button></div>`;
                    } else {
                        shopContainer.innerHTML = filteredProducts.map(p => createProductCard(p)).join('');
                    }
                }
            }

            // --- SELLER: ILISTA ANG SARILING PRODUCTS SA MANAGE PRODUCTS ---
            function renderMyProducts() {
                if (isAdminRole) return;
                const box = document.getElementById('my-products-list');
                const emptyBox = document.getElementById('product-empty-box');
                const count = document.getElementById('product-count');
                if (!box) return;

                const mine = products.filter(p => p.sellerId === currentUserId);
                if (count) count.innerText = `${mine.length} of ${mine.length} products`;

                if (mine.length === 0) {
                    box.innerHTML = '';
                    if (emptyBox) emptyBox.classList.remove('hidden');
                    return;
                }
                if (emptyBox) emptyBox.classList.add('hidden');

                box.innerHTML = mine.map(p => `
                    <div class="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden card-hover group">
                        <div class="h-44 bg-gray-50 overflow-hidden">
                            <img src="${p.img}" class="w-full h-full object-contain bg-gray-50 group-hover:scale-105 transition-transform duration-500" alt="${escapeHtml(p.name)}">
                        </div>
                        <div class="p-5">
                            <h3 class="font-bold text-gray-900 text-lg">${escapeHtml(p.name)}</h3>
                            <p class="text-green-700 font-extrabold text-sm mt-1">₱${p.price.toFixed(2)} <span class="text-gray-400 font-medium text-xs">/ ${escapeHtml(p.unit)}</span></p>
                            <p class="text-xs text-gray-500 mt-2 flex items-center gap-1.5"><span class="w-1.5 h-1.5 bg-gray-300 rounded-full"></span>${escapeHtml(p.category)} · Stock: ${p.stock}</p>
                            <p class="text-xs text-gray-400 mt-1.5 flex items-center gap-1.5"><i class="fa-solid fa-location-dot text-gray-300"></i> ${escapeHtml(p.barangay)}, Tayabas City</p>
                        </div>
                    </div>`).join('');
            }

            function handleSearch() {
                const input = document.getElementById('search-input');
                currentSearchQuery = input.value.toLowerCase().trim();
                const clearBtn = document.getElementById('clear-search');
                if (currentSearchQuery.length > 0) { clearBtn.classList.remove('hidden'); } else { clearBtn.classList.add('hidden'); }
                renderProducts();
            }

            function clearSearch() {
                document.getElementById('search-input').value = '';
                currentSearchQuery = '';
                document.getElementById('clear-search').classList.add('hidden');
                renderProducts();
            }

            function filterCategory(category) {
                currentCategory = category;
                const categoryItems = document.querySelectorAll('#category-list li');
                categoryItems.forEach(item => {
                    if (item.dataset.category === category) {
                        item.classList.add('bg-green-50', 'text-green-700', 'font-bold');
                        item.classList.remove('text-gray-600');
                    } else {
                        item.classList.remove('bg-green-50', 'text-green-700', 'font-bold');
                        item.classList.add('text-gray-600');
                    }
                });
                renderProducts();
            }

            function addToCart(productId) {
                if (isAdminRole) { alert('Administrators cannot add products to cart.'); return; }
                if (!currentUserId) { window.location.href = '?action=login'; return; }
                const product = products.find(p => p.id === productId);
                const existingItem = cart.find(item => item.id === productId);
                if (!product) return;
                if (existingItem) {
                    if (existingItem.quantity >= product.stock) { alert('Only ' + product.stock + ' in stock.'); return; }
                    existingItem.quantity += 1;
                } else {
                    cart.push({ id: productId, quantity: 1 });
                }
                renderCart();
                alert('Added to cart!');
            }

            // ===================== OFFERS =====================
            const userRole = '<?= $user_role ?>';
            const userNames = {};
            let offerProduct = null;

            async function api(action, params = {}, post = false) {
                const qs = new URLSearchParams(params).toString();
                const res = await fetch('?api=' + action + (post ? '' : '&' + qs), post ? { method: 'POST', body: new URLSearchParams(params) } : {});
                return res.json();
            }

            function makeOffer(productId) {
                if (isAdminRole) { alert('Administrators cannot make offers.'); return; }
                if (!currentUserId) { window.location.href = '?action=login'; return; }
                const p = products.find(x => x.id === productId);
                if (!p) return;
                if (p.sellerId === currentUserId) { alert("You can't make an offer on your own product."); return; }
                offerProduct = p;
                document.getElementById('offer-product-name').innerText = p.name;
                document.getElementById('offer-qty-label').innerText = 'Quantity (per ' + p.unit + ')';
                document.getElementById('offer-price-label').innerText = 'Offer price / per ' + p.unit;
                document.getElementById('offer-qty').value = 1;
                document.getElementById('offer-price').value = p.price;
                updateOfferTotal();
                const m = document.getElementById('offerModal');
                m.classList.remove('hidden'); m.classList.add('flex');
            }

            function updateOfferTotal() {
                const q = parseInt(document.getElementById('offer-qty').value) || 0;
                const pr = parseFloat(document.getElementById('offer-price').value) || 0;
                document.getElementById('offer-total').innerText = '₱' + (q * pr).toFixed(2).replace(/\.00$/, '');
            }

            function closeOfferModal() {
                const m = document.getElementById('offerModal');
                m.classList.add('hidden'); m.classList.remove('flex');
            }

            async function submitOffer() {
                if (isAdminRole) { alert('Administrators cannot make offers.'); return; }
                if (!offerProduct) return;
                try {
                    const r = await api('send_offer', {
                        product_id: offerProduct.id,
                        quantity: document.getElementById('offer-qty').value,
                        price: document.getElementById('offer-price').value
                    }, true);
                    if (r.ok) { closeOfferModal(); alert('Offer sent to the seller!'); loadOffers(); }
                    else alert(r.error || 'Could not send the offer.');
                } catch (e) { alert('Could not send the offer. Please try again.'); }
            }

            async function respondOffer(id, status) {
                if (isAdminRole) return;
                try {
                    const r = await api('offer_status', { offer_id: id, status: status }, true);
                    if (!r.ok) alert(r.error || 'Failed.');
                } catch (e) {}
                loadOffers();
            }

            async function loadOffers() {
                if (isAdminRole) return;
                if (!currentUserId) return;
                let r;
                try { r = await api('offers'); } catch (e) { return; }
                if (!r.offers) return;
                const seller = r.mode === 'seller';
                const list = document.getElementById(seller ? 'seller-offers-list' : 'offers-list');
                const empty = document.getElementById('offers-empty');
                const stat = document.getElementById('buyer-stat-offers');
                if (stat && !seller) stat.innerText = r.offers.filter(o => o.status === 'Pending').length;
                if (!seller && empty) empty.classList.toggle('hidden', r.offers.length > 0);
                if (!list) return;
                if (r.offers.length === 0) {
                    list.innerHTML = seller ? '<p class="text-gray-400 text-sm text-center py-8">No offers yet.</p>' : '';
                    return;
                }
                const pill = { Pending: 'bg-amber-50 text-amber-700 border border-amber-100', Accepted: 'bg-green-50 text-green-700 border border-green-100', Declined: 'bg-red-50 text-red-600 border border-red-100' };
                list.innerHTML = r.offers.map(o => {
                    userNames[o.other_id] = o.other_name;
                    const price = parseFloat(o.price);
                    const total = (price * o.quantity).toFixed(2).replace(/\.00$/, '');
                    return `
                        <div class="bg-white border border-gray-100 rounded-2xl p-5 flex flex-col sm:flex-row gap-4 sm:items-center hover:shadow-md transition-all">
                            <img src="${o.img}" alt="" class="w-20 h-20 rounded-xl object-contain bg-gray-50 border border-gray-100">
                            <div class="flex-1">
                                <p class="font-bold text-gray-900 text-lg">${escapeHtml(o.name)}</p>
                                <p class="text-sm text-gray-600 mt-1">${o.quantity} × ₱${price.toFixed(2)} / ${escapeHtml(o.unit)} = <b class="text-gray-900">₱${total}</b></p>
                                <p class="text-xs text-gray-400 mt-1.5 flex items-center gap-1.5"><i class="fa-regular fa-user"></i> ${seller ? 'From' : 'To'} ${escapeHtml(o.other_name)}</p>
                            </div>
                            <span class="text-xs font-bold px-3 py-1.5 rounded-full ${pill[o.status] || 'bg-gray-100 text-gray-700'}">${escapeHtml(o.status)}</span>
                            <div class="flex gap-2 flex-wrap">
                                ${seller && o.status === 'Pending' ? `
                                    <button onclick="respondOffer(${o.id}, 'Accepted')" class="bg-green-600 hover:bg-green-700 text-white text-xs font-bold px-5 py-2.5 rounded-xl transition shadow-sm">Accept</button>
                                    <button onclick="respondOffer(${o.id}, 'Declined')" class="border border-red-200 text-red-600 hover:bg-red-50 text-xs font-bold px-5 py-2.5 rounded-xl transition">Decline</button>` : ''}
                                <button onclick="openChat(${o.other_id}, ${o.product_id})" class="border border-gray-200 text-gray-600 hover:bg-gray-50 text-xs font-bold px-5 py-2.5 rounded-xl transition"><i class="fa-regular fa-comment mr-1.5"></i> Message</button>
                            </div>
                        </div>`;
                }).join('');
            }

            // ===================== MESSAGES =====================
            let chatWith = null;
            let convCache = [];
            let lastThreadCount = -1;

            function avatar(name, size) {
                return `<div class="${size} rounded-full bg-gradient-to-br from-green-100 to-emerald-200 text-green-800 font-extrabold flex items-center justify-center shrink-0 shadow-sm">${escapeHtml(String(name).slice(0, 2).toUpperCase())}</div>`;
            }

            function openMessages() {
                if (isAdminRole) return;
                if (!currentUserId) { window.location.href = '?action=login'; return; }
                showPage('messages');
                renderChatPanels();
                loadConversations().then(markMessagesSeen);
                if (chatWith) loadThread();
            }

            function openChat(userId, productId) {
                if (isAdminRole) return;
                chatWith = { id: userId, name: userNames[userId] || 'User', productId: productId || 0 };
                lastThreadCount = -1;
                document.getElementById('chat-messages').innerHTML = '';
                openMessages();
            }

            function chatSeller(productId) {
                if (isAdminRole) { alert('Administrators cannot message sellers through the marketplace.'); return; }
                if (!currentUserId) { window.location.href = '?action=login'; return; }
                const p = products.find(x => x.id === productId);
                if (!p) return;
                if (p.sellerId === currentUserId) { alert('This is your own product.'); return; }
                userNames[p.sellerId] = p.sellerName;
                openChat(p.sellerId, p.id);
            }

            async function loadConversations() {
                if (isAdminRole) return;
                try {
                    const r = await api('conversations');
                    if (!r.conversations) return;
                    convCache = r.conversations;
                    convCache.forEach(c => { userNames[c.id] = c.username; });
                    if (chatWith && userNames[chatWith.id]) chatWith.name = userNames[chatWith.id];
                    updateBell();
                    renderConversations();
                } catch (e) {}
            }

            function renderConversations() {
                if (isAdminRole) return;
                const box = document.getElementById('conv-list');
                if (!box) return;
                const q = (document.getElementById('conv-search').value || '').toLowerCase().trim();
                let list = convCache.slice();
                if (chatWith && !list.some(c => c.id == chatWith.id)) list.unshift({ id: chatWith.id, username: chatWith.name, body: '' });
                list = list.filter(c => c.username.toLowerCase().includes(q));
                if (!list.length) {
                    box.innerHTML = `<div class="text-center mt-12 px-4"><div class="w-14 h-14 bg-gray-50 rounded-xl flex items-center justify-center mx-auto mb-3"><i class="fa-regular fa-comment text-xl text-gray-300"></i></div><p class="font-bold text-gray-700 text-sm">No messages yet</p><p class="text-xs text-gray-400 mt-1">Start a conversation from a product card to see it here.</p></div>`;
                    return;
                }
                box.innerHTML = list.map(c => `
                    <button onclick="openChat(${c.id}, ${chatWith && chatWith.id == c.id ? chatWith.productId : 0})" class="w-full text-left flex items-center gap-3 p-3.5 rounded-xl hover:bg-gray-50 ${chatWith && chatWith.id == c.id ? 'bg-green-50 border border-green-100' : 'border border-transparent'} transition-all group">
                        ${avatar(c.username, 'w-11 h-11 text-sm')}
                        <div class="min-w-0 flex-1">
                            <p class="font-bold text-gray-900 text-sm truncate">${escapeHtml(c.username)}</p>
                            <p class="text-xs text-gray-400 truncate mt-0.5">${escapeHtml(c.body || 'Say hello!')}</p>
                        </div>
                    </button>`).join('');
            }

            function renderChatPanels() {
                if (isAdminRole) return;
                const head = document.getElementById('chat-header');
                const det = document.getElementById('chat-details');
                if (!chatWith) { head.innerHTML = ''; det.innerHTML = ''; return; }
                head.innerHTML = avatar(chatWith.name, 'w-10 h-10 text-sm') + `<p class="font-bold text-gray-900">${escapeHtml(chatWith.name)}</p>`;
                const p = products.find(x => x.id === chatWith.productId);
                det.innerHTML = `
                    <div class="border border-gray-100 rounded-2xl p-5 bg-white">
                        <p class="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4">Details</p>
                        <div class="flex items-center gap-3">${avatar(chatWith.name, 'w-14 h-14 text-lg')}<div><p class="font-bold text-gray-900 break-all">${escapeHtml(chatWith.name)}</p><p class="text-xs text-gray-400 mt-0.5">FarmDirect user</p></div></div>
                    </div>` + (p ? `
                    <div class="border border-gray-100 rounded-2xl mt-4 overflow-hidden bg-white">
                        <div class="h-40 bg-gray-50 overflow-hidden">
                            <img src="${p.img}" alt="" class="w-full h-full object-contain bg-gray-50">
                        </div>
                        <div class="p-5">
                            <p class="text-xs font-bold text-gray-400 uppercase tracking-widest">Discussing</p>
                            <p class="font-bold text-gray-900 mt-1">${escapeHtml(p.name)}</p>
                            <p class="mt-2 text-sm"><span class="font-extrabold text-green-700 text-lg">₱${p.price.toFixed(2)}</span><span class="text-gray-400 text-xs font-medium">/per ${escapeHtml(p.unit)}</span><span class="float-right text-xs text-gray-400 bg-gray-50 px-2 py-1 rounded-lg">${p.stock} in stock</span></p>
                            <button onclick="showPage('shop')" class="mt-4 w-full border border-gray-200 rounded-xl py-2.5 text-sm font-bold hover:bg-gray-50 transition">View Product</button>
                        </div>
                    </div>` : '');
            }

            async function loadThread(silent) {
                if (isAdminRole) return;
                if (!chatWith) return;
                let r;
                try { r = await api('thread', { with: chatWith.id }); } catch (e) { return; }
                if (!r.messages) return;
                if (!chatWith.productId && r.product_id) { chatWith.productId = r.product_id; renderChatPanels(); }
                if (silent && r.messages.length === lastThreadCount) return;
                lastThreadCount = r.messages.length;
                const box = document.getElementById('chat-messages');
                if (!r.messages.length) {
                    box.innerHTML = '<div class="text-center mt-16"><div class="w-14 h-14 bg-gray-50 rounded-xl flex items-center justify-center mx-auto mb-3"><i class="fa-regular fa-comment text-xl text-gray-300"></i></div><p class="text-gray-400 text-sm">No messages yet — say hello!</p></div>';
                    return;
                }
                box.innerHTML = r.messages.map(m => {
                    const mine = m.sender_id == r.me;
                    const time = new Date(m.created_at.replace(' ', 'T')).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    return `<div class="flex ${mine ? 'justify-end' : 'justify-start'}">
                        <div class="max-w-[75%] px-4 py-2.5 rounded-2xl text-sm ${mine ? 'chat-bubble-mine text-white rounded-br-sm shadow-md' : 'bg-white border border-gray-100 text-gray-800 rounded-bl-sm shadow-sm'}">
                            <p class="whitespace-pre-wrap break-words leading-relaxed">${escapeHtml(m.body)}</p>
                            <p class="text-[10px] mt-1.5 ${mine ? 'text-green-200/80' : 'text-gray-400'}">${time}</p>
                        </div></div>`;
                }).join('');
                box.scrollTop = box.scrollHeight;
            }

            async function sendChat() {
                if (isAdminRole) { alert('Administrators cannot send marketplace messages.'); return; }
                if (!chatWith) { alert('Select a conversation first.'); return; }
                const input = document.getElementById('chat-input');
                const body = input.value.trim();
                if (!body) return;
                input.value = '';
                try {
                    const r = await api('send_message', { to: chatWith.id, body: body, product_id: chatWith.productId || 0 }, true);
                    if (!r.ok) { alert(r.error || 'Could not send the message.'); input.value = body; return; }
                } catch (e) { input.value = body; return; }
                loadThread();
                loadConversations();
            }

            // ===================== CHANGE PASSWORD / SETTINGS =====================
            function showMsg(id, ok, text) {
                const el = document.getElementById(id);
                el.className = 'text-sm rounded-xl px-4 py-3 mb-4 ' + (ok ? 'bg-green-50 border border-green-200 text-green-700' : 'bg-red-50 border border-red-200 text-red-700');
                el.innerText = text;
            }

            function togglePwVisibility() {
                const input = document.getElementById('pw-new');
                const eye = document.getElementById('pw-eye');
                const show = input.type === 'password';
                input.type = show ? 'text' : 'password';
                eye.className = show ? 'fa-regular fa-eye-slash' : 'fa-regular fa-eye';
            }

            async function changePassword() {
                const cur = document.getElementById('pw-current').value;
                const nw = document.getElementById('pw-new').value;
                const con = document.getElementById('pw-confirm').value;
                if (!cur || !nw || !con) { showMsg('pw-msg', false, 'Please fill in all fields.'); return; }
                if (nw.length < 8) { showMsg('pw-msg', false, 'New password must be at least 8 characters.'); return; }
                if (nw !== con) { showMsg('pw-msg', false, 'New passwords do not match.'); return; }
                try {
                    const r = await api('change_password', { current: cur, new: nw, confirm: con }, true);
                    if (r.ok) {
                        showMsg('pw-msg', true, 'Password updated successfully.');
                        ['pw-current', 'pw-new', 'pw-confirm'].forEach(id => document.getElementById(id).value = '');
                    } else showMsg('pw-msg', false, r.error || 'Could not update the password.');
                } catch (e) { showMsg('pw-msg', false, 'Something went wrong. Please try again.'); }
            }

            function openSettings() {
                showPage('settings');
                showSettingsTab('account');
                loadSettings();
            }

            function showSettingsTab(tab) {
                ['account', 'notifications', 'danger'].forEach(name => {
                    document.getElementById('settings-' + name).classList.toggle('hidden', name !== tab);
                    const btn = document.getElementById('stab-' + name);
                    const active = name === tab;
                    btn.className = 'text-left px-5 py-3 rounded-2xl text-sm font-bold transition-all ' +
                        (name === 'danger' ? 'text-red-600 ' : 'text-[#1e3a1f] ') + (active ? 'bg-green-100 shadow-sm' : 'hover:bg-gray-100');
                });
            }

            async function loadSettings() {
                try {
                    const r = await api('settings');
                    if (r.error) return;
                    document.getElementById('notify-offers').checked = r.notify_offers == 1;
                    document.getElementById('notify-messages').checked = r.notify_messages == 1;
                } catch (e) {}
            }

            async function saveNotifications() {
                try {
                    const r = await api('save_settings', {
                        notify_offers: document.getElementById('notify-offers').checked ? 1 : 0,
                        notify_messages: document.getElementById('notify-messages').checked ? 1 : 0
                    }, true);
                    showMsg('notif-msg', !!r.ok, r.ok ? 'Preferences saved.' : (r.error || 'Could not save.'));
                } catch (e) { showMsg('notif-msg', false, 'Something went wrong. Please try again.'); }
            }

            function connectSocial(name) {
                alert(name + ' sign-in needs a ' + name + ' developer app (client ID and secret). It has not been set up yet.');
            }

            async function logoutEverywhere() {
                if (!confirm('Log out of all devices, including this one?')) return;
                try { await api('logout_all', {}, true); } catch (e) {}
                window.location.href = 'index.php';
            }

            async function deleteAccount() {
                const pw = document.getElementById('delete-password').value;
                if (!pw) { showMsg('delete-msg', false, 'Enter your password to confirm.'); return; }
                if (!confirm('Delete your account permanently? This cannot be undone.')) return;
                try {
                    const r = await api('delete_account', { password: pw }, true);
                    if (r.ok) { window.location.href = 'index.php'; }
                    else showMsg('delete-msg', false, r.error || 'Could not delete the account.');
                } catch (e) { showMsg('delete-msg', false, 'Something went wrong. Please try again.'); }
            }

            // ===================== FAQ =====================
            const faqData = [
                { category: "Getting Started", questions: [
                    { q: "What is FarmDirect?", a: "FarmDirect is an online agricultural marketplace connecting farmers, sellers, and buyers across the Philippines, making fresh farm products easier to discover and purchase." },
                    { q: "Is FarmDirect free to use?", a: "Yes, creating an account and browsing products is completely free for buyers. Sellers may incur a small transaction fee for every successful sale." },
                    { q: "How do I create an account?", a: "Click the Login button at the top right corner and select Register. Fill out the required information and verify your email address to get started." }
                ]},
                { category: "For Buyers", questions: [
                    { q: "How do I place an order?", a: "Browse the Shop, add your desired products to the cart, and click Checkout. Choose Pickup or Cash on Delivery, fill in your contact details, and confirm. You'll pay the rider or the seller in cash." },
                    { q: "What are the payment options?", a: "We currently accept Cash on Delivery (COD) and Cash on Pickup. More payment options are coming soon." },
                    { q: "How can I track my order?", a: "Go to the 'Purchases' page to see real-time updates on your order status and a full timeline, from Pending to Confirmed, Shipped, Delivered, and Paid." }
                ]},
                { category: "For Sellers", questions: [
                    { q: "How do I become a seller?", a: "Register an account and choose 'Seller' as your account type. Upload your valid ID for verification. Once approved, you can start listing products." },
                    { q: "How do I list my products?", a: "Once verified, go to your Seller Dashboard and click 'Add Product'. Fill in the product details, price, stock quantity, and upload a clear photo." },
                    { q: "When do I get paid?", a: "For Cash on Delivery and Pickup orders, payment is collected by the rider or at the farm on delivery/pickup. Confirm payment received from your Seller Orders page, and the order will show as Paid." }
                ]},
                { category: "Account and Security", questions: [
                    { q: "How do I reset my password?", a: "Click 'Forgot Password' on the login page and follow the instructions sent to your registered email address." },
                    { q: "Is my personal information safe?", a: "Yes, we use advanced encryption and security measures to protect your data. We never sell your information to third parties." },
                    { q: "How do I update my delivery address?", a: "Go to your Account Settings and update your default delivery address. You can also change it during the checkout process." }
                ]}
            ];

            function renderFAQ() {
                const container = document.getElementById('faq-container');
                if (!container) return;
                container.innerHTML = faqData.map(section => `
                    <div>
                        <h3 class="text-xl font-bold text-gray-800 mb-4 font-serif flex items-center gap-2"><span class="w-6 h-1 bg-green-500 rounded-full"></span>${section.category}</h3>
                        <div class="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden">
                            ${section.questions.map(item => `
                                <details class="group border-b border-gray-50 last:border-0">
                                    <summary class="flex justify-between items-center font-semibold cursor-pointer list-none p-5 hover:bg-gray-50/50 transition text-gray-700">
                                        <span>${item.q}</span>
                                        <span class="transition-transform duration-300 group-open:rotate-180"><i class="fa-solid fa-chevron-down text-gray-300 text-xs"></i></span>
                                    </summary>
                                    <div class="text-gray-500 text-sm px-5 pb-5 pt-0 leading-relaxed"><p>${item.a}</p></div>
                                </details>
                            `).join('')}
                        </div>
                    </div>
                `).join('');
            }

            // ===================== BELL = MESSAGES =====================
            function scrollFeatured(dir) {
                const c = document.getElementById('featured-products-container');
                if (c) c.scrollBy({ left: dir * 310, behavior: 'smooth' });
            }

            function seenKey() { return 'fd_seen_msg_' + currentUserId; }
            function getSeenMsg() {
                try { return parseInt(localStorage.getItem(seenKey()) || '0') || 0; } catch (e) { return 0; }
            }
            function unreadConvs() {
                const seen = getSeenMsg();
                return convCache.filter(c => parseInt(c.sender_id) !== currentUserId && parseInt(c.msg_id) > seen);
            }
            function markMessagesSeen() {
                const max = convCache.reduce((m, c) => Math.max(m, parseInt(c.msg_id) || 0), 0);
                try { localStorage.setItem(seenKey(), String(max)); } catch (e) {}
                updateBell();
            }
            function updateBell() {
                const bell = document.getElementById('bell-icon');
                if (!bell) return;
                const unread = unreadConvs().length > 0;
                bell.className = (unread ? 'fa-solid text-green-600' : 'fa-regular text-gray-500') + ' fa-bell p-2 rounded-lg hover:bg-green-50 transition-all cursor-pointer';
                bell.title = unread ? 'You have new messages' : 'Messages';
            }

            // Admin-specific JS loaders
            async function loadAdminStats() {
                try {
                    const r = await api('admin_stats');
                    if (!r.stats) return;
                    const set = (id, v) => { const el = document.getElementById(id); if (el) el.innerText = v; };
                    set('stat-users', r.stats.users ?? 0);
                    set('stat-sellers', r.stats.sellers ?? 0);
                    set('stat-buyers', r.stats.buyers ?? 0);
                    set('stat-products', r.stats.products ?? 0);
                    set('stat-pending', r.stats.pending_offers ?? 0);
                    set('stat-transactions', r.stats.transactions ?? 0);
                } catch (e) {}
            }

            async function loadAdminActivity() {
                const box = document.getElementById('admin-activity');
                if (!box) return;
                try {
                    const r = await api('admin_activity');
                    if (!r.activity) return;
                    const a = r.activity;
                    const pill = { Buyer: 'bg-blue-50 text-blue-700 border border-blue-100', Seller: 'bg-green-50 text-green-700 border border-green-100', Admin: 'bg-purple-50 text-purple-700 border border-purple-100', Pending: 'bg-amber-50 text-amber-700 border border-amber-100', Accepted: 'bg-green-50 text-green-700 border border-green-100', Declined: 'bg-red-50 text-red-600 border border-red-100' };
                    let html = '';
                    if (a.users?.length) {
                        html += `<p class="text-xs font-bold uppercase tracking-widest text-gray-400 mt-2 mb-2">New Users</p>`;
                        html += a.users.slice(0,5).map(u => `<div class="flex items-center justify-between bg-gray-50/80 rounded-xl px-4 py-2.5 border border-gray-50"><span><b class="text-gray-800">${escapeHtml(u.username)}</b> <span class="text-xs text-gray-400 ml-1">${new Date((u.created_at||'').replace(' ','T')).toLocaleDateString()}</span></span><span class="text-xs font-bold px-2.5 py-1 rounded-full ${pill[u.role]||'bg-gray-50 text-gray-600'}">${escapeHtml(u.role)}</span></div>`).join('');
                    }
                    if (a.products?.length) {
                        html += `<p class="text-xs font-bold uppercase tracking-widest text-gray-400 mt-4 mb-2">New Products</p>`;
                        html += a.products.slice(0,5).map(p => `<div class="flex items-center gap-3 bg-gray-50/80 rounded-xl px-4 py-2.5 border border-gray-50"><img src="${p.img}" class="w-8 h-8 rounded-lg object-contain bg-white border border-gray-100"><span class="flex-1"><b class="text-gray-800">${escapeHtml(p.name)}</b> <span class="text-xs text-gray-400 ml-1">· ${escapeHtml(p.seller)}</span></span><span class="ml-auto text-xs font-bold text-gray-600">₱${parseFloat(p.price).toFixed(2)}</span></div>`).join('');
                    }
                    if (a.offers?.length) {
                        html += `<p class="text-xs font-bold uppercase tracking-widest text-gray-400 mt-4 mb-2">Recent Offers</p>`;
                        html += a.offers.slice(0,5).map(o => `<div class="flex items-center justify-between bg-gray-50/80 rounded-xl px-4 py-2.5 border border-gray-50"><span><b class="text-gray-800">${escapeHtml(o.product)}</b> <span class="text-xs text-gray-400 ml-1">· ${escapeHtml(o.buyer)} → ${escapeHtml(o.seller)}</span></span><span class="text-xs font-bold px-2.5 py-1 rounded-full ${pill[o.status]||'bg-gray-50 text-gray-600'}">${escapeHtml(o.status)}</span></div>`).join('');
                    }
                    box.innerHTML = html || '<p class="text-gray-400 text-sm py-4">No activity yet.</p>';
                } catch (e) {
                    box.innerHTML = '<p class="text-red-500 text-sm">Could not load activity.</p>';
                }
            }

            async function loadAdminUsers() {
                if (!isAdminRole) return;
                const tbody = document.getElementById('admin-users-tbody');
                if (!tbody) return;
                const q = document.getElementById('admin-user-search')?.value || '';
                const filter = document.getElementById('admin-user-filter')?.value || 'All';
                try {
                    const r = await api('admin_users', { q, filter });
                    if (!r.users) { tbody.innerHTML = '<tr><td colspan="8" class="p-8 text-center text-red-500">Could not load users.</td></tr>'; return; }
                    if (r.users.length === 0) { tbody.innerHTML = '<tr><td colspan="8" class="p-8 text-center text-gray-400">No users match.</td></tr>'; return; }
                    const rolePill = { Buyer: 'bg-blue-50 text-blue-700 border border-blue-100', Seller: 'bg-green-50 text-green-700 border border-green-100', Admin: 'bg-purple-50 text-purple-700 border border-purple-100' };
                    tbody.innerHTML = r.users.map(u => `
                        <tr class="border-t border-gray-50 hover:bg-gray-50/50 transition-colors">
                            <td class="px-5 py-4 text-gray-400 font-mono text-xs">${u.id}</td>
                            <td class="px-5 py-4">
                                <div class="flex items-center gap-3">
                                    ${u.profile_pic ? `<img src="${escapeHtml(u.profile_pic)}" class="w-9 h-9 rounded-full object-contain bg-gray-50 border border-gray-100">` : `<div class="w-9 h-9 rounded-full bg-gradient-to-br from-green-100 to-emerald-200 text-green-800 flex items-center justify-center text-xs font-extrabold shadow-sm">${escapeHtml((u.username||'?').slice(0,1).toUpperCase())}</div>`}
                                    <span class="font-bold text-gray-800">${escapeHtml(u.username)}</span>
                                </div>
                            </td>
                            <td class="px-5 py-4 text-gray-500 text-sm">${escapeHtml(u.email)}</td>
                            <td class="px-5 py-4"><span class="text-xs font-bold px-2.5 py-1 rounded-full ${rolePill[u.role]||'bg-gray-50 text-gray-600'}">${escapeHtml(u.role)}</span></td>
                            <td class="px-5 py-4">${parseInt(u.email_verified) ? '<span class="text-green-600 text-sm font-medium flex items-center gap-1.5"><i class="fa-solid fa-circle-check"></i> Verified</span>' : '<span class="text-gray-400 text-sm flex items-center gap-1.5"><i class="fa-solid fa-circle-xmark"></i> Unverified</span>'}</td>
                            <td class="px-5 py-4">${parseInt(u.is_suspended) ? '<span class="text-xs font-bold px-2.5 py-1 rounded-full bg-red-50 text-red-600 border border-red-100">Suspended</span>' : '<span class="text-xs font-bold px-2.5 py-1 rounded-full bg-green-50 text-green-700 border border-green-100">Active</span>'}</td>
                            <td class="px-5 py-4 text-gray-400 text-xs">${u.created_at ? new Date(u.created_at.replace(' ','T')).toLocaleDateString() : '—'}</td>
                            <td class="px-5 py-4">
                                <div class="flex flex-wrap gap-1.5">
                                    ${parseInt(u.email_verified) ? '' : `<button onclick="adminAction(${u.id}, 'verify')" class="text-xs font-bold px-2.5 py-1.5 rounded-lg bg-green-50 text-green-700 hover:bg-green-100 transition border border-green-100">Verify</button>`}
                                    ${parseInt(u.is_suspended)
                                        ? `<button onclick="adminAction(${u.id}, 'unsuspend')" class="text-xs font-bold px-2.5 py-1.5 rounded-lg bg-green-50 text-green-700 hover:bg-green-100 transition border border-green-100">Unsuspend</button>`
                                        : `<button onclick="adminAction(${u.id}, 'suspend')" class="text-xs font-bold px-2.5 py-1.5 rounded-lg bg-amber-50 text-amber-700 hover:bg-amber-100 transition border border-amber-100">Suspend</button>`}
                                    ${u.role !== 'Admin' ? `<button onclick="adminAction(${u.id}, 'promote')" class="text-xs font-bold px-2.5 py-1.5 rounded-lg bg-purple-50 text-purple-700 hover:bg-purple-100 transition border border-purple-100">Promote</button>` : `<button onclick="adminAction(${u.id}, 'demote')" class="text-xs font-bold px-2.5 py-1.5 rounded-lg bg-gray-100 text-gray-600 hover:bg-gray-200 transition border border-gray-200">Demote</button>`}
                                    <button onclick="adminAction(${u.id}, 'delete')" class="text-xs font-bold px-2.5 py-1.5 rounded-lg bg-red-50 text-red-600 hover:bg-red-100 transition border border-red-100">Delete</button>
                                </div>
                            </td>
                        </tr>
                    `).join('');
                } catch (e) {
                    tbody.innerHTML = '<tr><td colspan="8" class="p-8 text-center text-red-500">Could not load users.</td></tr>';
                }
            }

            async function adminAction(userId, action) {
                if (!isAdminRole) return;
                if (action === 'delete' && !confirm('Delete this user permanently? This removes their products, offers, and messages.')) return;
                if (action === 'promote' && !confirm('Promote this user to Admin?')) return;
                if (action === 'demote' && !confirm('Demote this admin to Buyer?')) return;
                try {
                    const r = await api('admin_user_action', { user_id: userId, action }, true);
                    if (!r.ok) alert(r.error || 'Action failed.');
                    else loadAdminUsers();
                } catch (e) { alert('Action failed.'); }
            }

            async function loadAdminProducts() {
                if (!isAdminRole) return;
                const box = document.getElementById('admin-products-list');
                if (!box) return;
                const q = document.getElementById('admin-prod-search')?.value || '';
                const category = document.getElementById('admin-prod-category')?.value || '';
                box.innerHTML = '<div class="col-span-full flex justify-center py-10"><div class="w-8 h-8 border-3 border-green-200 border-t-green-600 rounded-full animate-spin"></div></div>';
                try {
                    const r = await api('admin_products', { q, category });
                    if (!r.products) return;
                    if (r.products.length === 0) { box.innerHTML = '<p class="text-gray-400 col-span-full text-center py-10">No products match.</p>'; return; }
                    box.innerHTML = r.products.map(p => `
                        <div class="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden flex flex-col card-hover">
                            <div class="h-44 bg-gray-50 overflow-hidden relative"><img src="${p.img}" alt="${escapeHtml(p.name)}" class="w-full h-full object-contain bg-gray-50"></div>
                            <div class="p-5 flex flex-col flex-grow">
                                <span class="text-[11px] font-bold text-green-800 bg-green-50 px-3 py-1 rounded-full self-start mb-3 border border-green-100">${escapeHtml(p.category)}</span>
                                <h3 class="text-lg font-serif font-bold text-[#1e3a1f] leading-tight">${escapeHtml(p.name)}</h3>
                                <p class="text-sm text-gray-500 mt-1.5">by ${escapeHtml(p.seller_name)}</p>
                                <p class="text-sm text-gray-400 mt-1">${escapeHtml(p.barangay || '')} · Stock: ${p.stock}</p>
                                <p class="mt-3 text-xl font-extrabold text-[#1e4620]">₱${parseFloat(p.price).toFixed(2)}<span class="text-sm text-gray-400 font-medium"> / ${escapeHtml(p.unit)}</span></p>
                                <button onclick="adminDeleteProduct(${p.id})" class="mt-4 bg-red-50 hover:bg-red-100 text-red-600 text-sm font-bold py-2.5 rounded-xl border border-red-100 transition"><i class="fa-solid fa-trash mr-1.5"></i> Delete</button>
                            </div>
                        </div>
                    `).join('');
                } catch (e) {}
            }

            async function adminDeleteProduct(productId) {
                if (!isAdminRole) return;
                if (!confirm('Delete this product permanently? Related offers will also be removed.')) return;
                try {
                    const r = await api('admin_delete_product', { product_id: productId }, true);
                    if (!r.ok) alert(r.error || 'Delete failed.');
                    else loadAdminProducts();
                } catch (e) { alert('Delete failed.'); }
            }

            async function loadAdminOffers() {
                if (!isAdminRole) return;
                const tbody = document.getElementById('admin-offers-tbody');
                if (!tbody) return;
                const status = document.getElementById('admin-offer-filter')?.value || '';
                try {
                    const r = await api('admin_offers', { status });
                    if (!r.offers) return;
                    if (r.offers.length === 0) { tbody.innerHTML = '<tr><td colspan="9" class="p-8 text-center text-gray-400">No offers match.</td></tr>'; return; }
                    const pill = { Pending: 'bg-amber-50 text-amber-700 border border-amber-100', Accepted: 'bg-green-50 text-green-700 border border-green-100', Declined: 'bg-red-50 text-red-600 border border-red-100' };
                    tbody.innerHTML = r.offers.map(o => {
                        const total = (parseFloat(o.price) * parseInt(o.quantity)).toFixed(2);
                        return `<tr class="border-t border-gray-50 hover:bg-gray-50/50 transition-colors">
                            <td class="px-5 py-4 text-gray-400 font-mono text-xs">#${o.id}</td>
                            <td class="px-5 py-4 font-bold text-gray-800">${escapeHtml(o.product)}</td>
                            <td class="px-5 py-4 text-gray-600">${escapeHtml(o.buyer)}</td>
                            <td class="px-5 py-4 text-gray-600">${escapeHtml(o.seller)}</td>
                            <td class="px-5 py-4 text-gray-600 font-medium">${o.quantity}</td>
                            <td class="px-5 py-4 text-gray-600">₱${parseFloat(o.price).toFixed(2)}</td>
                            <td class="px-5 py-4 font-extrabold text-gray-900">₱${total}</td>
                            <td class="px-5 py-4"><span class="text-xs font-bold px-2.5 py-1 rounded-full ${pill[o.status]||'bg-gray-50 text-gray-600'}">${escapeHtml(o.status)}</span></td>
                            <td class="px-5 py-4 text-gray-400 text-xs">${o.created_at ? new Date(o.created_at.replace(' ','T')).toLocaleString() : '—'}</td>
                        </tr>`;
                    }).join('');
                } catch (e) {}
            }

            async function loadAdminReports() {
                if (!isAdminRole) return;
                try {
                    const r = await api('admin_reports');
                    if (!r.reports) return;
                    const rep = r.reports;
                    const render = (elId, rows, key) => {
                        const el = document.getElementById(elId);
                        if (!el) return;
                        if (!rows || rows.length === 0) { el.innerHTML = '<p class="text-gray-400 text-sm">No data.</p>'; return; }
                        el.innerHTML = rows.map(row => `
                            <div class="flex items-center justify-between border-b border-gray-50 py-3 last:border-0">
                                <span class="font-semibold text-gray-700">${escapeHtml(String(row[key]))}</span>
                                <span class="text-xs font-bold px-3 py-1.5 rounded-full bg-gradient-to-r from-green-50 to-emerald-50 text-green-800 border border-green-100">${row.c}</span>
                            </div>`).join('');
                    };
                    render('report-offers-status', rep.offers_status, 'status');
                    render('report-users-role', rep.users_role, 'role');
                    render('report-products-cat', rep.products_category, 'category');
                    render('report-products-brgy', rep.products_barangay, 'barangay');
                    render('report-orders-status', rep.orders_status, 'status');
                    render('report-fulfillment', rep.orders_fulfillment, 'fulfillment');
                    render('report-payment-status', rep.payment_status, 'payment_status');
                    const tot = document.getElementById('report-orders-total');
                    if (tot) tot.innerText = '₱' + parseFloat(rep.orders_total || 0).toFixed(2);
                    const paid = document.getElementById('report-orders-paid');
                    if (paid) paid.innerText = '₱' + parseFloat(rep.orders_paid_total || 0).toFixed(2);
                } catch (e) {}
            }

            function openChatFromPopover(userId) {
                closeMessagesPopover();
                openChat(userId, 0);
            }

            function closeMessagesPopover() {
                const pop = document.getElementById('messagesPopover');
                if (pop) pop.classList.add('hidden');
            }

            document.addEventListener('click', (e) => {
                const pop = document.getElementById('messagesPopover');
                if (pop && !pop.classList.contains('hidden') && !pop.contains(e.target)) closeMessagesPopover();
            });

            // Check ng bagong messages kada 15 segundo (para sa bell)
            setInterval(() => { if (currentUserId && !isAdminRole) loadConversations(); }, 15000);

            // Auto-refresh habang bukas ang Messages page
            setInterval(() => {
                if (isAdminRole) return;
                const page = document.getElementById('page-messages');
                if (!currentUserId || !page || page.classList.contains('hidden')) return;
                loadConversations().then(markMessagesSeen);
                if (chatWith) loadThread(true);
            }, 4000);

            document.addEventListener('DOMContentLoaded', () => {
                const hashPage = location.hash.replace('#', '');
                if (['terms', 'privacy', 'faq'].includes(hashPage)) showPage(hashPage);
                if (currentUserId && !isAdminRole) loadConversations();
                renderFAQ();
                renderProducts();
                renderMyProducts();
                loadOffers();
                renderCart();
                renderSaved();
                updateBuyerStats();
                if (!isAdminRole && userRole === 'Buyer') { loadBuyerOrders(); }
                if (!isAdminRole && userRole === 'Seller') { loadSellerOrders(); }
                <?php if ($product_success): ?>showPage('manage-products');<?php endif; ?>
                if (isAdminRole) {
                    showPage('admin-dashboard');
                    loadAdminStats();
                    loadAdminActivity();
                }
                // Set default fulfillment state on the checkout page
                onFulfillmentChange('COD');
            });
        </script>
    </body>
    </html>
<?php endif; ?>