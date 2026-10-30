<?php
session_start();
include 'db_connect.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user_type = $_POST['user_type'];
    $username = $_POST['username'];
    $email = $_POST['email'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT); // Secure hashing
    $first_name = $_POST['first_name'];
    $last_name = $_POST['last_name'];
    $phone = $_POST['phone'];
    $region = $_POST['region'];
    $city = $_POST['city'];
    $barangay = $_POST['barangay'];

    $sql = "INSERT INTO users (user_type, username, email, password, first_name, last_name, phone, region, city, barangay) 
            VALUES ('$user_type', '$username', '$email', '$password', '$first_name', '$last_name', '$phone', '$region', '$city', '$barangay')";

    if ($conn->query($sql) === TRUE) {
        // Redirect back to index with success message
        header("Location: index.html?signup=success");
        exit();
    } else {
        // Redirect back with error
        header("Location: index.html?signup=error");
        exit();
    }
}
?>