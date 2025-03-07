<?php
session_start();
include "config.php";

if (isset($_POST["login"])) {
    $username_or_email = $_POST["username_or_email"];
    $password = $_POST["password"];

    $query = $conn->prepare("SELECT * FROM users WHERE email = ? OR username = ?");
    $query->bind_param("ss", $username_or_email, $username_or_email);
    $query->execute();
    $result = $query->get_result();

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();

        if (password_verify($password, $user["password"])) {
            $_SESSION["user"] = $user["username"];
            header("Location: dashboard.php");
            exit();
        } else {
            echo "Incorrect password!";
        }
    } else {
        echo "User not found!";
    }
}
?>
